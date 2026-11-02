"""Logs de acesso web: nginx e Apache (Common, Combined) e IIS (W3C com ``#Fields``).

Uma resposta 2xx a um ataque não prova sucesso: muitos sites respondem 200 para tudo. Por isso
a análise compara os tamanhos das respostas. O tamanho que se repete em caminhos diferentes ou
que aparece em páginas normais é a "página padrão" do site, e não conta como acerto. Só o que
sobra é marcado como "possivelmente bem-sucedido".
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ...core.context import CheckContext
from ...core.models import Confidence, Severity
from . import assinaturas, tempo
from .agregacao import (
    CHAVE_DEMAIS,
    MAX_AMOSTRAS,
    Indicio,
    Relato,
    Tabela,
    eh_ip,
    limpar,
    pico_na_janela,
    principais,
    relatar,
)
from .assinaturas import TIPOS

#: erros 404 do mesmo IP, em caminhos diferentes, que caracterizam uma rajada de varredura
RAJADA_404_MIN = 30
RAJADA_404_JANELA_S = 300.0
RAJADA_404_MIN_CAMINHOS = 20
#: varredura lenta: total de 404 e caminhos diferentes, sem olhar a janela
VARREDURA_404_MIN_TOTAL = 200
VARREDURA_404_MIN_CAMINHOS = 100
#: tentativas de login do mesmo IP dentro da janela que caracterizam força bruta na web
LOGIN_MIN_TENTATIVAS = 20
LOGIN_JANELA_S = 600.0
LOGIN_MIN_TOTAL = 100
#: requisições de uma ferramenta de varredura a partir das quais a severidade sobe
SCANNER_REQUISICOES_ALTO = 500
#: caminhos de ataque diferentes com a mesma resposta: é a página padrão, não um acerto
PAGINA_PADRAO_MIN_CAMINHOS = 3
#: vezes que um tamanho aparece em páginas normais para ser tratado como página padrão
PAGINA_NORMAL_MIN_VEZES = 2
#: limites de memória
MAX_TAMANHOS = 100_000
MAX_CAMINHOS_POR_IP = 512
MAX_IPS_404 = 50_000
MAX_RESPOSTAS = 100_000

_CAMPO = re.compile(r'"((?:[^"\\]|\\.)*)"')
_STATUS = re.compile(r"\s+(\d{3})(?:\s+(\d+|-))?")
_ORIGEM = re.compile(r"[0-9A-Za-z_.:\-%]+")
_LOGIN = re.compile(
    r"(?:^|/)(?:wp-login\.php|xmlrpc\.php|login|signin|sign-in|logon|administrator/index\.php)"
    r"(?:$|[/.?])",
    re.I,
)
_WORDPRESS = re.compile(r"(?:^|/)(?:wp-login|xmlrpc)\.php(?:$|\?)", re.I)


@dataclass(slots=True)
class Requisicao:
    """Uma linha de log de acesso já interpretada."""

    ip: str
    momento: float | None
    metodo: str
    uri: str
    status: int
    tamanho: int | None
    agente: str = ""
    referer: str = ""


def interpretar_clf(linha: str) -> Requisicao | None:
    """Common e Combined, com ou sem prefixo de host virtual ou de syslog."""
    fim_data = linha.find('] "')
    if fim_data < 0:
        return None
    inicio_data = linha.rfind(" [", 0, fim_data)
    if inicio_data < 0:
        return None
    partes = linha[:inicio_data].split()
    if len(partes) < 3:
        return None
    ip = _origem(partes)
    if not ip:
        return None
    momento = tempo.de_clf(linha[inicio_data + 2 : fim_data])
    pedido = _CAMPO.match(linha, fim_data + 2)
    if momento is None or pedido is None:
        return None
    status = _STATUS.match(linha, pedido.end())
    if status is None:
        return None
    metodo, uri = _separar_pedido(assinaturas.sem_escapes(pedido.group(1)))
    campos = _CAMPO.findall(linha, status.end())
    tamanho = status.group(2)
    return Requisicao(
        ip=ip,
        momento=momento,
        metodo=metodo,
        uri=uri,
        status=int(status.group(1)),
        tamanho=int(tamanho) if tamanho and tamanho.isdigit() else None,
        referer=assinaturas.sem_escapes(campos[0]) if campos else "",
        agente=assinaturas.sem_escapes(campos[1]) if len(campos) > 1 else "",
    )


def _origem(partes: list[str]) -> str:
    """IP do cliente: o primeiro token que é IP; senão o campo antes de ident e usuário."""
    for parte in partes:
        if eh_ip(parte):
            return parte
    candidato = partes[-3]
    return candidato if candidato != "-" and _ORIGEM.fullmatch(candidato) else ""


def _separar_pedido(pedido: str) -> tuple[str, str]:
    """``GET /a b HTTP/1.1`` em método e URL (a URL de um ataque pode ter espaços crus)."""
    partes = pedido.split(" ")
    if len(partes) < 2:
        return "", ""
    fim = -1 if partes[-1].startswith("HTTP/") else len(partes)
    return partes[0], " ".join(partes[1:fim])


class LeitorW3C:
    """IIS: as colunas são declaradas em ``#Fields`` e podem mudar no meio do arquivo."""

    def __init__(self) -> None:
        self.colunas: dict[str, int] = {}

    @property
    def ativo(self) -> bool:
        return bool(self.colunas)

    def diretiva(self, linha: str) -> None:
        if linha.lower().startswith("#fields:"):
            nomes = linha.split(":", 1)[1].split()
            self.colunas = {nome.lower(): indice for indice, nome in enumerate(nomes)}

    def _valor(self, partes: list[str], nome: str) -> str:
        indice = self.colunas.get(nome)
        if indice is None or indice >= len(partes) or partes[indice] == "-":
            return ""
        return partes[indice]

    def interpretar(self, linha: str) -> Requisicao | None:
        partes = linha.split()
        status = self._valor(partes, "sc-status")
        ip = self._valor(partes, "c-ip")
        if not status.isdigit() or not ip:
            return None
        uri = self._valor(partes, "cs-uri-stem") or self._valor(partes, "cs-uri")
        consulta = self._valor(partes, "cs-uri-query")
        tamanho = self._valor(partes, "sc-bytes")
        data = self._valor(partes, "date")
        return Requisicao(
            ip=ip,
            momento=tempo.de_w3c(data, self._valor(partes, "time")) if data else None,
            metodo=self._valor(partes, "cs-method"),
            uri=f"{uri}?{consulta}" if consulta else uri,
            status=int(status),
            tamanho=int(tamanho) if tamanho.isdigit() else None,
            agente=self._valor(partes, "cs(user-agent)").replace("+", " "),
            referer=self._valor(partes, "cs(referer)"),
        )


@dataclass(slots=True)
class _Respostas2xx:
    """Respostas 2xx de um ataque: a decisão sobre a página padrão só sai no fim."""

    tamanhos: Counter[int] = field(default_factory=Counter)
    amostras: list[tuple[int, str]] = field(default_factory=list)

    def registrar(self, tamanho: int, amostra: str) -> None:
        self.tamanhos[tamanho] += 1
        if len(self.amostras) < MAX_AMOSTRAS * 4:
            self.amostras.append((tamanho, limpar(amostra, 400)))


def _eleva(chave: str, req: Requisicao) -> bool:
    """Se uma resposta 2xx a este ataque pode indicar sucesso."""
    if not TIPOS[chave].eleva_por_2xx:
        return False
    if chave == "shellshock":
        return "cgi" in req.uri.lower() or ".sh" in req.uri.lower()
    return True


class AnalisadorWeb:
    """Acumula assinaturas, ferramentas e rajadas por IP; decide e reporta só no fim."""

    def __init__(self) -> None:
        self.requisicoes = 0
        self.iis = False
        self.ataques: dict[str, Tabela] = {chave: Tabela() for chave in TIPOS}
        self.respostas: dict[tuple[str, str], _Respostas2xx] = {}
        self.shells = Tabela()
        self.shells_fortes: set[str] = set()
        self.shells_post: set[str] = set()
        self.sensiveis = Tabela()
        self.scanners = Tabela()
        self.erros_404 = Tabela()
        self.caminhos_404: dict[str, set[int]] = defaultdict(set)
        self.logins = Tabela()
        self.tamanhos_normais: Counter[int] = Counter()
        self.tamanhos_ataque: dict[int, set[int]] = defaultdict(set)

    # -- leitura -----------------------------------------------------------------
    def alimentar(self, req: Requisicao, arquivo: str, numero: int, linha: str) -> None:
        self.requisicoes += 1
        amostra = f"{arquivo}:{numero}: {linha}"
        comum = {"arquivo": arquivo, "extra": str(req.status)}
        ferramenta = assinaturas.identificar_scanner(req.agente)
        if ferramenta:
            self.scanners.registrar(
                req.ip, req.momento, amostra, ip=req.ip, extra=ferramenta, arquivo=arquivo
            )
        self._contar_erros(req, amostra, arquivo)
        self._contar_login(req, amostra, arquivo)
        tipos = assinaturas.classificar(req.uri, req.agente, req.referer)
        ok = 200 <= req.status < 300
        for chave in tipos:
            self.ataques[chave].registrar(req.ip, req.momento, amostra, ip=req.ip, **comum)
            if ok and _eleva(chave, req):
                self._anotar_2xx(chave, req, amostra)
        shell = self._shell(req, amostra, comum, ok) if req.uri else False
        if ok and req.uri and assinaturas.arquivo_sensivel(req.uri):
            self.sensiveis.registrar(req.ip, req.momento, amostra, ip=req.ip, **comum)
            self._anotar_2xx("sensivel", req, amostra)
        elif ok and not tipos and not shell:
            self._anotar_normal(req.tamanho)

    def _contar_erros(self, req: Requisicao, amostra: str, arquivo: str) -> None:
        if req.status != 404:
            return
        self.erros_404.registrar(
            req.ip, req.momento, amostra, ip=req.ip, arquivo=arquivo, guardar_tempo=True
        )
        if req.ip not in self.caminhos_404 and len(self.caminhos_404) >= MAX_IPS_404:
            return
        caminhos = self.caminhos_404[req.ip]
        if len(caminhos) < MAX_CAMINHOS_POR_IP:
            caminhos.add(hash(req.uri.partition("?")[0]))

    def _contar_login(self, req: Requisicao, amostra: str, arquivo: str) -> None:
        caminho = req.uri.partition("?")[0]
        if req.status == 401:
            # 401 em GET de API/monitor é rotina; só conta em POST ou em página de login.
            if req.metodo != "POST" and not _LOGIN.search(caminho):
                return
            tentativa = True
        elif req.metodo != "POST" or not _LOGIN.search(caminho):
            return
        elif _WORDPRESS.search(caminho):
            # WordPress responde 200 ao errar a senha e 302 ao acertar.
            tentativa = req.status not in (301, 302, 303)
        else:
            tentativa = req.status in (403, 429)
        if tentativa:
            self.logins.registrar(
                req.ip, req.momento, amostra, ip=req.ip, arquivo=arquivo, guardar_tempo=True
            )

    def _shell(self, req: Requisicao, amostra: str, comum: dict[str, str], ok: bool) -> bool:
        sinal = assinaturas.sinal_shell(req.uri)
        if sinal is None:
            return False
        self.shells.registrar(req.ip, req.momento, amostra, ip=req.ip, **comum)
        if sinal.forte:
            self.shells_fortes.add(req.ip)
        if ok:
            self._anotar_2xx("shell", req, amostra)
            if req.metodo == "POST":
                self.shells_post.add(req.ip)
        return True

    def _anotar_2xx(self, chave: str, req: Requisicao, amostra: str) -> None:
        if req.tamanho is None:
            # Sem tamanho de resposta (IIS padrão, CLF com "-") o resultado é indeterminado.
            return
        tamanho = req.tamanho
        respostas = self.respostas.get((chave, req.ip))
        if respostas is None:
            if len(self.respostas) >= MAX_RESPOSTAS:
                return
            respostas = self.respostas[(chave, req.ip)] = _Respostas2xx()
        respostas.registrar(tamanho, amostra)
        if tamanho not in self.tamanhos_ataque and len(self.tamanhos_ataque) >= MAX_TAMANHOS:
            return
        caminhos = self.tamanhos_ataque[tamanho]
        if len(caminhos) < MAX_CAMINHOS_POR_IP:
            caminhos.add(hash(req.uri))

    def _anotar_normal(self, tamanho: int | None) -> None:
        if tamanho and (
            tamanho in self.tamanhos_normais or len(self.tamanhos_normais) < MAX_TAMANHOS
        ):
            self.tamanhos_normais[tamanho] += 1

    # -- decisão -----------------------------------------------------------------
    def _pagina_padrao(self, tamanho: int) -> bool:
        """Resposta vazia, ou de um tamanho que o site repete para qualquer pedido."""
        if tamanho == 0:
            return True
        if self.tamanhos_normais.get(tamanho, 0) >= PAGINA_NORMAL_MIN_VEZES:
            return True
        return len(self.tamanhos_ataque.get(tamanho, ())) >= PAGINA_PADRAO_MIN_CAMINHOS

    def _acertos(self, chave: str, ips: list[str]) -> tuple[int, list[str]]:
        """Quantas respostas 2xx de ``ips`` não são a página padrão, e amostras delas."""
        total = 0
        amostras: list[str] = []
        for ip in ips:
            respostas = self.respostas.get((chave, ip))
            if respostas is None:
                continue
            total += sum(n for t, n in respostas.tamanhos.items() if not self._pagina_padrao(t))
            amostras += [a for t, a in respostas.amostras if not self._pagina_padrao(t)]
        return total, amostras

    def _ips_com_acerto(self, chave: str) -> set[str]:
        return {
            ip
            for (tipo, ip), _ in self.respostas.items()
            if tipo == chave and self._acertos(chave, [ip])[0]
        }

    def relatar(self, ctx: CheckContext, ativo: str) -> int:
        antes = ctx.findings_reported
        tech = ("iis",) if self.iis else ("nginx", "apache")
        for chave in TIPOS:
            self._relatar_ataque(ctx, ativo, chave, tech)
        self._relatar_shells(ctx, ativo, tech)
        self._relatar_sensiveis(ctx, ativo, tech)
        self._relatar_scanners(ctx, ativo, tech)
        self._relatar_404(ctx, ativo, tech)
        self._relatar_logins(ctx, ativo, tech)
        return ctx.findings_reported - antes

    def _ips_de(self, chave: str, tabela: Tabela, escolhidos: str) -> list[str]:
        """IPs por trás de uma entrada de ``principais``: o próprio ou os que foram fundidos."""
        if escolhidos != CHAVE_DEMAIS:
            return [escolhidos]
        destaque = {
            ip for ip, _ in principais(tabela.itens.items(), primeiro=self._ips_com_acerto(chave))
        }
        return [ip for ip in tabela.itens if ip not in destaque]

    def _relatar_ataque(
        self, ctx: CheckContext, ativo: str, chave: str, tech: tuple[str, ...]
    ) -> None:
        tabela = self.ataques[chave]
        tipo = TIPOS[chave]
        acertaram = self._ips_com_acerto(chave)
        for ip, indicio in principais(tabela.itens.items(), primeiro=acertaram):
            acertos, amostras = self._acertos(chave, self._ips_de(chave, tabela, ip))
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            indicio.amostras = list(dict.fromkeys(amostras + indicio.amostras))[:MAX_AMOSTRAS]
            titulo = (
                f"Tentativas de {tipo.rotulo} a partir de {origem} ({indicio.total} requisições)"
            )
            resumo = (
                f"{indicio.total} requisições com assinatura de {tipo.rotulo} a partir de {origem}."
            )
            if acertos:
                titulo = (
                    f"Ataque de {tipo.rotulo} possivelmente bem-sucedido a partir de {origem} "
                    f"({acertos} respostas 2xx)"
                )
                resumo += (
                    f" {acertos} delas receberam resposta 2xx com conteúdo diferente da página "
                    "padrão do site. Isso não prova o sucesso: confira os logs da aplicação."
                )
            relatar(
                ctx,
                Relato(
                    achado=tipo.achado,
                    ativo=ativo,
                    titulo=titulo,
                    resumo=resumo,
                    discriminador=ip,
                    tecnicas=tipo.tecnicas,
                    severidade=tipo.sucesso if acertos else tipo.tentativa,
                    confianca=Confidence.TENTATIVE if acertos else Confidence.FIRM,
                    extras={
                        "possivelmente_bem_sucedido": bool(acertos),
                        "respostas_2xx": acertos,
                        "status": _status(indicio),
                    },
                    tech=tech,
                    cves=tipo.cves,
                ),
                indicio,
            )

    def _relatar_shells(self, ctx: CheckContext, ativo: str, tech: tuple[str, ...]) -> None:
        acertaram = self._ips_com_acerto("shell")
        for ip, indicio in principais(self.shells.itens.items(), primeiro=acertaram):
            acertos, amostras = self._acertos("shell", self._ips_de("shell", self.shells, ip))
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            extras = {"respostas_2xx": acertos, "status": _status(indicio)}
            if not acertos:
                relatar(
                    ctx,
                    Relato(
                        achado="logs.web.sondagem_shell",
                        ativo=ativo,
                        titulo=f"Procura por web shells a partir de {origem} ({indicio.total} requisições)",
                        resumo=(
                            f"{origem} procurou {indicio.total} vez(es) por arquivos com nome de web "
                            "shell. Nenhuma resposta indica que o arquivo exista."
                        ),
                        discriminador=ip,
                        tecnicas=("T1595.003", "T1505.003"),
                        extras=extras,
                        tech=tech,
                    ),
                    indicio,
                )
                continue
            forte = ip in self.shells_fortes
            # Só 2xx por tamanho é indireto: CRITICAL exige corroboração (POST ao arquivo).
            corroborado = forte and ip in self.shells_post
            indicio.amostras = (amostras + indicio.amostras)[:MAX_AMOSTRAS]
            relatar(
                ctx,
                Relato(
                    achado="logs.web.webshell",
                    ativo=ativo,
                    titulo=f"Possível web shell acessado por {origem} ({acertos} respostas 2xx)",
                    resumo=(
                        f"{origem} acessou uma URL com cara de web shell e recebeu {acertos} "
                        "resposta(s) 2xx com conteúdo próprio. Verifique o arquivo no servidor agora."
                    ),
                    discriminador=ip,
                    tecnicas=("T1505.003", "T1190"),
                    severidade=Severity.CRITICAL if corroborado else Severity.HIGH,
                    confianca=Confidence.FIRM if corroborado else Confidence.TENTATIVE,
                    extras=extras,
                    tech=tech,
                ),
                indicio,
            )

    def _relatar_sensiveis(self, ctx: CheckContext, ativo: str, tech: tuple[str, ...]) -> None:
        acertaram = self._ips_com_acerto("sensivel")
        candidatos = [(ip, self.sensiveis.itens[ip]) for ip in sorted(acertaram)]
        for ip, indicio in principais(candidatos):
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            acertos, amostras = self._acertos(
                "sensivel", [i for i in acertaram] if ip == CHAVE_DEMAIS else [ip]
            )
            indicio.amostras = (amostras + indicio.amostras)[:MAX_AMOSTRAS]
            relatar(
                ctx,
                Relato(
                    achado="logs.web.arquivo_sensivel",
                    ativo=ativo,
                    titulo=f"Arquivo sensível baixado por {origem} ({acertos} respostas 2xx)",
                    resumo=(
                        f"{origem} pediu arquivos de configuração ou backup e recebeu {acertos} "
                        "resposta(s) 2xx. Considere vazado o que havia neles."
                    ),
                    discriminador=ip,
                    tecnicas=("T1595.003", "T1552"),
                    confianca=Confidence.TENTATIVE,
                    extras={"respostas_2xx": acertos},
                    tech=tech,
                ),
                indicio,
            )

    def _relatar_scanners(self, ctx: CheckContext, ativo: str, tech: tuple[str, ...]) -> None:
        for ip, indicio in principais(self.scanners.itens.items()):
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            nomes = sorted(indicio.extras)
            ferramentas = ", ".join(nomes)
            alto = indicio.total >= SCANNER_REQUISICOES_ALTO
            relatar(
                ctx,
                Relato(
                    achado="logs.web.varredura_scanner",
                    ativo=ativo,
                    titulo=f"Ferramenta de varredura a partir de {origem}: {ferramentas}",
                    resumo=(
                        f"{indicio.total} requisições de {origem} se identificam como ferramenta de "
                        f"varredura ({ferramentas})."
                    ),
                    discriminador=ip,
                    tecnicas=("T1595.002",),
                    severidade=Severity.MEDIUM if alto else None,
                    extras={"ferramentas": nomes},
                    tech=tech,
                ),
                indicio,
            )

    def _relatar_404(self, ctx: CheckContext, ativo: str, tech: tuple[str, ...]) -> None:
        candidatos: list[tuple[str, Indicio]] = []
        for ip, indicio in self.erros_404.itens.items():
            caminhos = len(self.caminhos_404.get(ip, ()))
            pico = pico_na_janela(indicio.tempos, RAJADA_404_JANELA_S)
            rajada = pico >= RAJADA_404_MIN and caminhos >= RAJADA_404_MIN_CAMINHOS
            lenta = (
                indicio.total >= VARREDURA_404_MIN_TOTAL and caminhos >= VARREDURA_404_MIN_CAMINHOS
            )
            if rajada or lenta:
                candidatos.append((ip, indicio))
        for ip, indicio in principais(candidatos):
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            caminhos = len(self.caminhos_404.get(ip, ()))
            relatar(
                ctx,
                Relato(
                    achado="logs.web.varredura_404",
                    ativo=ativo,
                    titulo=f"Rajada de erros 404 a partir de {origem} ({indicio.total} requisições)",
                    resumo=(
                        f"{origem} pediu {indicio.total} endereços inexistentes: é o padrão de quem "
                        "testa uma lista de caminhos em busca de arquivos e painéis esquecidos."
                    ),
                    discriminador=ip,
                    tecnicas=("T1595.003",),
                    extras={
                        "caminhos_distintos": caminhos,
                        "pico_em_5_min": pico_na_janela(indicio.tempos, RAJADA_404_JANELA_S),
                    },
                    tech=tech,
                ),
                indicio,
            )

    def _relatar_logins(self, ctx: CheckContext, ativo: str, tech: tuple[str, ...]) -> None:
        candidatos = [
            (ip, indicio)
            for ip, indicio in self.logins.itens.items()
            if indicio.total >= LOGIN_MIN_TOTAL
            or pico_na_janela(indicio.tempos, LOGIN_JANELA_S) >= LOGIN_MIN_TENTATIVAS
        ]
        for ip, indicio in principais(candidatos):
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            relatar(
                ctx,
                Relato(
                    achado="logs.web.forca_bruta",
                    ativo=ativo,
                    titulo=f"Força bruta em página de login a partir de {origem} ({indicio.total} tentativas)",
                    resumo=f"{indicio.total} tentativas de login recusadas a partir de {origem}.",
                    discriminador=ip,
                    tecnicas=("T1110.001",),
                    extras={"pico_em_10_min": pico_na_janela(indicio.tempos, LOGIN_JANELA_S)},
                    tech=tech,
                ),
                indicio,
            )


def _status(indicio: Indicio) -> dict[str, int]:
    return dict(indicio.extras.most_common(10))
