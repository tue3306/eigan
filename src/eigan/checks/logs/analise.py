"""Análise de logs: indícios de ataque em logs de autenticação, de acesso web e do Windows.

A checagem recebe o caminho informado (arquivo ou pasta), lê cada arquivo aos poucos
(``.gz`` e UTF-16 incluídos), escolhe o formato pelo conteúdo e entrega cada linha ao
analisador certo. Nada é executado nem enviado para fora: é só leitura de arquivos.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from . import kb_auth, kb_web, kb_windows  # noqa: F401  (registram as entradas da base)
from .auth import AnalisadorAuth
from .leitura import (
    ERROS_LEITURA,
    ArquivoBinario,
    ArquivoLog,
    CompressaoNaoSuportada,
    Orcamento,
    TextoAberto,
    abrir_texto,
    data_referencia,
    descobrir,
    ler_linhas,
)
from .web import AnalisadorWeb, LeitorW3C, interpretar_clf
from .windows import blocos_xml, eh_csv_windows, eventos_csv, interpretar_bloco
from .windows_analise import AnalisadorWindows

#: tempo máximo de leitura (segundos), abaixo do limite da checagem
TEMPO_LEITURA_S = 160.0
#: arquivos ilegíveis ou binários listados no registro de atividade
MAX_AVISOS = 10

ACHADOS = (
    "logs.linux.admin_uid_zero",
    "logs.linux.grupo_admin",
    "logs.linux.novo_usuario",
    "logs.ssh.forca_bruta",
    "logs.ssh.forca_bruta_distribuida",
    "logs.ssh.sucesso_apos_falhas",
    "logs.ssh.usuarios_invalidos",
    "logs.sudo.falhas",
    "logs.sudo.nao_autorizado",
    "logs.web.arquivo_sensivel",
    "logs.web.cmdi",
    "logs.web.forca_bruta",
    "logs.web.lfi",
    "logs.web.log4shell",
    "logs.web.rfi",
    "logs.web.shellshock",
    "logs.web.sondagem_shell",
    "logs.web.sqli",
    "logs.web.ssrf_metadados",
    "logs.web.traversal",
    "logs.web.varredura_404",
    "logs.web.varredura_scanner",
    "logs.web.webshell",
    "logs.web.xss",
    "logs.windows.comando_suspeito",
    "logs.windows.forca_bruta",
    "logs.windows.grupo_privilegiado",
    "logs.windows.log_apagado",
    "logs.windows.rdp_apos_falhas",
    "logs.windows.servico_instalado",
    "logs.windows.usuario_criado",
)


@dataclass
class _Estado:
    """Analisadores e contadores de uma execução."""

    auth: AnalisadorAuth = field(default_factory=AnalisadorAuth)
    web: AnalisadorWeb = field(default_factory=AnalisadorWeb)
    windows: AnalisadorWindows = field(default_factory=AnalisadorWindows)
    lidos: int = 0
    avisos: list[str] = field(default_factory=list)

    def aviso(self, texto: str) -> None:
        if len(self.avisos) < MAX_AVISOS:
            self.avisos.append(texto)


def _formato(amostra: str) -> str:
    """Reconhece o formato pelo começo do arquivo: xml, csv, w3c ou texto."""
    if "<Event" in amostra and "<EventID" in amostra:
        return "xml"
    if "#Fields:" in amostra:
        return "w3c"
    if eh_csv_windows(amostra):
        return "csv"
    return "texto"


def _ler_texto(aberto: TextoAberto, arquivo: ArquivoLog, orc: Orcamento, estado: _Estado) -> None:
    w3c = LeitorW3C() if _formato(aberto.amostra) == "w3c" else None
    referencia = data_referencia(arquivo.caminho)
    for numero, linha in enumerate(ler_linhas(aberto.fluxo, orc), 1):
        if w3c is not None:
            if linha.startswith("#"):
                w3c.diretiva(linha)
                continue
            requisicao = w3c.interpretar(linha) if w3c.ativo else None
            if requisicao is not None:
                estado.web.iis = True
                estado.web.alimentar(requisicao, arquivo.rotulo, numero, linha)
            continue
        if estado.auth.alimentar(linha, arquivo.rotulo, numero, referencia):
            continue
        if '] "' in linha:
            requisicao = interpretar_clf(linha)
            if requisicao is not None:
                estado.web.alimentar(requisicao, arquivo.rotulo, numero, linha)


def _ler_arquivo(arquivo: ArquivoLog, orc: Orcamento, estado: _Estado) -> None:
    with abrir_texto(arquivo.caminho) as aberto:
        formato = _formato(aberto.amostra)
        if formato == "xml":
            for numero, bloco in enumerate(blocos_xml(aberto.fluxo, orc), 1):
                evento = interpretar_bloco(bloco, f"{arquivo.rotulo}:{numero}")
                if evento is not None:
                    estado.windows.alimentar(evento)
        elif formato == "csv":
            estado.windows.fuso = "horário local do arquivo"
            for evento in eventos_csv(aberto.fluxo, aberto.amostra, orc, arquivo.rotulo):
                estado.windows.alimentar(evento)
        else:
            _ler_texto(aberto, arquivo, orc, estado)
    estado.lidos += 1


def _passou(
    ctx: CheckContext, ativo: str, controle: str, texto: str, reconhecido: int, achados: int
) -> None:
    if reconhecido and not achados:
        ctx.passed(controle, texto, ativo)


@check(
    id="logs.analise",
    name="Indícios de ataque nos logs",
    category=Category.LOGS,
    consumes=facts.LOGS_SOURCE,
    description=(
        "Lê logs de autenticação do Linux, de acesso web (nginx, Apache, IIS) e eventos de "
        "segurança do Windows (XML ou CSV) e aponta força bruta, ataques web, varreduras, "
        "contas criadas, limpeza de logs e comandos suspeitos."
    ),
    findings=ACHADOS,
    timeout=180.0,
)
def check_logs(ctx: CheckContext, fact: Fact) -> None:
    origem = Path(str(fact.data.get("path") or fact.key))
    ativo = str(origem)
    descoberta = descobrir(origem, ctx.settings)
    for problema in descoberta.problemas[:MAX_AVISOS]:
        ctx.log(f"Logs: não foi possível ler {problema}")
    if descoberta.limite_atingido:
        ctx.log("Logs: limite de arquivos atingido, o restante da pasta foi ignorado.")
    orc = Orcamento.novo(ctx.settings, ctx.check_cancel, TEMPO_LEITURA_S)
    estado = _Estado()
    for arquivo in descoberta.arquivos:
        ctx.check_cancel()
        if orc.esgotado:
            break
        try:
            _ler_arquivo(arquivo, orc, estado)
        except CompressaoNaoSuportada:
            estado.aviso(f"{arquivo.rotulo}: compactação não suportada (.zst), descompacte antes")
        except ArquivoBinario:
            estado.aviso(f"{arquivo.rotulo}: arquivo binário, exporte como texto, CSV ou XML")
        except (*ERROS_LEITURA, csv.Error, ValueError, OverflowError) as erro:
            estado.aviso(f"{arquivo.rotulo}: erro de leitura ({type(erro).__name__})")
    for aviso in estado.avisos:
        ctx.log(f"Logs: {aviso}")
    parcial = orc.esgotado
    if parcial:
        ctx.log(f"Logs: leitura interrompida pelo limite ({orc.motivo}); resultado parcial.")
    achados_auth = estado.auth.relatar(ctx, ativo, parcial)
    achados_web = estado.web.relatar(ctx, ativo)
    achados_win = estado.windows.relatar(ctx, ativo, parcial)
    if not (estado.auth.reconhecidas or estado.web.requisicoes or estado.windows.eventos):
        ctx.log(f"Logs: nenhum formato conhecido em {estado.lidos} arquivo(s) lido(s).")
        return
    if parcial or estado.avisos or descoberta.problemas or descoberta.limite_atingido:
        # Leitura incompleta não pode virar ponto forte: parte do histórico ficou de fora.
        return
    _passou(
        ctx,
        ativo,
        "logs.auth",
        "Logs de autenticação analisados sem indícios de ataque",
        estado.auth.reconhecidas,
        achados_auth,
    )
    _passou(
        ctx,
        ativo,
        "logs.web",
        "Logs de acesso web analisados sem indícios de ataque",
        estado.web.requisicoes,
        achados_web,
    )
    _passou(
        ctx,
        ativo,
        "logs.windows",
        "Eventos do Windows analisados sem indícios de ataque",
        estado.windows.eventos,
        achados_win,
    )
