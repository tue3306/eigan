"""Identificação da máquina (``host.info``) e fim do suporte do sistema operacional.

As datas de fim de suporte vêm de ``data/host_eol.json``, verificadas nas páginas
oficiais (Microsoft Learn, Canonical, Debian, Red Hat) e citadas no próprio
arquivo. Versão que não está na tabela não é avaliada — só registramos no log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...data import load_json
from . import sistema
from .comum import admin, ativo, inteiro

CHAVE_VERSAO = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
AVISO_DIAS = 90

_REFERENCIAS_EOL = (
    "https://learn.microsoft.com/en-us/lifecycle/faq/windows",
    "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
    "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info",
    "https://ubuntu.com/about/release-cycle",
    "https://wiki.debian.org/LTS",
    "https://access.redhat.com/support/policy/updates/errata",
)
_EXEMPLOS_EOL = (
    Fix(
        "windows",
        "Windows (PowerShell)",
        "# versão instalada\n"
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' |\n"
        "  Select-Object ProductName, DisplayVersion, CurrentBuild, EditionID\n"
        "# atualizar: Configurações > Windows Update > Verificar se há atualizações",
        "powershell",
    ),
    Fix(
        "linux",
        "Ubuntu",
        "cat /etc/os-release\nsudo apt update && sudo apt full-upgrade\nsudo do-release-upgrade",
        "bash",
    ),
    Fix(
        "linux",
        "Debian",
        "cat /etc/os-release\nsudo apt update && sudo apt full-upgrade\n"
        "# depois troque o codinome (ex.: bookworm -> trixie) em /etc/apt/sources.list\n"
        "# seguindo as notas de lançamento da nova versão e repita o full-upgrade",
        "bash",
    ),
)

kb.register(
    KBEntry(
        id="host.sistema.sem_suporte",
        title="Sistema operacional sem suporte do fabricante",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O sistema desta máquina não recebe mais correções de segurança gratuitas do fabricante.",
        explanation=(
            "Quando uma versão do Windows ou de uma distribuição Linux chega ao fim do suporte, o "
            "fabricante deixa de publicar correções para as falhas descobertas depois dessa data. "
            "Cada vulnerabilidade nova fica aberta para sempre nesta máquina, e antivírus ou "
            "firewall não substituem a correção do próprio sistema."
        ),
        risk=(
            "Falhas públicas, muitas já exploradas por ransomware, continuam abertas. Quem alcança a "
            "máquina por um anexo, um site ou a rede usa essas falhas para executar código e tomar o "
            "controle. Manter sistemas sem suporte também costuma violar exigências de auditoria, de "
            "seguro e o dever de segurança da LGPD."
        ),
        steps=(
            "Confirme a versão instalada: no Windows, tecla Windows+R e 'winver'; no Linux, "
            "'cat /etc/os-release'.",
            "Windows: atualize para uma versão com suporte pelo Windows Update ou pelo Assistente de "
            "Instalação. Se o hardware não permitir, planeje a troca do equipamento e, enquanto isso, "
            "contrate as atualizações estendidas (ESU) quando a Microsoft oferecer.",
            "Linux: atualize para a próxima versão com suporte da distribuição (ex.: "
            "'sudo do-release-upgrade' no Ubuntu) ou contrate o suporte estendido do fabricante "
            "(Ubuntu Pro/ESM, RHEL ELS) durante a migração.",
            "Antes de atualizar, faça backup completo e teste os sistemas críticos; depois, deixe as "
            "atualizações automáticas ligadas.",
        ),
        verify=(
            "Rode a auditoria de novo: a versão nova aparece na identificação do sistema com suporte "
            "válido e este achado some."
        ),
        examples=_EXEMPLOS_EOL,
        effort="alto",
        fix_group="sistema",
        references=_REFERENCIAS_EOL,
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.3"),
        tags=("fim-de-suporte", "atualizacao"),
    ),
    KBEntry(
        id="host.sistema.suporte_acabando",
        title="Suporte do sistema operacional termina em breve",
        category=Category.HOST,
        severity=Severity.LOW,
        summary=f"O fabricante deixa de publicar correções de segurança para esta versão em até {AVISO_DIAS} dias.",
        explanation=(
            "Esta versão do sistema ainda recebe correções, mas a data de fim do suporte publicada "
            "pelo fabricante está próxima. Depois dela, as falhas novas deixam de ser corrigidas."
        ),
        risk=(
            "Se a atualização não for planejada agora, a máquina passa a acumular falhas sem correção "
            "logo após a data — o mesmo risco de um sistema sem suporte."
        ),
        steps=(
            "Agende a atualização para uma versão com suporte antes da data indicada na evidência.",
            "Windows: instale a versão mais recente pelo Windows Update (Configurações > Windows "
            "Update) ou pelo Assistente de Instalação; em empresas, aprove a atualização de "
            "recursos no WSUS/Intune.",
            "Linux: planeje a migração para a próxima versão da distribuição (ex.: "
            "'sudo do-release-upgrade' no Ubuntu) e teste os serviços críticos antes.",
        ),
        verify="Depois da atualização, rode a auditoria de novo: a data de fim do suporte deve ficar distante.",
        examples=_EXEMPLOS_EOL,
        effort="medio",
        fix_group="sistema",
        references=_REFERENCIAS_EOL,
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.3"),
        tags=("fim-de-suporte", "atualizacao"),
    ),
)
#: edições cobertas pela política "Home and Pro"; edição desconhecida usa a data mais
#: longa (Enterprise/Education) para não acusar fim de suporte antes da hora
EDICOES_DOMESTICAS = frozenset(
    {
        "Core",
        "CoreN",
        "CoreSingleLanguage",
        "CoreCountrySpecific",
        "Professional",
        "ProfessionalN",
        "ProfessionalEducation",
        "ProfessionalEducationN",
        "ProfessionalWorkstation",
        "ProfessionalWorkstationN",
    }
)


@dataclass
class Suporte:
    produto: str
    fim: date
    fontes: list[str] = field(default_factory=list)
    deducao: str = ""  # por que a data vale para esta versão (quando é dedução)
    nota: str = ""  # ESU / ESM / ELS
    reduzida: bool = False  # suporte estendido pago detectado (ESM ativo)
    esu_possivel: bool = False  # ESU pago existe e não dá para saber se está inscrito


def _data(texto: str) -> date:
    return date.fromisoformat(texto)


# -- coleta ------------------------------------------------------------------------
def coletar_windows() -> dict[str, Any]:
    def ler(nome: str) -> Any:
        return sistema.read_registry_value(CHAVE_VERSAO, nome)

    produto = str(ler("ProductName") or "Windows")
    tipo = str(ler("InstallationType") or "Client")
    build = inteiro(ler("CurrentBuildNumber") or ler("CurrentBuild")) or 0
    ubr = inteiro(ler("UBR"))
    servidor = "server" in tipo.lower() or "server" in produto.lower()
    if not servidor and build >= 22000:
        produto = produto.replace("Windows 10", "Windows 11")  # o registro mantém "Windows 10"
    versao = str(ler("DisplayVersion") or ler("ReleaseId") or "") or nome_da_versao(build)
    return {
        "family": "windows",
        "os": produto,
        "version": versao,
        "build": f"{build}.{ubr}" if ubr is not None else str(build),
        "build_number": build,
        "edition": str(ler("EditionID") or ""),
        "installation_type": tipo,
        "server": servidor,
    }


def nome_da_versao(build: int) -> str:
    """Versão comercial (``22H2``...) pelo número do build, quando o registro não informa."""
    try:
        nomes = load_json("host_eol.json")["windows_nomes"]
    except (KeyError, ValueError):
        return ""
    return str(nomes.get(str(build), ""))


def ler_os_release(texto: str) -> dict[str, str]:
    campos: dict[str, str] = {}
    for linha in texto.splitlines():
        chave, sep, valor = linha.strip().partition("=")
        if sep and chave and not chave.startswith("#"):
            campos[chave] = valor.strip().strip('"').strip("'")
    return campos


def coletar_linux() -> dict[str, Any]:
    campos: dict[str, str] = {}
    for caminho in ("/etc/os-release", "/usr/lib/os-release"):
        texto = sistema.read_text_file(caminho)
        if texto:
            campos = ler_os_release(texto)
            break
    return {
        "family": "linux",
        "os": campos.get("PRETTY_NAME") or campos.get("NAME") or "Linux",
        "name": campos.get("NAME", ""),
        "distro": campos.get("ID", "").lower(),
        "distro_like": campos.get("ID_LIKE", "").lower(),
        "version": campos.get("VERSION_ID", ""),
    }


# -- tabela de fim de suporte -------------------------------------------------------------
def suporte_windows(info: dict[str, Any]) -> Suporte | None:
    dados = load_json("host_eol.json")
    fontes = dados["_fontes"]
    build = int(info.get("build_number") or 0)
    edicao = str(info.get("edition") or "")
    if info.get("server"):
        return _por_build(
            dados["windows_server"], build, "fim", fontes["windows_server"], "Windows Server"
        )
    if "EnterpriseS" in edicao:  # EnterpriseS, EnterpriseSN, IoTEnterpriseS...: canal LTSC
        familia = "IoTEnterpriseS" if edicao.startswith("IoT") else "EnterpriseS"
        for item in dados["windows_ltsc"]:
            if item["build"] == build and familia in item["edicoes"]:
                return Suporte(item["nome"], _data(item["fim"]), list(fontes["windows_ltsc"]))
        return None  # LTSC/IoT fora da tabela: não avaliamos
    domestica = edicao in EDICOES_DOMESTICAS
    campo = "fim_home_pro" if domestica else "fim_enterprise"
    fonte = fontes["windows_11"] if build >= 22000 else fontes["windows_10"]
    suporte = _por_build(dados["windows_cliente"], build, campo, fonte, "Windows")
    if suporte is not None and not suporte.deducao:
        grupo = "Home/Pro" if domestica else "Enterprise/Education"
        suporte.produto = f"{suporte.produto} ({grupo})"
        item = next(i for i in dados["windows_cliente"] if i["build"] == build)
        if item.get("esu"):
            suporte.nota = "A Microsoft oferece atualizações de segurança estendidas pagas (ESU) para esta versão; a inscrição não é detectável, então verifique se a máquina está inscrita."
            suporte.esu_possivel = True
    return suporte


def _nota_esu(esu_fim: str | None) -> str:
    """Texto sobre as atualizações estendidas pagas (ESU), conforme a data já passou ou não."""
    if not esu_fim:
        return ""
    if _data(esu_fim) < sistema.hoje():
        return f"O programa de atualizações estendidas (ESU) também terminou em {esu_fim}."
    return f"ESU (pago) até {esu_fim}."


def _por_build(
    tabela: list[dict[str, Any]], build: int, campo: str, fontes: list[str], familia: str
) -> Suporte | None:
    for item in tabela:
        if item["build"] == build:
            nota = _nota_esu(item.get("esu_fim"))
            aberto = bool(item.get("esu_fim")) and _data(item["esu_fim"]) >= sistema.hoje()
            return Suporte(
                item["nome"], _data(item[campo]), list(fontes), nota=nota, esu_possivel=aberto
            )
    menor = min(tabela, key=lambda i: int(i["build"]))
    if build and build < int(menor["build"]):
        fim = menor.get(campo) or menor.get("fim_enterprise") or menor["fim"]
        return Suporte(
            f"{familia} (build {build})",
            _data(fim),
            list(fontes),
            deducao=f"versão anterior ao {menor['nome']}, cujo suporte terminou em {fim}",
        )
    return None


def _ubuntu_intermediaria(chave: str, nome: str, fontes: list[str]) -> Suporte | None:
    """Versão não LTS do Ubuntu fora da tabela: a Canonical dá 9 meses de suporte."""
    partes = _tupla(chave)
    if partes is None or len(partes) != 2:
        return None
    ano, mes = partes
    lts = mes == 4 and ano % 2 == 0
    if lts or mes not in (4, 10):
        return None
    meses = 2000 + ano, mes + 9
    limite = date(meses[0] + (meses[1] - 1) // 12, (meses[1] - 1) % 12 + 1, 1)
    if limite >= sistema.hoje():
        return None
    return Suporte(
        f"{nome} {chave}",
        limite,
        fontes,
        deducao=(
            f"versão intermediária (não LTS) lançada em {2000 + ano}-{mes:02d}; a Canonical dá "
            "9 meses de suporte, então o prazo terminou no máximo no início de "
            f"{limite.strftime('%m/%Y')}"
        ),
    )


def _tupla(versao: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(parte) for parte in versao.split("."))
    except ValueError:
        return None


def suporte_linux(info: dict[str, Any]) -> Suporte | None:
    dados = load_json("host_eol.json")
    distro = str(info.get("distro") or "")
    nome = f"{info.get('name', '')} {info.get('os', '')}".lower()
    if distro == "centos" and "stream" in nome:
        return None  # CentOS Stream tem ciclo próprio, fora da tabela
    tabela = dados["linux"].get(distro)
    versao = str(info.get("version") or "")
    if not tabela or not versao:
        return None
    chave = versao if distro == "ubuntu" else versao.split(".")[0]
    fontes = list(dados["_fontes"].get(distro, []))
    item = tabela["versoes"].get(chave)
    if item is not None:
        suporte = Suporte(f"{tabela['nome']} {chave}", _data(item["fim"]), fontes)
        if item.get("esm_ate"):
            suporte.nota = f"Com Ubuntu Pro (ESM), as correções seguem até {item['esm_ate']}."
        if item.get("els"):
            suporte.nota = "A Red Hat vende suporte estendido (ELS) para esta versão."
        return suporte
    alvo = _tupla(chave)
    menor = min(tabela["versoes"], key=lambda v: _tupla(v) or (0,))
    if alvo is not None and alvo < (_tupla(menor) or (0,)):
        fim = tabela["versoes"][menor]["fim"]
        return Suporte(
            f"{tabela['nome']} {chave}",
            _data(fim),
            fontes,
            deducao=f"versão anterior a {menor}, cujo suporte terminou em {fim}",
        )
    if distro == "ubuntu":
        return _ubuntu_intermediaria(chave, tabela["nome"], fontes)
    return None


def esm_ativo() -> bool:
    """Ubuntu Pro/ESM configurado no APT (repositórios esm.ubuntu.com)."""
    pasta = "/etc/apt/sources.list.d"
    for nome in sistema.list_dir(pasta) or []:
        texto = sistema.read_text_file(f"{pasta}/{nome}") or ""
        if _esm_infra_ativo(texto):
            return True
    return False


def _esm_infra_ativo(texto: str) -> bool:
    """Linha ativa (não comentada) do repositório esm-infra, que cobre o arquivo 'main'.

    Só esm-apps cobre o 'universe' e não basta; blocos deb822 com ``Enabled: no`` não contam.
    """
    blocos = [b for b in texto.replace("\r", "").split("\n\n") if b.strip()]
    for bloco in blocos:
        linhas = [x.strip() for x in bloco.splitlines() if not x.strip().startswith("#")]
        if not any("esm.ubuntu.com/infra" in x for x in linhas):
            continue
        if any(x.lower().replace(" ", "") == "enabled:no" for x in linhas):
            continue
        return True
    return False


# -- checagem ----------------------------------------------------------------------
@check(
    id="host.info",
    name="Identificação do sistema e suporte do fabricante",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Coleta sistema, versão, build, edição, nome, arquitetura e privilégio da auditoria, e "
        "confere o fim do suporte do sistema operacional (tabela verificada e citada)."
    ),
    findings=("host.sistema.sem_suporte", "host.sistema.suporte_acabando"),
    facts=(facts.HOST_INFO,),
    platforms=frozenset({"windows", "linux"}),
    order=5,
)
def check_info(ctx: CheckContext, fact: Fact) -> None:
    plataforma = str(fact.data.get("platform") or fact.key)
    try:
        info = coletar_windows() if plataforma == "windows" else coletar_linux()
    except sistema.AcessoNegado:
        ctx.log(f"Identificação do sistema: {sistema.NAO_VERIFICADO}")
        return
    info.update(sistema.info_plataforma())
    info["admin"] = admin(ctx)
    descricao = f"{info['os']} {info.get('version', '')}".strip()
    ctx.add_fact(facts.HOST_INFO, plataforma, f"Sistema identificado: {descricao}", **info)
    if not info["admin"]:
        ctx.log(
            "Auditoria sem privilégio de administrador/root: alguns itens ficam 'não verificados'."
        )
    try:
        suporte = suporte_windows(info) if plataforma == "windows" else suporte_linux(info)
    except (KeyError, ValueError) as exc:
        ctx.log(f"Tabela de fim de suporte inválida: {exc}")
        return
    if suporte is None:
        ctx.log(f"Fim de suporte não avaliado para {descricao}: versão fora da tabela verificada.")
        return
    if plataforma == "linux" and info.get("distro") == "ubuntu" and suporte.fim < sistema.hoje():
        try:
            suporte.reduzida = esm_ativo()
        except sistema.AcessoNegado:
            suporte.reduzida = False
    _avaliar(ctx, info, suporte)


def _avaliar(ctx: CheckContext, info: dict[str, Any], suporte: Suporte) -> None:
    dias = (suporte.fim - sistema.hoje()).days
    base = f"{info['os']} {info.get('version', '')}".strip()
    if info.get("build"):
        base += f" (build {info['build']})"
    extras = [texto for texto in (suporte.deducao, suporte.nota) if texto]
    detalhes = {
        "produto": suporte.produto,
        # em dedução a data é só um limite, não o fim real desta versão: não a publicamos
        "fim_suporte": None if suporte.deducao else suporte.fim.isoformat(),
        "dias": dias,
        "fontes": suporte.fontes,
        "deducao": suporte.deducao or None,
    }
    if dias < 0:
        if suporte.deducao:
            evidencia = f"{base}: {suporte.produto} — suporte já terminou ({suporte.deducao})."
            extras = [suporte.nota] if suporte.nota else []
        else:
            evidencia = (
                f"{base}: {suporte.produto} — suporte terminou em {suporte.fim.isoformat()}."
            )
        ctx.report(
            "host.sistema.sem_suporte",
            asset=ativo(ctx),
            title="Sistema operacional fora do suporte padrão (ESM ativo)"
            if suporte.reduzida
            else None,
            severity=Severity.LOW if suporte.reduzida else None,
            evidence=" ".join([evidencia, *extras]),
            details=detalhes,
            confidence=Confidence.TENTATIVE
            if suporte.reduzida or suporte.esu_possivel
            else Confidence.FIRM,
            tech=[str(info.get("family", ""))],
        )
    elif dias <= AVISO_DIAS:
        ctx.report(
            "host.sistema.suporte_acabando",
            asset=ativo(ctx),
            evidence=" ".join(
                [
                    f"{base}: {suporte.produto} — suporte termina em {suporte.fim.isoformat()} ({dias} dias).",
                    *extras,
                ]
            ),
            details=detalhes,
            confidence=Confidence.FIRM,
            tech=[str(info.get("family", ""))],
        )
    else:
        ctx.passed(
            "host.sistema.suporte",
            f"{suporte.produto} com suporte do fabricante até {suporte.fim.isoformat()}",
            ativo(ctx),
        )
