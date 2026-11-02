"""Assinaturas de ataque em requisições web: o que procurar em cada URL e cabeçalho.

As regras são deliberadamente estreitas. URLs comuns se parecem com ataques o tempo todo
(``?q=O'Reilly``, ``?returnUrl=..%2Fhome``, ``/docs/union-select``, ``?url=https://...``) e falso
positivo é defeito: cada padrão exige a sintaxe do ataque, não só a palavra. As regras de
SSRF, inclusão de arquivo e nomes de ferramentas seguem as ideias do OWASP Core Rule Set
(Apache-2.0), reescritas aqui em Python; nenhum padrão foi copiado de GPL.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote_plus

from ...core.models import Severity
from ...data import load_json

#: voltas de ``../`` além da raiz que caracterizam fuga da pasta do site. Um nível só acontece
#: com robôs que não normalizam links relativos, sem nenhuma intenção de ataque.
TRAVESSIA_MIN_ALEM_DA_RAIZ = 2
#: voltas seguidas de ``../`` no valor de um parâmetro que caracterizam ataque
TRAVESSIA_MIN_NA_CONSULTA = 3
#: voltas de decodificação da URL (atacantes codificam duas ou três vezes)
VOLTAS_DECODIFICACAO = 3
#: tamanho máximo da URL e dos cabeçalhos analisados (o resto é cortado: o atacante controla o log)
MAX_URI = 4_096
MAX_CABECALHO = 1_024


@dataclass(frozen=True)
class TipoAtaque:
    """Um tipo de ataque: o achado, as severidades e as técnicas do ATT&CK."""

    achado: str
    rotulo: str
    tentativa: Severity
    sucesso: Severity
    tecnicas: tuple[str, ...]
    cves: tuple[str, ...] = ()
    #: o status 2xx pode indicar sucesso (Log4Shell e XSS refletido: não indica)
    eleva_por_2xx: bool = True


TIPOS: dict[str, TipoAtaque] = {
    "sqli": TipoAtaque(
        "logs.web.sqli", "injeção de SQL", Severity.MEDIUM, Severity.HIGH, ("T1190",)
    ),
    "xss": TipoAtaque(
        "logs.web.xss", "XSS", Severity.LOW, Severity.MEDIUM, ("T1190",), eleva_por_2xx=False
    ),
    "traversal": TipoAtaque(
        "logs.web.traversal", "path traversal", Severity.MEDIUM, Severity.HIGH, ("T1190",)
    ),
    "lfi": TipoAtaque(
        "logs.web.lfi", "inclusão de arquivo local", Severity.MEDIUM, Severity.HIGH, ("T1190",)
    ),
    "rfi": TipoAtaque(
        "logs.web.rfi",
        "inclusão de arquivo remoto",
        Severity.MEDIUM,
        Severity.CRITICAL,
        ("T1190", "T1105"),
    ),
    "cmdi": TipoAtaque(
        "logs.web.cmdi",
        "injeção de comandos",
        Severity.MEDIUM,
        Severity.CRITICAL,
        ("T1190", "T1059.004"),
    ),
    "log4shell": TipoAtaque(
        "logs.web.log4shell",
        "Log4Shell",
        Severity.MEDIUM,
        Severity.CRITICAL,
        ("T1190",),
        ("CVE-2021-44228",),
        eleva_por_2xx=False,
    ),
    "shellshock": TipoAtaque(
        "logs.web.shellshock",
        "Shellshock",
        Severity.MEDIUM,
        Severity.CRITICAL,
        ("T1190", "T1059.004"),
        ("CVE-2014-6271",),
    ),
    "ssrf": TipoAtaque(
        "logs.web.ssrf_metadados",
        "SSRF contra o serviço de metadados da nuvem",
        Severity.MEDIUM,
        Severity.HIGH,
        ("T1190", "T1552.005"),
    ),
}

# Filtro rápido: URL sem nenhum destes trechos não precisa passar pelas regras caras.
_TALVEZ_URI = re.compile(
    r"%|\+|\.\.|/\*|--|['\"<$(;|`\\]|/etc/|/proc/|://|win\.ini|boot\.ini|\.htpasswd|wp-config|"
    r"169\.254|metadata|meta-data|information_schema|xp_cmdshell|/bin/|@@|cmd\.exe",
    re.I,
)
_TALVEZ_CABECALHO = re.compile(r"\$\{|%24%7b|\(\s*\)\s*\{|\(\)%20\{", re.I)
_TALVEZ_SHELL = re.compile(r"\.(?:php|phtml|phar|aspx?|jspx?|cgi|pl)|%2e|%25", re.I)
_TALVEZ_SENSIVEL = re.compile(r"/\.(?:env|git|aws|ssh|htpasswd)|\.sql|%2e|%25", re.I)

_SQL_COMENTARIO = re.compile(r"/\*(?!!).*?\*/")
_SQL_MARCAS = re.compile(r"/\*!\d*|\*/")
_SQLI_UNIAO = re.compile(
    r"\bunion\s+(?:all\s+|distinct\s+)?select\s*\(*\s*"
    r"(?:null\b|\d|@@|\*|0x|['\"]|concat|group_concat|char\(|version\(|user\(|database\(|"
    r"\w+\s*,|[\w.,\s*()`]+?\bfrom\s)"
)
_SQLI_CONSULTA = re.compile(
    r"['\"`)]\s*(?:or|and|xor|\|\||&&)\s+\(?['\"]?\w*['\"]?\s*"
    r"(?:=|<|>|like\b|rlike\b|regexp\b|between\b|is\s+null|in\s*\()"
    r"|(?:^|[\s=(&,])(?:or|and)\s+\(?\d+\)?\s*=\s*\(?\d+\b"
    r"|['\"]\s*(?:;\s*)?(?:--(?:\s|$)|#\s*$|/\*)"
    r"|;\s*(?:drop|truncate)\s+(?:table|database)\b"
    r"|;\s*(?:shutdown|exec(?:ute)?\s+(?:master|xp_)|insert\s+into\b|delete\s+from\b)"
    r"|(?:['\"`);,]|\b(?:select|and|or|then|else)\b)\s*\(?\s*\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)"
    r"|\bbenchmark\s*\(\s*\d+\s*,"
    r"|\bwaitfor\s+delay\s+['\"]"
    r"|\binformation_schema\.(?:tables|columns|schemata|processlist)\b"
    r"|\b(?:mysql\.user|sysobjects|syscolumns|pg_catalog\.pg_|sqlite_master)\b"
    r"|\bxp_cmdshell\b"
    r"|\b(?:extractvalue|updatexml)\s*\("
    r"|\bload_file\s*\("
    r"|\binto\s+(?:out|dump)file\b"
    r"|@@(?:version|datadir|hostname)\b"
)

_XSS_FUNCOES = r"(?:alert|prompt|confirm|eval|fetch|import|atob|document\.|window\.|location|top\.)"
_XSS = re.compile(
    r"<\s*/?\s*script\b"
    r"|<\s*(?:img|svg|body|iframe|video|audio|details|input|marquee|object|embed|a|div|form|"
    r"math|style|base|link|meta)\b[^>]{0,200}?\bon[a-z]{3,20}\s*="
    r"|<\s*(?:iframe|embed|object)\b[^>]{0,200}?\b(?:src|data)\s*=\s*['\"]?\s*(?:javascript|data):"
    r"|['\"\s/]on(?:error|load|mouseover|mouseenter|focus|click|toggle|animationstart|"
    rf"pointerover|wheel)\s*=\s*['\"]?\s*(?:javascript:|{_XSS_FUNCOES})"
    rf"|javascript\s*:\s*{_XSS_FUNCOES}"
)

# Sequências que nenhum navegador produz: pontos codificados, dupla codificação e UTF-8 inválido.
_TRAVESSIA_BRUTA = re.compile(
    r"%2e%2e(?:%2f|%5c|/|\\)|%2e\.(?:%2f|%5c|/)|\.%2e(?:%2f|%5c|/)|%252e|%c0%ae|%c0%af|%c1%9c|"
    r"%c1%1c|%e0%80%ae|\.\.%25(?:2f|5c)|\.\.%c0%af|\.\.;/",
    re.I,
)
_TRAVESSIA_CAMINHO_BRUTA = re.compile(r"\.\.(?:%2f|%5c)", re.I)
_TRAVESSIA_CONSULTA = re.compile(
    rf"(?:\.\.[/\\]){{{TRAVESSIA_MIN_NA_CONSULTA},}}|(?:\.\.\.\.[/\\]{{2}}){{2,}}"
)

_LFI_ALVO = (
    r"(?<![\w.-])(?:etc/(?:passwd|shadow|group|hosts|sudoers)|proc/self/(?:environ|cmdline|maps|status|fd/\d+)|"
    r"(?:windows|winnt)[/\\](?:win\.ini|system\.ini|system32[/\\]\S+)|win\.ini|boot\.ini|"
    r"var/log/(?:apache2?|httpd|nginx|auth\.log|messages|secure)\S*|\.htpasswd|wp-config\.php)"
)
_LFI_CONSULTA = re.compile(rf"(?:^|=)[^&\s]*?{_LFI_ALVO}(?=$|&|\x00|#)")
_LFI_CAMINHO = re.compile(rf"^/+{_LFI_ALVO}(?=$|\x00)|\.\.[/\\].*?{_LFI_ALVO}(?=$|\x00)")
_LFI_WRAPPER = re.compile(
    r"(?:^|=)\s*(?:php://(?:filter|input|fd|memory|temp)|expect://|phar://|zip://|"
    r"data:(?://)?text/(?:plain|html)[;,]|file:///?[a-z/\\])"
)

_RFI = re.compile(
    r"(?:^|[&;])(?P<nome>[\w.\[\]-]{1,40})=(?:https?|ftps?)://(?P<host>[^/?&\s:]+)(?P<resto>[^&\s]*)"
)
_RFI_NOMES = frozenset(
    "page file include inc path template tpl doc document folder root dir pg style pdf view "
    "lang language module mod content layout conf config load require site show".split()
)
_RFI_SCRIPT = re.compile(r"\.(?:txt|php\d?|phtml|inc|jsp|aspx?|sh|pl|py|cgi)(?:\?.*)?$|\?$")
_IP_LITERAL = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-f:]+\]$")

_CMDI = re.compile(
    r"(?:(?<![=?&])[;|]|&&|\$\(|`|\n)\s*(?:(?:/usr(?:/local)?)?/s?bin/)?(?:"
    r"cat\s+/[\w./-]+|ls\s+-[a-z]+|uname\s+-[a-z]+|"
    r"(?:wget|curl|fetch)\s+\S+|(?:nc|ncat|netcat)\s+\S+|"
    r"(?:ba|z|da|k)?sh\s+-[a-z]+|(?:chmod|chown)\s+\S+\s+\S+|rm\s+-[a-z]+|"
    r"(?:python[23]?|perl|ruby|php)\s+-[a-z]\b|"
    r"(?:id|whoami|ifconfig|ipconfig|pwd|hostname)\s*(?:$|[;|&`)])|"
    r"(?:ping|nslookup|dig)\s+\S+|sleep\s+\d+\s*(?:$|[;|&`)])|"
    r"powershell|cmd(?:\.exe)?\s*/[ck]\b"
    r")"
    r"|\$\{ifs\}"
    r"|(?:^|[=;|&])\s*/bin/(?:ba)?sh\b"
    r"|system32[/\\]cmd\.exe(?:$|[&?]|\s*/[ck]\b)"
)

_LOG4J_INTERNO = re.compile(r"\$\{(?:lower|upper):([^{}]*)\}|\$\{[^{}]*?:-([^{}]*)\}")
_SHELLSHOCK = re.compile(r"(?<![\w$])\(\s*\)\s*\{[^}]{0,200}\}\s*[;>]")
_SSRF = re.compile(
    r"(?:^|//|[=@:?&\s\[])(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
    r"fd00:ec2::254)(?:$|[/:?&\s\]#])"
    r"|//(?:2852039166|0xa9fea9fe)(?:$|[/:?&\s#])"
    r"|(?:^|/)latest/(?:meta-data|user-data|dynamic/instance-identity)(?:$|[/?&\s])"
    r"|(?:^|/)computemetadata/v1(?:$|[/?&\s])"
    r"|/metadata/(?:instance|identity/oauth2/token)[/?].*\bapi-version="
)

_UPLOAD_SCRIPT = re.compile(
    r"/(?:wp-content/)?(?:uploads?|upfiles|userfiles)/(?:[^?]*/)?[^/?]+\.(?:php\d?|phtml|phar|aspx?|jspx?)$"
)
_NOME_ALEATORIO = re.compile(r"^(?:[0-9a-f]{8,}|[0-9]{6,})[.]")
_SCRIPT = re.compile(r"\.(?:php\d?|phtml|phar|aspx?|jspx?|cgi|pl)$")
_PARAM_SHELL = re.compile(
    r"(?:^|&)(?:cmd|exec|execute|command|shell|run|system)="
    r"(?:ls|dir|id|whoami|uname|cat\s|pwd|wget\s|curl\s|net\s+user|ipconfig|ifconfig|ps\s|nc\s|"
    r"bash|sh\s|powershell|cmd)\b"
)
_ARQUIVO_SENSIVEL = re.compile(
    r"^/(?:[^/]+/)*(?:"
    r"\.env(?:\.(?:local|prod|production|dev|development|staging|backup|bak|old))?|"
    r"\.git/(?:config|head)|\.aws/credentials|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|\.htpasswd|"
    r"(?:wp-config|configuration|config|settings)\.php\.(?:bak|old|save|orig|swp|txt)|"
    r"(?:backup|dump|database|db)\.sql(?:\.gz)?"
    r")$"
)
_ESCAPE_LOG = re.compile(r"\\x([0-9a-fA-F]{2})|\\(.)")


def sem_escapes(texto: str) -> str:
    """Desfaz os escapes do log (``\\x22`` no nginx, ``\\"`` no Apache)."""
    if "\\" not in texto:
        return texto

    def _trocar(achado: re.Match[str]) -> str:
        return chr(int(achado.group(1), 16)) if achado.group(1) else achado.group(2)

    return _ESCAPE_LOG.sub(_trocar, texto)


def decodificar(texto: str) -> str:
    """Desfaz a codificação de URL até estabilizar (limitada: ``%25252e`` é o ataque)."""
    atual = texto
    for _ in range(VOLTAS_DECODIFICACAO):
        novo = unquote_plus(atual)
        if novo == atual:
            break
        atual = novo
    return atual


@dataclass(frozen=True)
class Uri:
    """Uma URL separada em caminho e consulta, crua e decodificada (em minúsculas)."""

    bruta: str
    caminho: str
    consulta: str

    @property
    def completa(self) -> str:
        return f"{self.caminho}?{self.consulta}" if self.consulta else self.caminho


@lru_cache(maxsize=2_048)
def analisar_uri(uri: str) -> Uri:
    """Decodifica depois de separar: um ``?`` codificado não pode inventar uma consulta."""
    sem_origem = re.sub(r"^[a-z][a-z0-9+.-]*://[^/?]*", "", uri, flags=re.I) or "/"
    caminho, _, consulta = sem_origem.partition("?")
    return Uri(uri, decodificar(caminho).lower(), decodificar(consulta).lower())


def _sqli(uri: Uri) -> bool:
    texto = _SQL_MARCAS.sub(" ", _SQL_COMENTARIO.sub(" ", uri.completa))
    if _SQLI_UNIAO.search(texto):
        return True
    return (
        bool(uri.consulta)
        and _SQLI_CONSULTA.search(_SQL_MARCAS.sub(" ", _SQL_COMENTARIO.sub(" ", uri.consulta)))
        is not None
    )


def _xss(uri: Uri) -> bool:
    return _XSS.search(html.unescape(uri.completa)) is not None


def _escapa_da_raiz(caminho: str) -> bool:
    profundidade = 0
    for parte in re.split(r"[/\\]+", caminho):
        if parte == "..":
            profundidade -= 1
            if profundidade <= -TRAVESSIA_MIN_ALEM_DA_RAIZ:
                return True
        elif parte and parte != ".":
            profundidade += 1
    return False


def _travessia(uri: Uri) -> bool:
    if _TRAVESSIA_BRUTA.search(uri.bruta):
        return True
    caminho_bruto = uri.bruta.partition("?")[0]
    if _TRAVESSIA_CAMINHO_BRUTA.search(caminho_bruto) or _escapa_da_raiz(uri.caminho):
        return True
    return _TRAVESSIA_CONSULTA.search(uri.consulta) is not None


def _lfi(uri: Uri) -> bool:
    if _LFI_CAMINHO.search(uri.caminho):
        return True
    return _LFI_CONSULTA.search(uri.consulta) is not None or (
        _LFI_WRAPPER.search(uri.consulta) is not None
    )


def _rfi(uri: Uri) -> bool:
    for achado in _RFI.finditer(uri.consulta):
        nome = achado.group("nome").split("[", 1)[0]
        suspeito = nome in _RFI_NOMES or _IP_LITERAL.match(achado.group("host")) is not None
        if suspeito and _RFI_SCRIPT.search(achado.group("resto")):
            return True
    return False


def eh_log4shell(texto: str) -> bool:
    """Procura ``${jndi:`` mesmo escondido em buscas aninhadas, como ``${${lower:j}ndi:``."""
    if "$" not in texto:
        return False
    atual = texto.lower()
    for _ in range(8):
        novo = _LOG4J_INTERNO.sub(lambda m: m.group(1) or m.group(2) or "", atual)
        if novo == atual:
            break
        atual = novo
    return "${jndi:" in atual


def _em_cabecalhos(agente: str, referer: str) -> list[str]:
    encontrados: list[str] = []
    for bruto in (agente, referer):
        if bruto and _TALVEZ_CABECALHO.search(bruto):
            texto = decodificar(bruto)
            if "log4shell" not in encontrados and eh_log4shell(texto):
                encontrados.append("log4shell")
            if "shellshock" not in encontrados and _SHELLSHOCK.search(texto):
                encontrados.append("shellshock")
    return encontrados


def classificar(uri: str, agente: str, referer: str) -> list[str]:
    """Tipos de ataque (chaves de ``TIPOS``) presentes em uma requisição."""
    uri = uri[:MAX_URI]
    tipos = _em_cabecalhos(agente[:MAX_CABECALHO], referer[:MAX_CABECALHO])
    if not uri or not _TALVEZ_URI.search(uri):
        return tipos
    partes = analisar_uri(uri)
    verificadores = (
        ("sqli", _sqli),
        ("xss", _xss),
        ("traversal", _travessia),
        ("lfi", _lfi),
        ("rfi", _rfi),
    )
    for chave, verificador in verificadores:
        if verificador(partes):
            tipos.append(chave)
    if _CMDI.search(partes.completa):
        tipos.append("cmdi")
    if "log4shell" not in tipos and eh_log4shell(partes.completa):
        tipos.append("log4shell")
    if "shellshock" not in tipos and _SHELLSHOCK.search(partes.completa):
        tipos.append("shellshock")
    if _SSRF.search(partes.completa):
        tipos.append("ssrf")
    return tipos


@dataclass(frozen=True)
class SinalShell:
    """Por que a URL parece um web shell. ``forte`` quando o nome é inconfundível."""

    forte: bool
    motivo: str


@lru_cache(maxsize=1)
def _nomes_shell() -> tuple[frozenset[str], frozenset[str]]:
    dados = load_json("logs_webshells.json")
    return frozenset(dados["distintivos"]), frozenset(dados["suspeitos"])


def sinal_shell(uri: str) -> SinalShell | None:
    """Reconhece um web shell pelo nome, pela pasta de uploads ou pelo parâmetro de comando."""
    uri = uri[:MAX_URI]
    if not _TALVEZ_SHELL.search(uri):
        return None
    partes = analisar_uri(uri)
    nome = partes.caminho.rsplit("/", 1)[-1]
    distintivos, suspeitos = _nomes_shell()
    if nome in distintivos:
        return SinalShell(True, f"nome de web shell conhecido: {nome}")
    if nome in suspeitos:
        return SinalShell(False, f"nome comum de web shell: {nome}")
    if _UPLOAD_SCRIPT.search(partes.caminho) and _NOME_ALEATORIO.match(nome):
        return SinalShell(False, "script de nome aleatório dentro de pasta de uploads")
    if _SCRIPT.search(nome) and _PARAM_SHELL.search(partes.consulta):
        return SinalShell(False, "parâmetro de URL com comando do sistema")
    return None


def arquivo_sensivel(uri: str) -> bool:
    """A URL pede um arquivo que nunca deveria ser publicado (``.env``, ``.git/config``...)."""
    uri = uri[:MAX_URI]
    if not _TALVEZ_SENSIVEL.search(uri):
        return False
    return _ARQUIVO_SENSIVEL.match(analisar_uri(uri).caminho) is not None


@lru_cache(maxsize=1)
def _regex_scanners() -> re.Pattern[str]:
    agentes = load_json("logs_scanners.json")["agentes"]
    return re.compile("|".join(re.escape(agente.lower()) for agente in agentes))


@lru_cache(maxsize=1_024)
def identificar_scanner(agente: str) -> str:
    """Nome da ferramenta de varredura no User-Agent (vazio quando não há)."""
    if not agente or agente == "-":
        return ""
    achado = _regex_scanners().search(agente[:MAX_CABECALHO].lower())
    return achado.group(0) if achado else ""
