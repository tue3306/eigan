"""Apoios compartilhados pelas checagens web.

Tudo o que mais de uma checagem usa é calculado UMA vez por auditoria com
``ctx.memo``: a página inicial (com os redirecionamentos dentro da mesma origem),
o HTML interpretado, a linha de base de "soft 404" de cada origem, o conteúdo de
cada script e as tecnologias reconhecidas. Assim as checagens rodam em paralelo
sem repetir requisições.

Linha de base de soft 404: muitos sites respondem 200 (ou redirecionam para a
home/login) para QUALQUER caminho. Antes de acreditar em uma sonda com
assinatura fraca, comparamos a resposta com a de um caminho aleatório do mesmo
"formato" (diretório, arquivo .php, arquivo oculto...). Se forem parecidas, a
sonda é descartada — falso positivo é defeito.

Robustez: o alvo pode responder qualquer coisa. Corpos são lidos com teto de
bytes, cabeçalhos ``Location`` malformados (porta inválida, IPv6 quebrado) ou com
bytes fora do ASCII não derrubam a checagem, um ``charset`` hostil (``undefined``,
``idna``) não impede a leitura do texto e hosts IPv6 viram URLs com colchetes
(``http://[::1]/``).
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import TypeVar
from urllib.parse import quote, urlsplit

from ...core.context import CheckContext
from ...core.facts import base_url, origin_of
from ...core.http import Response
from ...core.target import is_ip
from .htmlscan import HtmlDoc, parse_html
from .techdetect import TechHit, detect

T = TypeVar("T")
R = TypeVar("R")

REDIRECTS = frozenset({301, 302, 303, 307, 308})
TEXT_PROBE_BYTES = 65_536
BINARY_PROBE_BYTES = 1_024
SCRIPT_MAX_BYTES = 1_500_000
PAGE_MAX_BYTES = 2_000_000
LIVENESS_BYTES = 2_048
MAX_SAME_ORIGIN_HOPS = 5
#: ecos do caminho mais curtos que isso não são removidos (apagariam letras soltas)
_MIN_ECHO = 4
#: semelhança mínima de tamanho para o mesmo <title> contar como soft 404
_TITLE_LENGTH_RATIO = 0.75
#: tamanho parecido só conta como soft 404 se o conteúdo também for parecido: um ``.env``
#: pequeno e um "Not found" em text/plain têm quase o mesmo tamanho e nada em comum
_SIMILAR_RATIO = 0.9
_SIMILAR_SAMPLE = 8_192
#: caracteres que ``quote`` mantém: a URL já vem montada (só escapa o que não pode ir na rede)
_URL_SAFE = "%/:=&?~#+!$,;'@()*[]"

#: prioridade das tecnologias na lista ``tech`` dos achados (servidor primeiro)
_KIND_ORDER = {"server": 0, "language": 1, "framework": 1, "cms": 2, "cdn": 3, "waf": 3}
#: tecnologias equivalentes para escolher o exemplo de correção
_ALIASES: dict[str, tuple[str, ...]] = {
    "openresty": ("nginx",),
    "tengine": ("nginx",),
    "kestrel": ("aspnet",),
    "aspnet-mvc": ("aspnet",),
    "asp": ("iis",),
    "werkzeug": ("flask",),
    "laravel": ("php",),
    "codeigniter": ("php",),
    "wordpress": ("php",),
    "joomla": ("php",),
    "drupal": ("php",),
    "symfony": ("php",),
    "spring-boot": ("spring",),
}


# -- URLs seguras ------------------------------------------------------------------------


def safe_location(resp: Response) -> str | None:
    """Destino absoluto e enviável do ``Location`` (``None`` se ausente ou malformado)."""
    try:
        target = resp.location
    except ValueError:  # ex.: "http://[::1" ou porta não numérica
        return None
    if target is None:
        return None
    # O http.client decodifica cabeçalhos como latin-1: isso devolve os bytes originais.
    return quote(target, safe=_URL_SAFE, encoding="latin-1", errors="replace")


def safe_origin(url: str) -> str | None:
    """Origem normalizada da URL (``None`` se a URL for inválida)."""
    try:
        return origin_of(url)
    except ValueError:
        return None


def same_origin(url: str, origin: str) -> bool:
    return safe_origin(url) == origin


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def probe_url(origin: str, path: str) -> str:
    return origin.rstrip("/") + path


def readable(resp: Response) -> Response:
    """Garante que ``resp.text`` não levante exceção (``charset=undefined``, ``idna``, NUL)."""
    try:
        _ = resp.text
    except ValueError:  # UnicodeError é subclasse: o núcleo só trata LookupError
        resp._text = resp.body.decode("utf-8", errors="replace")
    return resp


def safe_get(ctx: CheckContext, url: str, max_bytes: int) -> Response | None:
    """GET que nunca levanta exceção por causa do endereço (bytes fora do ASCII, porta inválida)."""
    try:
        resp = ctx.http.get(url, max_bytes=max_bytes)
    except ValueError:  # UnicodeEncodeError no caminho ou "Port out of range"
        return None
    return readable(resp) if resp is not None else None


# -- página inicial ------------------------------------------------------------------


@dataclass
class Page:
    """A página do fato: respostas dentro da mesma origem até a final."""

    url: str
    origin: str
    host: str
    chain: list[Response]
    left_to: str | None = None  # destino de um redirecionamento para FORA da origem

    @property
    def first(self) -> Response:
        return self.chain[0]

    @property
    def final(self) -> Response:
        return self.chain[-1]

    @property
    def https(self) -> bool:
        return self.origin.startswith("https://")

    @property
    def is_redirect(self) -> bool:
        return self.final.status in REDIRECTS

    @property
    def html(self) -> bool:
        return not self.is_redirect and self.final.is_html

    @property
    def ok(self) -> bool:
        """A resposta final é de sucesso (2xx)?"""
        return 200 <= self.final.status < 300


def load_page(ctx: CheckContext, url: str) -> Page | None:
    """GET da URL seguindo redirecionamentos só dentro da mesma origem (memorizado)."""
    return ctx.memo(f"web.page:{url}", lambda: _fetch_page(ctx, url))


def _page_limit(ctx: CheckContext) -> int:
    return max(1, min(PAGE_MAX_BYTES, ctx.settings.http_max_bytes))


def _fetch_page(ctx: CheckContext, url: str) -> Page | None:
    origin = safe_origin(url)
    host = host_of(url)
    if origin is None or not host:
        return None
    limit = _page_limit(ctx)
    first = safe_get(ctx, url, limit)
    if first is None:
        return None
    chain = [first]
    left_to: str | None = None
    for _ in range(MAX_SAME_ORIGIN_HOPS):
        current = chain[-1]
        target = safe_location(current) if current.status in REDIRECTS else None
        if not target:
            break
        if safe_origin(target) != origin:
            left_to = target
            break
        if any(resp.url == target for resp in chain):
            break  # laço de redirecionamento
        ctx.check_cancel()
        follow = safe_get(ctx, target, limit)
        if follow is None:
            break
        chain.append(follow)
    return Page(url, origin, host, chain, left_to)


def page_doc(ctx: CheckContext, page: Page) -> HtmlDoc | None:
    """HTML interpretado da resposta final (``None`` se não for HTML)."""
    if not page.html:
        return None
    final = page.final
    return ctx.memo(f"web.doc:{final.url}", lambda: parse_html(final.text, final.url))


def skip_reason(ctx: CheckContext, page: Page) -> str | None:
    """Motivo para NÃO avaliar o conteúdo desta página (ou ``None``)."""
    if page.is_redirect:
        destino = page.left_to or safe_location(page.final) or "outro endereço"
        return f"{page.url} redireciona para {destino}; a avaliação segue no destino"
    if has_https_counterpart(ctx, page):
        return f"{page.url} também responde em HTTPS; cabeçalhos e conteúdo são avaliados lá"
    return None


def https_counterpart_url(page: Page) -> str:
    """A versão HTTPS (porta 443) do host da página."""
    return base_url("https", page.host, 443)


def has_https_counterpart(ctx: CheckContext, page: Page) -> bool:
    """Fato http:// na porta 80 cujo host também responde em HTTPS (porta 443)."""
    try:
        parts = urlsplit(page.url)
        port = parts.port or 80
    except ValueError:
        return False
    if parts.scheme != "http" or port != 80:
        return False
    https_url = https_counterpart_url(page)
    return ctx.memo(
        f"web.https_ok:{page.host}",
        lambda: safe_get(ctx, https_url, LIVENESS_BYTES) is not None,
    )


# -- tecnologias -----------------------------------------------------------------------


def detected_techs(ctx: CheckContext, page: Page) -> list[TechHit]:
    """Tecnologias reconhecidas nas respostas da página (memorizado)."""

    def compute() -> list[TechHit]:
        doc = page_doc(ctx, page)
        text = page.final.text if doc is not None else ""
        return detect(page.chain, doc, text)

    return ctx.memo(f"web.techs:{page.url}", compute)


def hints(ctx: CheckContext, page: Page) -> list[str]:
    """Nomes para ``ctx.report(tech=...)``: servidor, linguagem/framework, CMS, CDN."""
    hits = sorted(detected_techs(ctx, page), key=lambda h: _KIND_ORDER.get(h.kind, 4))
    return with_aliases([h.name for h in hits] + ctx.techs(page.host))


def with_aliases(names: Iterable[str]) -> list[str]:
    """Acrescenta os equivalentes usados nos exemplos de correção (openresty -> nginx...)."""
    out: list[str] = []
    for name in names:
        for item in (name, *_ALIASES.get(name, ())):
            if item not in out:
                out.append(item)
    return out


# -- linha de base de soft 404 ---------------------------------------------------------

_DIGITS = re.compile(rb"\d+")
#: identificadores aleatórios (tokens CSRF, ids de requisição, nonces)
_TOKENS = re.compile(rb"[A-Za-z0-9+/=_\-]{24,}")


@dataclass(frozen=True)
class Baseline:
    """Como a origem responde a um caminho que certamente não existe."""

    path: str
    status: int
    length: int
    digest: str
    location: str | None
    content_type: str
    text: str = field(repr=False, default="")
    title: str = ""
    body: bytes = field(repr=False, default=b"")  # corpo normalizado
    truncated: bool = False


def shape_of(path: str) -> str:
    """Formato do caminho: ``dir``, ``dot`` (oculto), ``ext:php``... ou ``plain``."""
    if path.endswith("/"):
        return "dir"
    name = path.rsplit("/", 1)[-1]
    if name.startswith("."):
        return "dot"
    if "." in name:
        return "ext:" + name.rsplit(".", 1)[-1].lower()[:10]
    return "plain"


def random_path(shape: str) -> str:
    token = "eigan-" + secrets.token_hex(6)
    if shape == "dir":
        return f"/{token}/"
    if shape == "dot":
        return f"/.{token}"
    if shape.startswith("ext:"):
        return f"/{token}.{shape[4:]}"
    return f"/{token}"


def _echoes(path: str) -> list[str]:
    """Formas como uma página pode repetir o caminho pedido (as longas primeiro)."""
    variants = {path, quote(path, safe=""), quote(path), path.lstrip("/"), path.strip("/")}
    return sorted((v for v in variants if len(v) >= _MIN_ECHO), key=len, reverse=True)


def _normalized(body: bytes, path: str) -> bytes:
    """Corpo sem os ecos do caminho e sem números/tokens que mudam a cada resposta."""
    out = body
    for variant in _echoes(path):
        out = out.replace(variant.encode("utf-8", "ignore"), b"")
    out = _TOKENS.sub(b"T", out)
    return _DIGITS.sub(b"0", out)


def _digest(body: bytes) -> str:
    return hashlib.blake2b(body, digest_size=16).hexdigest()


def _strip_location(location: str | None, path: str) -> str | None:
    if not location:
        return None
    for variant in _echoes(path):
        location = location.replace(variant, "")
    return location


def _title_of(text: str, path: str) -> str:
    # Sem regex: "<title>" repetido milhares de vezes deixaria a busca quadrática.
    sample = text[:TEXT_PROBE_BYTES]
    lowered = sample.lower()
    start = lowered.find("<title")
    begin = lowered.find(">", start) + 1 if start >= 0 else 0
    end = lowered.find("</title", begin) if begin else -1
    if end < 0:
        return ""
    title = sample[begin:end]
    for variant in _echoes(path):
        title = title.replace(variant, "")
    return " ".join(title.split()).lower()


def _bodies_match(a: bytes, a_cut: bool, b: bytes, b_cut: bool) -> bool:
    """Corpos iguais — ou um é o começo do outro porque a leitura foi cortada no teto."""
    if a == b:
        return True
    margin = 64  # o fim de um corpo cortado pode ter sido normalizado de outro jeito
    if a_cut and len(a) <= len(b) and len(a) > margin:
        return b.startswith(a[:-margin])
    if b_cut and len(b) <= len(a) and len(b) > margin:
        return a.startswith(b[:-margin])
    return False


def _similar(a: bytes, b: bytes) -> bool:
    """Conteúdos parecidos? (só o começo: ``quick_ratio`` é barato, mas o corpo pode ser grande)"""
    matcher = SequenceMatcher(None, a[:_SIMILAR_SAMPLE], b[:_SIMILAR_SAMPLE], autojunk=False)
    return matcher.quick_ratio() >= _SIMILAR_RATIO


def as_baseline(resp: Response, path: str) -> Baseline:
    readable(resp)
    body = _normalized(resp.body, path)
    return Baseline(
        path=path,
        status=resp.status,
        length=len(body),
        digest=_digest(body),
        location=_strip_location(safe_location(resp), path),
        content_type=resp.content_type,
        text=resp.text[:TEXT_PROBE_BYTES],
        title=_title_of(resp.text, path),
        body=body,
        truncated=resp.truncated,
    )


def baseline(ctx: CheckContext, origin: str, shape: str = "plain") -> Baseline | None:
    """Resposta da origem para um caminho aleatório do formato pedido.

    Calculada UMA vez por origem e formato na auditoria inteira (``ctx.memo``).
    """

    def measure() -> Baseline | None:
        path = random_path(shape)
        resp = safe_get(ctx, probe_url(origin, path), TEXT_PROBE_BYTES)
        return as_baseline(resp, path) if resp is not None else None

    return ctx.memo(f"web.soft404:{origin}:{shape}", measure)


def looks_like(resp: Response, base: Baseline | None, path: str) -> bool:
    """A resposta é (quase) a mesma da linha de base?"""
    if base is None or resp.status != base.status:
        return False
    if resp.status in REDIRECTS:
        return _strip_location(safe_location(resp), path) == base.location
    body = _normalized(resp.body, path)
    if _digest(body) == base.digest or _bodies_match(
        body, resp.truncated, base.body, base.truncated
    ):
        return True
    if resp.content_type != base.content_type:
        return False
    longest = max(len(body), base.length, 1)
    title = _title_of(readable(resp).text, path) if base.title else ""
    if (
        title
        and title == base.title
        and min(len(body), base.length) / longest >= _TITLE_LENGTH_RATIO
    ):
        return True  # mesmo modelo de página com conteúdo dinâmico
    tolerance = max(64, int(base.length * 0.08))
    return abs(len(body) - base.length) <= tolerance and _similar(body, base.body)


def _home_sample(ctx: CheckContext, page: Page) -> tuple[bytes, bool]:
    """Começo normalizado do corpo da página inicial (memorizado) e se ele foi cortado."""
    home = page.final
    limit = 2 * TEXT_PROBE_BYTES

    def compute() -> tuple[bytes, bool]:
        cut = home.truncated or len(home.body) > limit
        return _normalized(home.body[:limit], "/"), cut

    return ctx.memo(f"web.home_sample:{home.url}", compute)


def is_soft404(ctx: CheckContext, page: Page, path: str, resp: Response) -> bool:
    """A resposta da sonda é só a página genérica do site (soft 404 ou a própria home)?"""
    if looks_like(resp, baseline(ctx, page.origin, shape_of(path)), path):
        return True
    if page.final.status != resp.status or page.is_redirect:
        return False
    home_body, home_cut = _home_sample(ctx, page)
    return _bodies_match(_normalized(resp.body, path), resp.truncated, home_body, home_cut)


# -- sondas e scripts ------------------------------------------------------------------


def fetch_script(ctx: CheckContext, url: str) -> Response | None:
    """Conteúdo de um script (memorizado; ``None`` se não for JavaScript)."""

    def get() -> Response | None:
        # O endereço vem do HTML (já é texto, não latin-1) e pode ter acentos ou espaços.
        resp = safe_get(ctx, quote(url, safe=_URL_SAFE, errors="replace"), SCRIPT_MAX_BYTES)
        if resp is None or resp.status != 200 or resp.is_html:
            return None
        return resp

    return ctx.memo(f"web.script:{url}", get)


def run_parallel(
    ctx: CheckContext, items: Sequence[T], func: Callable[[T], R | None], workers: int = 4
) -> list[R]:
    """Aplica ``func`` em paralelo (poucas conexões) e devolve os resultados não nulos.

    Os trabalhadores só buscam e avaliam; quem reporta é a thread da checagem.
    """
    size = max(1, min(workers, ctx.settings.http_per_host, len(items)))
    results: list[R | None]
    if size == 1:
        results = []
        for item in items:
            ctx.check_cancel()
            results.append(func(item))
        return [r for r in results if r is not None]

    def task(item: T) -> R | None:
        return None if ctx.cancelled else func(item)

    with ThreadPoolExecutor(max_workers=size, thread_name_prefix="eigan-web") as pool:
        results = list(pool.map(task, items))
    ctx.check_cancel()
    return [r for r in results if r is not None]


def claim(ctx: CheckContext, key: str) -> bool:
    """``True`` só para a primeira checagem que pedir esta chave na auditoria."""
    token = object()
    return ctx.memo(key, lambda: token) is token


def profile_level(ctx: CheckContext) -> int:
    """0 = rápido, 1 = padrão, 2 = completo."""
    if ctx.settings.quick:
        return 0
    return 2 if ctx.settings.deep else 1


# -- domínios --------------------------------------------------------------------------

#: segundo nível comum em domínios de país (exemplo.com.br, exemplo.co.uk)
_SECOND_LEVEL_GENERIC = frozenset(
    {"com", "net", "org", "gov", "edu", "co", "ac", "mil", "nom", "art", "blog", "eco",
     "ind", "inf", "rec", "srv", "tmp", "tv", "app", "dev", "log", "wiki", "or", "ne",
     "go", "gob", "gv", "ltd", "plc", "sch"}
)  # fmt: skip
#: categorias de registro sob .br (adv.br, eti.br, jus.br...): regras de duas etiquetas da
#: Public Suffix List (https://publicsuffix.org/list/public_suffix_list.dat, MPL-2.0), 2026-11
_BR_CATEGORIES = frozenset(
    {
    "9guacu", "abc", "adm", "adv", "agr", "aju", "am", "anani", "aparecida", "api",
    "app", "arq", "art", "ato", "b", "barueri", "belem", "bet", "bhz", "bib", "bio",
    "blog", "bmd", "boavista", "bsb", "campinagrande", "campinas", "caxias", "cim",
    "cng", "cnt", "com", "contagem", "coop", "coz", "cri", "cuiaba", "curitiba", "def",
    "des", "det", "dev", "ecn", "eco", "edu", "emp", "enf", "eng", "esp", "etc", "eti",
    "far", "feira", "flog", "floripa", "fm", "fnd", "fortal", "fot", "foz", "fst",
    "g12", "geo", "ggf", "goiania", "gov", "gru", "ia", "imb", "ind", "inf", "jab",
    "jampa", "jdf", "joinville", "jor", "jus", "leg", "leilao", "lel", "log",
    "londrina", "macapa", "maceio", "manaus", "maringa", "mat", "med", "mil", "morena",
    "mp", "mus", "natal", "net", "niteroi", "not", "ntr", "odo", "ong", "org", "osasco",
    "palmas", "poa", "ppg", "pro", "psc", "psi", "pvh", "qsl", "radio", "rec", "recife",
    "rep", "ribeirao", "rio", "riobranco", "riopreto", "salvador", "sampa",
    "santamaria", "santoandre", "saobernardo", "saogonca", "seg", "sjc", "slg", "slz",
    "social", "sorocaba", "srv", "taxi", "tc", "tec", "teo", "the", "tmp", "trd", "tur",
    "tv", "udi", "vet", "vix", "vlog", "wiki", "xyz", "zlg",
    }
)  # fmt: skip
_SECOND_LEVEL = _SECOND_LEVEL_GENERIC | _BR_CATEGORIES


def site_of(host: str) -> str:
    """Domínio "registrável" aproximado (sem lista de sufixos públicos)."""
    host = host.lower().strip(".").strip("[]")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2:
        known = _BR_CATEGORIES if labels[-1] == "br" else _SECOND_LEVEL_GENERIC
        if labels[-2] in known:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_HTML_START = re.compile(r"<(?:!doctype|html|head|body|title|h1|div|p|meta|script|style)\b", re.I)


def looks_html(text: str) -> bool:
    """O texto começa como um documento HTML (página de erro, soft 404)?

    Os comentários são pulados em um laço: em uma regex, repetir ``<!---->`` faz o tempo
    dobrar a cada comentário, e o texto vem do alvo.
    """
    head = text[:2048].lstrip()
    while head.startswith("<!--"):
        end = head.find("-->", 4)
        if end < 0:
            return False
        head = head[end + 3 :].lstrip()
    return bool(_HTML_START.match(head))


def short(text: str, limit: int = 200) -> str:
    """Trecho para evidência: o valor de um cabeçalho vem do alvo e pode ter 64 KiB."""
    return text if len(text) <= limit else f"{text[:limit]}…"
