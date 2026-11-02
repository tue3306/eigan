"""Leitura e avaliação da Content-Security-Policy (CSP nível 3).

As regras seguem a especificação do W3C e o CSP Evaluator do Google
(https://csp-evaluator.withgoogle.com/):

- ``'unsafe-inline'`` é ignorado quando a lista tem nonce, hash ou
  ``'strict-dynamic'`` — só pesa sem eles;
- ``'strict-dynamic'`` faz o navegador ignorar origens (``https:``, domínios)
  e ``'self'`` na hora de carregar scripts;
- ``script-src-elem``/``script-src-attr`` caem para ``script-src`` e depois para
  ``default-src``; ``object-src`` cai para ``default-src``; ``base-uri`` e
  ``frame-ancestors`` não herdam nada;
- sem ``base-uri``, uma tag ``<base>`` injetada muda o destino de links e formulários
  relativos; em políticas com nonce ela desvia também os scripts (anula a proteção);
- várias políticas valem ao mesmo tempo: um script só roda se TODAS permitirem,
  então basta uma política forte;
- ``frame-ancestors`` não vale em ``<meta>``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: cadeia de herança de cada diretiva (a primeira que existir vale)
FALLBACKS: dict[str, tuple[str, ...]] = {
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "object-src": ("object-src", "default-src"),
}
#: origens que aceitam qualquer site (por esquema ou curinga) — ``data:`` deixa o próprio
#: atacante escrever o script na URL
BROAD_SOURCES = frozenset({"*", "http:", "https:", "data:", "http://*", "https://*"})
#: curingas sobre domínios em que qualquer cliente da plataforma hospeda arquivos próprios
_PUBLIC_WILDCARD = re.compile(
    r"^(?:https?://)?\*\.(?:cloudfront\.net|amazonaws\.com|herokuapp\.com|azurewebsites\.net|"
    r"appspot\.com|github\.io|firebaseapp\.com|web\.app|netlify\.app|vercel\.app|"
    r"pages\.dev|workers\.dev)(?::\d+|:\*)?(?:/.*)?$",
    re.I,
)
_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


@dataclass
class Policy:
    directives: dict[str, list[str]]
    source: str  # "cabeçalho" | "meta"
    raw: str

    def sources(self, name: str) -> list[str] | None:
        return self.directives.get(name)

    def effective(self, name: str) -> list[str] | None:
        """Lista que realmente vale para a diretiva, seguindo a herança da CSP3."""
        for candidate in FALLBACKS.get(name, (name,)):
            found = self.directives.get(candidate)
            if found is not None:
                return found
        return None

    def script_lists(self) -> list[list[str]]:
        """Listas distintas que valem para ``<script>`` e para atributos (onclick...)."""
        lists: list[list[str]] = []
        for name in ("script-src-elem", "script-src-attr"):
            found = self.effective(name)
            if found is not None and found not in lists:
                lists.append(found)
        return lists


@dataclass(frozen=True)
class Issue:
    code: str
    text: str
    grave: bool = False  # anula a proteção contra XSS


def _normalize_source(token: str) -> str:
    """Palavras-chave e esquemas não diferenciam maiúsculas; nonces e hashes sim."""
    lowered = token.lower()
    if lowered.startswith(_NONCE_OR_HASH):
        return lowered[: lowered.index("-") + 1] + token[lowered.index("-") + 1 :]
    if token.startswith("'") or token.endswith(":") or "://" in token:
        return lowered
    return token


def parse_policy(text: str, source: str = "cabeçalho") -> Policy:
    directives: dict[str, list[str]] = {}
    for chunk in text.split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name not in directives:  # repetição é ignorada pelo navegador
            directives[name] = [_normalize_source(p) for p in parts[1:]]
    return Policy(directives, source, text.strip())


def parse_policies(values: list[str], source: str = "cabeçalho") -> list[Policy]:
    """Um cabeçalho pode trazer várias políticas separadas por vírgula."""
    policies: list[Policy] = []
    for value in values:
        for text in value.split(","):
            if text.strip():
                policies.append(parse_policy(text, source))
    return policies


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.lower().startswith(_NONCE_OR_HASH) for s in sources)


def _has_nonce(sources: list[str]) -> bool:
    return any(s.lower().startswith("'nonce-") for s in sources)


def is_broad(sources: list[str]) -> bool:
    """A lista aceita qualquer site (``*``, ``https:``, ``data:``...)?"""
    return any(s.lower() in BROAD_SOURCES for s in sources)


def _script_issues(sources: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    strict_dynamic = "'strict-dynamic'" in sources
    if "'unsafe-inline'" in sources and not _has_nonce_or_hash(sources) and not strict_dynamic:
        issues.append(
            Issue(
                "unsafe_inline",
                "'unsafe-inline' sem nonce/hash: scripts injetados na página são executados",
                grave=True,
            )
        )
    if "'unsafe-eval'" in sources:
        issues.append(Issue("unsafe_eval", "'unsafe-eval' permite eval() e funções semelhantes"))
    if not strict_dynamic:
        broad = list(dict.fromkeys(s for s in sources if s.lower() in BROAD_SOURCES))
        if broad:
            issues.append(
                Issue(
                    "origem_ampla",
                    f"script-src aceita qualquer origem ({', '.join(broad)}): basta hospedar o "
                    "script malicioso em outro site",
                    grave=True,
                )
            )
        shared = [s for s in sources if _PUBLIC_WILDCARD.match(s)]
        if shared:
            issues.append(
                Issue(
                    "host_publico",
                    "script-src libera todo um domínio de hospedagem pública "
                    f"({', '.join(shared[:3])}): qualquer cliente da plataforma publica scripts ali",
                )
            )
        plain = [s for s in sources if s.lower().startswith("http://") and s.lower() != "http://*"]
        if plain:
            issues.append(
                Issue(
                    "http", f"scripts liberados por HTTP sem criptografia ({', '.join(plain[:3])})"
                )
            )
    return issues


def _policy_script_issues(policy: Policy) -> list[Issue]:
    """Problemas de script de UMA política (``<script>`` e atributos de evento)."""
    found: list[Issue] = []
    for sources in policy.script_lists():
        for issue in _script_issues(sources):
            if all(issue.code != other.code for other in found):
                found.append(issue)
    return found


def _object_issue(policies: list[Policy]) -> Issue | None:
    lists = [p.effective("object-src") for p in policies]
    defined = [found for found in lists if found is not None]
    if not defined:
        return Issue(
            "sem_object_src", "sem object-src (nem default-src): plugins podem rodar código"
        )
    if all(is_broad(found) for found in defined):
        return Issue(
            "object_src_amplo", "object-src aceita qualquer origem: plugins podem rodar código"
        )
    return None


def _scripts_follow_base(policies: list[Policy]) -> bool:
    """Com nonce (ou hash + strict-dynamic) o script relativo é aceito em qualquer endereço."""
    for policy in policies:
        for sources in policy.script_lists():
            if _has_nonce(sources):
                return True
            if _has_nonce_or_hash(sources) and "'strict-dynamic'" in sources:
                return True
    return False


def _base_uri_issue(policies: list[Policy]) -> Issue | None:
    """``base-uri`` ausente (ou aberto a qualquer site) em todas as políticas."""
    lists = [p.sources("base-uri") for p in policies]
    if any(found is not None and not is_broad(found) for found in lists):
        return None
    if _scripts_follow_base(policies):
        return Issue(
            "sem_base_uri",
            "sem base-uri: uma tag <base> injetada faz os scripts relativos com nonce virem de "
            "outro site",
            grave=True,
        )
    return Issue(
        "sem_base_uri",
        "sem base-uri (o default-src não vale para ela): uma tag <base> injetada muda o destino "
        "de links e formulários relativos",
    )


def _weight(found: list[Issue]) -> tuple[int, int]:
    """Peso dos problemas de uma política: graves primeiro, depois a quantidade."""
    return sum(i.grave for i in found), len(found)


def evaluate(policies: list[Policy]) -> list[Issue]:
    """Problemas da combinação de políticas (o navegador aplica todas ao mesmo tempo)."""
    if not policies:
        return []
    issues: list[Issue] = []
    scripted = [p for p in policies if p.script_lists()]
    if not scripted:
        issues.append(
            Issue(
                "sem_script_src",
                "sem script-src nem default-src: a política não restringe scripts "
                "(as demais diretivas, como frame-ancestors, continuam valendo)",
            )
        )
    else:
        # Basta uma política forte: o navegador exige que TODAS permitam o script.
        candidates = [_policy_script_issues(p) for p in scripted]
        best: list[Issue] = min(candidates, key=_weight)
        issues.extend(best)
    object_issue = _object_issue(policies)
    if object_issue is not None:
        issues.append(object_issue)
    base_issue = _base_uri_issue(policies)
    if base_issue is not None:
        issues.append(base_issue)
    return issues


def frame_ancestor_lists(policies: list[Policy]) -> list[list[str]]:
    """Listas ``frame-ancestors`` das políticas de cabeçalho (em ``<meta>`` não valem)."""
    lists: list[list[str]] = []
    for policy in policies:
        found = policy.sources("frame-ancestors")
        if policy.source == "cabeçalho" and found is not None:
            lists.append(found)
    return lists
