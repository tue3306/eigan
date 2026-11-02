"""Leitura de JavaScript da mesma origem: token em ``localStorage`` e credencial literal.

Duas buscas que só um olho humano costumava fazer: a aplicação guarda o token de sessão em
``localStorage``/``sessionStorage`` (legível por qualquer script injetado) ou traz um par
usuário/senha escrito no próprio código. As duas são heurísticas: o filtro prefere perder um
caso a acusar rótulo de formulário, tradução ou nome de campo. Valores nunca saem inteiros.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass

#: o texto só é varrido se tiver alguma destas palavras (evita custo em bundles grandes)
_STORAGE_WORDS = ("localstorage", "sessionstorage")
_CRED_WORDS = ("senha", "password", "passwd", "pwd", "passphrase", "pass")
MAX_PER_SOURCE = 5

# -- token em localStorage / sessionStorage -------------------------------------------------

_TOKEN_KEY = re.compile(r"token|jwt|sess(?:ion|ao|ão)|auth(?!or)|bearer|sid$", re.I)
#: chaves de preferência: nunca são identificador de sessão
_NOT_TOKEN_KEY = re.compile(
    r"theme|dark|lang|locale|idioma|i18n|cart|carrinho|consent|consentimento|cookie|"
    r"preferen|banner|dismiss|tour|onboard|sidebar|csrf|xsrf|tokenizer|font|layout|"
    r"page_?token|next_?page",
    re.I,
)
#: palavras inteiras de preferência (``tema`` não pode casar dentro de ``sistema``)
_NOT_TOKEN_WORDS = frozenset({"tema"})
#: o valor guardado é token de CSRF ou de paginação, não de sessão
_NOT_TOKEN_VALUE = re.compile(r"csrf|xsrf|next_?page|page_?token", re.I)
_STORE_REF = r"(?<![\w$])(?P<store>local|session)Storage\s*"
_SET_ITEM_TAIL = (
    r"\.\s*setItem\s*\(\s*(?:(?P<q>[\"'`])(?P<lit>[^\"'`\n]{1,80})(?P=q)|"
    r"(?P<var>[A-Za-z_$][\w$.]{0,60}))\s*,\s*(?P<value>[^)\n]{0,80})"
)
_ASSIGN_TAIL = (
    r"(?:\[\s*(?P<q>[\"'`])(?P<lit>[^\"'`\n]{1,80})(?P=q)\s*\]|"
    r"\.(?P<prop>[A-Za-z_$][\w$]{0,60}))\s*=(?!=)\s*(?P<value>[^;\n]{0,80})"
)
#: ``localStorage.setItem("chave", valor)`` e ``localStorage.setItem(CHAVE, valor)``
_SET_ITEM = re.compile(_STORE_REF + _SET_ITEM_TAIL)
#: ``localStorage["chave"] = x`` e ``localStorage.chave = x``
_ASSIGN = re.compile(_STORE_REF + _ASSIGN_TAIL)
#: ``const s = window.localStorage``: o apelido passa a valer como o próprio storage
_ALIAS = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:(?:window|self|globalThis|top)\s*\.\s*)?(?P<store>local|session)Storage(?![\w$.\[(])"
)
_CONST_STR = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*[\"'`](?P<lit>[^\"'`\n]{1,80})[\"'`]"
)
_TOKEN_VALUE = re.compile(r"[\w$.]*(?:token|jwt)[\w$.]*", re.I)
_EMPTY_VALUE = re.compile(r"^\s*(?:[\"'`]{2}|null|undefined|void 0|!1|0)\s*$")
#: bandeira ou data (``"1"``, ``true``, ``Date.now()``): nunca é credencial
_FLAG_VALUE = re.compile(
    r"^\s*(?:[\"'`]?(?:\d{1,13}|true|false|yes|no)[\"'`]?\s*|\+?\s*(?:Date\.now|new\s+Date|"
    r"performance\.now)\b.*)$",
    re.I,
)
#: textos entre aspas e comentários (estes viram espaços, mantendo as posições)
_LEXEME = re.compile(
    r"(?P<str>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)"
    r"|(?P<com>//[^\n]*|/\*.*?\*/)",
    re.S,
)
_CONST_MIN_NAME = 3  # ``var e="token"`` em bundle minificado não vale para outro escopo
_MAX_ALIASES = 5


@dataclass(frozen=True)
class StoredToken:
    storage: str  # localStorage | sessionStorage
    key: str  # nome da chave (ou da variável que a guarda)
    value_kind: str  # "variável" | "literal"


def clean_key(key: str) -> str:
    """Tira caracteres de controle (ESC, BEL...) de um nome que veio do alvo."""
    return "".join(c if c.isprintable() else " " for c in key).strip()


def _preference_key(key: str) -> bool:
    return bool(_NOT_TOKEN_KEY.search(key)) or any(
        w.lower() in _NOT_TOKEN_WORDS for w in _WORD.findall(key)
    )


def _token_key(key: str) -> bool:
    return bool(_TOKEN_KEY.search(key)) and not _preference_key(key)


def _scrub(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Texto sem comentários (mesmas posições) e os trechos que são texto entre aspas."""
    spans: list[tuple[int, int]] = []
    out: list[str] = []
    last = 0
    for m in _LEXEME.finditer(text):
        if m["str"] is not None:
            spans.append(m.span())
            continue
        out.append(text[last : m.start()])
        out.append("".join(c if c == "\n" else " " for c in m[0]))
        last = m.end()
    out.append(text[last:])
    return "".join(out), spans


def find_stored_tokens(text: str) -> list[StoredToken]:
    """Gravações de algo parecido com token de sessão em ``localStorage``/``sessionStorage``."""
    low = text.lower()
    if not any(w in low for w in _STORAGE_WORDS):
        return []
    text, spans = _scrub(text)
    starts = [a for a, _ in spans]

    def in_string(pos: int) -> bool:
        i = bisect.bisect_right(starts, pos) - 1
        return i >= 0 and pos < spans[i][1]

    consts = {
        m["name"]: m["lit"] for m in _CONST_STR.finditer(text) if len(m["name"]) >= _CONST_MIN_NAME
    }
    found: dict[tuple[str, str], StoredToken] = {}

    def add(store: str, key: str, value: str) -> None:
        if _EMPTY_VALUE.match(value) or _FLAG_VALUE.match(value) or (store, key) in found:
            return
        kind = "literal" if value.strip()[:1] in "\"'`" else "variável"
        found[(store, key)] = StoredToken(f"{store}Storage", key, kind)

    # (``localStorage`` e apelidos) -> padrões; o apelido troca só o início da expressão
    refs: list[tuple[re.Pattern[str], re.Pattern[str], str | None]] = [(_SET_ITEM, _ASSIGN, None)]
    aliases = {m["name"]: m["store"] for m in _ALIAS.finditer(text)}
    for name, store in list(aliases.items())[:_MAX_ALIASES]:
        ref = rf"(?<![\w$.])(?:{re.escape(name)})\s*"
        refs.append((re.compile(ref + _SET_ITEM_TAIL), re.compile(ref + _ASSIGN_TAIL), store))
    for set_item, assign, alias_store in refs:
        for m in set_item.finditer(text):
            if in_string(m.start()):
                continue
            store = alias_store or m["store"]
            key = clean_key(m["lit"] or consts.get(m["var"].split(".")[-1], m["var"]))
            if not key or _preference_key(key):
                continue
            value = m["value"]
            # a chave pode ter outro nome e o valor ser a variável do token (``setItem("u", token)``)
            by_value = _TOKEN_VALUE.fullmatch(value.strip()) and not _NOT_TOKEN_VALUE.search(value)
            if _token_key(key) or by_value:
                add(store, key, value)
        for m in assign.finditer(text):
            if in_string(m.start()):
                continue
            key = clean_key(m["lit"] or m["prop"])
            if _token_key(key):
                add(alias_store or m["store"], key, m["value"])
    return list(found.values())[:MAX_PER_SOURCE]


# -- credencial literal ---------------------------------------------------------------------

#: a palavra do campo; ``pass`` só como palavra (``bypass`` e ``passed`` ficam de fora)
_CRED_WORD = (
    r"senha|password|passwd|pwd|passphrase|"
    r"(?-i:(?:(?<![A-Za-z])[Pp]ass|(?<=[a-z])Pass)(?![a-z]))"
)
#: do fim do nome do campo ao literal: ``:``, ``=``, ``==``, ``!=`` (e ``.value`` antes do operador).
#: A parte final do nome é possessiva: sem retrocesso, o custo no texto do alvo fica linear.
_CRED = re.compile(
    rf"(?P<word>{_CRED_WORD})(?P<rest>[\w$]{{0,30}}+)[\"']?\s*[\])]?\s*"
    r"(?:\.\s*(?:value|val\s*\(\s*\))\s*)?"
    r"(?:(?<![<>])={1,3}(?!=)|!==?(?!=)|:(?!=))\s*"
    r"(?P<q>[\"'])(?P<val>[^\"'\\\n]{3,64})(?P=q)",
    re.I,
)
#: o literal vem antes: ``"admin123" === senha`` (o nome do campo vem logo depois)
_CRED_REVERSED = re.compile(
    rf"([\"'])(?P<val>[^\"'\\\n]{{3,64}})\1\s*(?:={{2,3}}|!==?)\s*(?P<path>[\w$.(\"']{{0,60}}?)"
    rf"(?P<word>{_CRED_WORD})(?P<rest>[\w$]{{0,30}}+)",
    re.I,
)
#: depois do literal, estes sinais mostram que ele é parte de uma expressão maior
_CRED_CONTINUES = re.compile(r"\s*(?:[+.?(\[]|in\b)")
_KEY_LEFT = re.compile(r"[\w$]{0,30}\Z")
_TAIL_IDENT = re.compile(r"[\w$]*\Z")
_USER = re.compile(
    r"(?<![\w$])[\"']?(?:usuario|usuário|user|username|login|email|e-mail|cpf)[\"']?\s*"
    r"(?::|={1,3})(?!=)\s*(?P<q>[\"'])(?P<val>[^\"'\\\n]{2,64})(?P=q)",
    re.I,
)
#: partes do nome do campo que indicam texto de tela, validação ou configuração, não valor
_LABEL_PREFIX_TEXT = (
    "label placeholder title titulo text msg message mensagem hint dica error erro required "
    "obrigat invalid inval confirm forgot esquec reset redefin recover recuper change alter "
    "trocar show hide mostrar ocultar exibir strength forca rule regra policy politica min max "
    "length tamanho type tipo field campo input class selector seletor autocomplete match "
    "mismatch differ diferen wrong incorrect incorret expired expir toggle visible icon tooltip "
    "aria help ajuda desc caption legend button botao btn link route rota url path endpoint "
    "header regex pattern validator name nome param prop ref"
)
_LABEL_PREFIXES = tuple(_LABEL_PREFIX_TEXT.split())
_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def _label_key(key: str) -> bool:
    """O nome do campo fala de tela, validação ou configuração (``passwordLabel``)?"""
    words = [w.lower() for w in _WORD.findall(key)]
    return any(w == "id" or w.startswith(_LABEL_PREFIXES) for w in words)


#: palavras que são rótulo em vários idiomas (comparadas sem acento e sem pontuação)
_LABEL_WORDS = frozenset(
    {
        "senha",
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "passwort",
        "kennwort",
        "contrasena",
        "clave",
        "motdepasse",
        "palavrapasse",
        "wachtwoord",
        "lozinka",
        "haslo",
        "parola",
        "heslo",
        "salasana",
        "losenord",
        "parool",
        "none",
        "null",
        "undefined",
        "true",
        "false",
        "todo",
        "tbd",
        "secret",
        "hidden",
        "text",
        "string",
        "required",
    }
)
_PLACEHOLDER_VALUE = re.compile(
    r"^(?:[*•·●x#.\-_]{3,}|your|seu|sua|<.*>|\{.*\}|%[sd]|\$\{|\{\{)|[*…]$|\.\.\.|"
    r"^(?:your|seu|sua|my|minha|enter|digite|informe|insira|type)[-_ ]",
    re.I,
)
#: chaves de tradução (``auth.password.label``), nomes de CSS/campo em kebab ou snake case
_IDENTIFIER_VALUE = re.compile(r"^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+){1,}$")


@dataclass(frozen=True)
class LiteralCredential:
    key: str
    value: str  # completo; nunca exibir (use ``mask``)
    paired: bool  # há um usuário literal ao lado (par usuário/senha)


def _normalize(text: str) -> str:
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", plain.lower())


def _is_credential_value(key: str, value: str) -> bool:
    """O texto entre aspas é uma senha de verdade, e não rótulo, tradução ou nome de campo?"""
    if any(c.isspace() or not c.isprintable() for c in value):  # frase de tela ou mensagem
        return False
    if "|" in value:  # regra de validação (``required|min:8``)
        return False
    if value[0] in "#.[/<{$%@" or value.startswith(("http", "data:")):
        return False
    if _PLACEHOLDER_VALUE.search(value) or _IDENTIFIER_VALUE.match(value):
        return False
    norm = _normalize(value)
    if not norm or norm in _LABEL_WORDS or norm == _normalize(key):
        return False
    if len(set(value)) == 1:
        return False
    # nome de campo ou método em camelCase sem dígitos (``currentPassword``, ``checkSenha``)
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z]+)+", value) and not any(c.isdigit() for c in value):
        return False
    return True


def _consider(
    text: str,
    start: int,
    end: int,
    key: str,
    value: str,
    found: dict[tuple[str, str], LiteralCredential],
) -> None:
    if _label_key(key) or not _is_credential_value(key, value) or (key.lower(), value) in found:
        return
    window = text[max(0, start - 160) : end + 160]
    user = next(
        (u for u in _USER.finditer(window) if _is_credential_value("usuario", u["val"])),
        None,
    )
    found[(key.lower(), value)] = LiteralCredential(key, value, user is not None)


def find_literal_credentials(text: str) -> list[LiteralCredential]:
    """Senhas escritas no código (``senha:"teste"``, ``password = "abc123"``), já filtradas."""
    low = text.lower()
    if not any(w in low for w in _CRED_WORDS):
        return []
    found: dict[tuple[str, str], LiteralCredential] = {}
    for m in _CRED.finditer(text):
        if _CRED_CONTINUES.match(text, m.end()):  # ``"abc" + sal``, ``"x" in obj``
            continue
        left = _KEY_LEFT.search(text, max(0, m.start() - 30), m.start())
        key = clean_key((left[0] if left else "") + m["word"] + m["rest"])
        _consider(text, m.start(), m.end(), key, m["val"], found)
        if len(found) >= MAX_PER_SOURCE:
            return list(found.values())
    for m in _CRED_REVERSED.finditer(text):
        left = _TAIL_IDENT.search(m["path"])
        key = clean_key((left[0] if left else "") + m["word"] + m["rest"])
        _consider(text, m.start(), m.end(), key, m["val"], found)
        if len(found) >= MAX_PER_SOURCE:
            break
    return list(found.values())
