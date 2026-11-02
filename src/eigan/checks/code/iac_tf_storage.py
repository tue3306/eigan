"""Regras de armazenamento público: AWS S3 (ACL e política), Azure Blob e Google Cloud Storage.

Segue a definição da própria AWS
(https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html):
ACL é pública se concede algo a ``AllUsers`` ou ``AuthenticatedUsers``; política é pública
salvo se limitar o acesso a valores fixos de certas condições. O bloqueio de acesso público
do próprio bucket (em qualquer arquivo do módulo) anula a ACL ou a política pública.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ...core.models import Confidence, Severity
from .iac_common import BUCKET_PUBLIC
from .iac_hcl import Block, Call, Ref
from .iac_tf_model import Module, Resource, TfRun, as_bool, as_text

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
#: ACL pronta -> (quem ganha acesso, inclui escrita)
_CANNED_ACLS: dict[str, tuple[str, bool]] = {
    "public-read": ("qualquer pessoa na Internet pode ler", False),
    "public-read-write": ("qualquer pessoa na Internet pode ler e gravar", True),
    "authenticated-read": ("qualquer conta da AWS pode ler", False),
}
_GROUPS = {_ALL_USERS: "qualquer pessoa na Internet", _AUTH_USERS: "qualquer conta da AWS"}
_WRITE_PERMISSIONS = frozenset({"WRITE", "WRITE_ACP", "FULL_CONTROL"})
_BLOCK_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
_BUCKET_REF = re.compile(r"\baws_s3_bucket\.([\w\-]+)")
_POLICY_DOCUMENT = re.compile(r"^data\.aws_iam_policy_document\.([\w\-]+)\.(?:minified_)?json$")
#: condições que tornam a política não pública quando têm valor fixo (lista da AWS)
_LIMITING_KEYS = frozenset(
    {
        "aws:principalorgid",
        "aws:principalarn",
        "aws:principalaccount",
        "aws:sourceip",
        "aws:sourcearn",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:sourceowner",
        "aws:sourceaccount",
        "aws:userid",
        "s3:dataaccesspointarn",
        "s3:dataaccesspointaccount",
    }
)
_POLICY_VARIABLE = re.compile(r"[$&]\{[a-z0-9]+:", re.I)
_PRIVATE_NETS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_GOOGLE_PUBLIC = {
    "allUsers": "qualquer pessoa na Internet",
    "allAuthenticatedUsers": "qualquer conta do Google",
}
_GOOGLE_WRITE_ROLE = re.compile(r"admin|creator|writer|owner|editor", re.I)


@dataclass
class _Statement:
    """Trecho ``Allow`` de uma política, já no mesmo formato para JSON e ``aws_iam_policy_document``."""

    sid: str
    public_principal: bool
    actions: list[str]
    conditions: list[tuple[str, str, list[Any]]] = field(default_factory=list)


class _Buckets:
    """Índice por bucket: bloqueio de acesso público e sites estáticos do módulo."""

    def __init__(self, module: Module) -> None:
        self.module = module
        self.names: dict[str, str] = {}
        for bucket in module.of_type("aws_s3_bucket"):
            literal = bucket.block.get("bucket")
            if isinstance(literal, str):
                self.names[literal] = bucket.name
        self.blocks = {
            self.key(item.block.get("bucket")): item.block
            for item in module.of_type("aws_s3_bucket_public_access_block")
        }
        self.websites = {
            self.key(item.block.get("bucket"))
            for item in module.of_type("aws_s3_bucket_website_configuration")
        }
        self.websites |= {
            item.name for item in module.of_type("aws_s3_bucket") if item.block.children("website")
        }

    def key(self, value: Any) -> str:
        """Nome do recurso do bucket a partir de ``aws_s3_bucket.b.id`` ou do nome literal."""
        resolved, _indirect = self.module.resolve(value)
        text = resolved.raw if isinstance(resolved, Ref) else as_text(resolved)
        match = _BUCKET_REF.search(text)
        return match.group(1) if match else self.names.get(text, text)

    def _blocked(self, key: str, *flags: str) -> bool:
        block = self.blocks.get(key)
        if block is None:
            return False
        return any(self.module.flag(block.get(flag))[0] is True for flag in flags)

    def acl_blocked(self, key: str) -> bool:
        return self._blocked(key, "block_public_acls", "ignore_public_acls")

    def policy_blocked(self, key: str) -> bool:
        return self._blocked(key, "block_public_policy", "restrict_public_buckets")


def check_storage(run: TfRun) -> None:
    module = run.module
    buckets = _Buckets(module)
    for resource in module.of_type("aws_s3_bucket"):
        key = resource.name
        _canned_acl(run, buckets, resource, key)
        _inline_grants(run, buckets, resource, key)
        _policy(run, buckets, resource, key)
    for resource in module.of_type("aws_s3_bucket_acl"):
        key = buckets.key(resource.block.get("bucket"))
        _canned_acl(run, buckets, resource, key)
        _acl_policy_grants(run, buckets, resource, key)
    for resource in module.of_type("aws_s3_bucket_policy"):
        _policy(run, buckets, resource, buckets.key(resource.block.get("bucket")))
    for resource in module.of_type("aws_s3_bucket_public_access_block"):
        _public_access_block(run, resource)
    for resource in module.of_type("azurerm_storage_container"):
        _azure_container(run, resource)
    for resource in module.of_type(
        "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"
    ):
        _google_iam(run, resource)


def _private_fix(key: str) -> str:
    bucket = (
        f"aws_s3_bucket.{key}.id" if re.fullmatch(r"[\w\-]+", key or "") else '"<nome-do-bucket>"'
    )
    return (
        f'resource "aws_s3_bucket_public_access_block" "{key if bucket[0] != chr(34) else "bucket"}" {{\n'
        f"  bucket                  = {bucket}\n"
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}"
    )


def _public(
    run: TfRun,
    buckets: _Buckets,
    resource: Resource,
    key: str,
    *,
    line: int,
    title: str,
    evidence: str,
    discriminator: str,
    write: bool,
    indirect: bool = False,
    confidence: Confidence = Confidence.CONFIRMED,
    **details: Any,
) -> None:
    """Escrita pública é crítica; leitura de um site estático pode ser intencional (média)."""
    website = key in buckets.websites
    severity = Severity.CRITICAL if write else Severity.MEDIUM if website else Severity.HIGH
    if website and not write:
        details["observacao"] = (
            "o bucket hospeda um site estático: confirme se o acesso público é intencional"
        )
    run.issue(
        resource,
        BUCKET_PUBLIC,
        line,
        title,
        evidence,
        discriminator,
        _private_fix(key),
        severity=severity,
        confidence=confidence,
        indirect=indirect,
        **details,
    )


def _canned_acl(run: TfRun, buckets: _Buckets, resource: Resource, key: str) -> None:
    value, indirect = run.module.resolve(resource.block.get("acl"))
    acl = as_text(value).strip().lower()
    if acl not in _CANNED_ACLS or buckets.acl_blocked(key):
        return
    who, write = _CANNED_ACLS[acl]
    _public(
        run,
        buckets,
        resource,
        key,
        line=resource.block.line_of("acl"),
        title=f"{resource.address} usa a ACL pública {acl}",
        evidence=f'{resource.address}: acl = "{acl}" ({who})',
        discriminator=f"acl:{acl}",
        write=write,
        indirect=indirect,
        acl=acl,
    )


def _inline_grants(run: TfRun, buckets: _Buckets, resource: Resource, key: str) -> None:
    """Bloco ``grant`` dentro de ``aws_s3_bucket`` (forma antiga)."""
    for grant in resource.block.children("grant"):
        permissions, _via = run.module.resolved_list(grant.get("permissions"))
        _group_grant(run, buckets, resource, key, grant, as_text(grant.get("uri")), permissions)


def _acl_policy_grants(run: TfRun, buckets: _Buckets, resource: Resource, key: str) -> None:
    """``access_control_policy { grant { grantee { uri } permission } }`` de ``aws_s3_bucket_acl``."""
    for policy in resource.block.children("access_control_policy"):
        for grant in policy.children("grant"):
            for grantee in grant.children("grantee"):
                uri = as_text(grantee.get("uri"))
                _group_grant(run, buckets, resource, key, grant, uri, [grant.get("permission")])


def _group_grant(
    run: TfRun,
    buckets: _Buckets,
    resource: Resource,
    key: str,
    grant: Block,
    uri: str,
    permissions: list[Any],
) -> None:
    who = _GROUPS.get(uri.strip())
    if who is None or buckets.acl_blocked(key):
        return
    names = sorted(
        {as_text(permission).upper() for permission in permissions if as_text(permission)}
    )
    _public(
        run,
        buckets,
        resource,
        key,
        line=grant.line,
        title=f"{resource.address} concede acesso a {who} pela ACL",
        evidence=f"{resource.address}: grant para {uri} ({', '.join(names) or 'permissão não informada'})",
        discriminator=f"grant:{uri.rsplit('/', 1)[-1]}",
        write=bool(_WRITE_PERMISSIONS.intersection(names)),
        permissoes=names,
    )


# -- políticas ----------------------------------------------------------------------------


def _policy(run: TfRun, buckets: _Buckets, resource: Resource, key: str) -> None:
    if not resource.block.has("policy") or buckets.policy_blocked(key):
        return
    statements, indirect = _statements(run.module, resource.block.get("policy"))
    for index, statement in enumerate(statements, start=1):
        if not statement.public_principal or _limited(statement.conditions):
            continue
        write = _writes(statement.actions)
        conditions = sorted({condition[1] for condition in statement.conditions})
        where = statement.sid or f"instrução {index}"
        actions = ", ".join(statement.actions[:5]) or "?"
        suffix = f"; condições sem efeito de limite: {', '.join(conditions)}" if conditions else ""
        _public(
            run,
            buckets,
            resource,
            key,
            line=resource.block.line_of("policy"),
            title=f"{resource.address} libera acesso público pela política ({where})",
            evidence=f'{resource.address}: Allow para Principal "*" em {actions}{suffix}',
            discriminator=f"policy:{where}",
            write=write,
            indirect=indirect,
            confidence=Confidence.FIRM if conditions else Confidence.CONFIRMED,
            acoes=statement.actions[:20],
            condicoes=conditions,
        )


def _statements(module: Module, value: Any) -> tuple[list[_Statement], bool]:
    resolved, indirect = module.resolve(value)
    if isinstance(resolved, Call) and resolved.name == "jsonencode" and resolved.args:
        resolved, via = module.resolve(resolved.args[0])
        indirect = indirect or via
    if isinstance(resolved, Ref):
        match = _POLICY_DOCUMENT.match(resolved.raw)
        document = module.policy_documents.get(match.group(1)) if match else None
        return (
            (_from_document(module, document), indirect) if document is not None else ([], indirect)
        )
    if isinstance(resolved, str):
        try:
            resolved = json.loads(resolved)
        except ValueError:
            return [], indirect  # modelo com interpolação fora de aspas: conteúdo desconhecido
    return (_from_json(resolved), indirect) if isinstance(resolved, dict) else ([], indirect)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _from_json(document: dict[str, Any]) -> list[_Statement]:
    statements: list[_Statement] = []
    for item in _as_list(document.get("Statement")):
        if not isinstance(item, dict) or as_text(item.get("Effect")).lower() != "allow":
            continue
        actions = [as_text(action) for action in _as_list(item.get("Action"))]
        if "NotAction" in item:
            actions.append("*")
        conditions: list[tuple[str, str, list[Any]]] = []
        condition = item.get("Condition")
        if isinstance(condition, dict):
            for operator, keys in condition.items():
                if isinstance(keys, dict):
                    conditions += [
                        (operator, key, _as_list(values)) for key, values in keys.items()
                    ]
        statements.append(
            _Statement(
                as_text(item.get("Sid")),
                _public_principal(item.get("Principal")),
                actions,
                conditions,
            )
        )
    return statements


def _public_principal(principal: Any) -> bool:
    if isinstance(principal, dict):
        return "*" in _as_list(principal.get("AWS"))
    return principal == "*"


def _from_document(module: Module, document: Block) -> list[_Statement]:
    """``data "aws_iam_policy_document"``: ``effect`` é ``Allow`` quando não informado."""
    statements: list[_Statement] = []
    for statement in document.children("statement"):
        if as_text(statement.get("effect") or "Allow").lower() != "allow":
            continue
        public = False
        for principal in statement.children("principals"):
            identifiers, _via = module.resolved_list(principal.get("identifiers"))
            kind = as_text(principal.get("type"))
            public = public or (kind in ("*", "AWS") and "*" in identifiers)
        actions, _via = module.resolved_list(statement.get("actions"))
        names = [as_text(action) for action in actions]
        if statement.has("not_actions"):
            names.append("*")
        conditions = [
            (
                as_text(item.get("test")),
                as_text(item.get("variable")),
                module.resolved_list(item.get("values"))[0],
            )
            for item in statement.children("condition")
        ]
        statements.append(_Statement(as_text(statement.get("sid")), public, names, conditions))
    return statements


def _limited(conditions: list[tuple[str, str, list[Any]]]) -> bool:
    """Alguma condição restringe a valores fixos? ``NotX`` e ``...IfExists`` não restringem."""
    for operator, key, values in conditions:
        base = operator.lower().rsplit(":", 1)[-1]
        if base.startswith("not") or base.endswith("ifexists"):
            continue
        lowered = key.lower()
        if lowered in _LIMITING_KEYS and values and all(_fixed(lowered, value) for value in values):
            return True
    return False


def _fixed(key: str, value: Any) -> bool:
    """Referência do Terraform é um valor fixo ao aplicar; curinga e variável de política não são."""
    if isinstance(value, (Ref, Call)):
        return True
    text = as_text(value)
    if not text or _POLICY_VARIABLE.search(text):
        return False
    if key == "aws:sourceip":
        return _narrow_network(text)
    if key == "aws:userid" and text.endswith(":*"):
        return False
    if key == "s3:dataaccesspointarn":
        return "*" not in text.rsplit("/", 1)[0] and "?" not in text
    return "*" not in text and "?" not in text


def _narrow_network(text: str) -> bool:
    """Faixas maiores que /8 (IPv4) ou /32 (IPv6), fora as privadas, contam como públicas."""
    try:
        network = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return False
    if network.version == 4:
        private = any(network.subnet_of(net) for net in _PRIVATE_NETS)  # type: ignore[arg-type]
        return private or network.prefixlen >= 8
    return network.prefixlen >= 32


def _writes(actions: list[str]) -> bool:
    for action in actions:
        lowered = action.lower()
        if lowered in ("*", "s3:*") or lowered.startswith(("s3:put", "s3:delete", "s3:abort")):
            return True
    return False


def _public_access_block(run: TfRun, resource: Resource) -> None:
    block = resource.block
    flags = {flag: run.module.flag(block.get(flag)) for flag in _BLOCK_FLAGS}
    if all(value is True for value, _via in flags.values()):
        run.strength(
            resource,
            "code.iac.s3_bloqueio_publico",
            "os quatro bloqueios de acesso público estão ligados",
        )
        return
    disabled = [flag for flag, (value, _via) in flags.items() if value is False]
    if not disabled:
        return
    fix = "\n".join(f"{flag} = true" for flag in _BLOCK_FLAGS)
    run.issue(
        resource,
        BUCKET_PUBLIC,
        block.line_of(disabled[0]),
        f"{resource.address} desliga o bloqueio de acesso público do bucket",
        f"{resource.address}: " + ", ".join(f"{flag} = false" for flag in disabled),
        "bloqueio",
        fix,
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        indirect=any(via for value, via in flags.values() if value is False),
        desligados=disabled,
    )


# -- outras nuvens ---------------------------------------------------------------------------


def _azure_container(run: TfRun, resource: Resource) -> None:
    value, indirect = run.module.resolve(resource.block.get("container_access_type"))
    level = as_text(value).strip().lower()
    if level not in ("blob", "container"):
        return
    who = "arquivos" if level == "blob" else "arquivos e a listagem do container"
    run.issue(
        resource,
        BUCKET_PUBLIC,
        resource.block.line_of("container_access_type"),
        f"{resource.address} tem acesso público ({level})",
        f'{resource.address}: container_access_type = "{level}" ({who} sem autenticação)',
        "acesso",
        'container_access_type = "private"',
        indirect=indirect,
        nivel=level,
    )


def _google_iam(run: TfRun, resource: Resource) -> None:
    block = resource.block
    name = "member" if block.has("member") else "members"
    members, indirect = run.module.resolved_list(block.get(name))
    role = as_text(run.module.resolve(block.get("role"))[0])
    for member in members:
        who = _GOOGLE_PUBLIC.get(as_text(member).strip())
        if who is None:
            continue
        write = bool(_GOOGLE_WRITE_ROLE.search(role))
        run.issue(
            resource,
            BUCKET_PUBLIC,
            block.line_of(name),
            f"{resource.address} concede {role or 'um papel'} a {who}",
            f'{resource.address}: {name} inclui "{member}" com o papel {role or "?"}',
            f"iam:{member}",
            f'{name} = "serviceAccount:app@meu-projeto.iam.gserviceaccount.com"'
            if name == "member"
            else f'{name} = ["serviceAccount:app@meu-projeto.iam.gserviceaccount.com"]',
            severity=Severity.CRITICAL if write else Severity.HIGH,
            indirect=indirect,
            papel=role,
            membro=member,
        )


__all__ = ["as_bool", "check_storage"]
