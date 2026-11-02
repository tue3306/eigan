"""Regras de firewall na nuvem: AWS (security groups), Azure (NSG) e Google Cloud (firewall).

Só reportam regras de **entrada** que liberam **qualquer origem** para portas de
administração remota ou de banco de dados. Porta ou origem que dependem de uma variável
sem valor no módulo ficam de fora: valor desconhecido nunca vira achado.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ...core.models import Confidence
from .iac_common import ADMIN_PORTS, DB_PORTS, FIREWALL_OPEN
from .iac_hcl import Block, Ref
from .iac_tf_model import Module, Resource, TfRun, as_bool, as_int, as_text

_SENSITIVE_PORTS: dict[int, str] = {**ADMIN_PORTS, **DB_PORTS}
_MAX_NAMES = 4
_WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
#: fonte "qualquer endereço" nas regras do Azure (o ``*`` e a tag ``Internet`` são documentados)
_AZURE_WORLD = _WORLD_CIDRS | {"*", "internet"}
_TCP_PROTOCOLS = frozenset({"tcp", "6"})
#: ``-1`` (AWS) e ``all`` (GCP) liberam qualquer porta; o ``*`` do Azure respeita as portas da regra
_ALL_PROTOCOLS = frozenset({"-1", "all"})
_ALL_PORTS = (0, 65535)
PortRange = tuple[int, int]


@dataclass
class _Rule:
    """Uma regra de entrada já normalizada."""

    resource: Resource
    line: int
    protocol: Any
    ports: list[PortRange]
    sources: list[str]
    indirect: bool
    fix: str


def check_network(run: TfRun) -> None:
    module = run.module
    for resource in module.of_type("aws_security_group", "aws_default_security_group"):
        for values, line in _inline_rules(module, resource.block, "ingress"):
            _aws(run, resource, values, line)
    for resource in module.of_type("aws_security_group_rule"):
        values = _attrs(resource.block)
        if as_text(module.resolve(values.get("type"))[0]).lower() == "ingress":
            _aws(run, resource, values, resource.block.line)
    for resource in module.of_type("aws_vpc_security_group_ingress_rule"):
        _aws(run, resource, _attrs(resource.block), resource.block.line)
    for resource in module.of_type("azurerm_network_security_rule"):
        _azure(run, resource, _attrs(resource.block), resource.block.line)
    for resource in module.of_type("azurerm_network_security_group"):
        for values, line in _inline_rules(module, resource.block, "security_rule"):
            _azure(run, resource, values, line)
    for resource in module.of_type("google_compute_firewall"):
        _google(run, resource)


def _attrs(block: Block) -> dict[str, Any]:
    return {name: attr.value for name, attr in block.attrs.items()}


def _inline_rules(module: Module, block: Block, kind: str) -> list[tuple[dict[str, Any], int]]:
    """Regras escritas como blocos, como lista de objetos ou como bloco ``dynamic``."""
    rules = [(_attrs(child), child.line) for child in block.children(kind)]
    resolved, _indirect = module.resolve(block.get(kind))
    if isinstance(resolved, list):
        rules += [(item, block.line_of(kind)) for item in resolved if isinstance(item, dict)]
    for dynamic in block.children("dynamic"):
        if dynamic.label(0) == kind:
            rules += _expand_dynamic(module, dynamic, kind)
    return rules


def _expand_dynamic(module: Module, dynamic: Block, kind: str) -> list[tuple[dict[str, Any], int]]:
    """``dynamic "ingress"``: aplica ``ingress.value`` a cada item de um ``for_each`` conhecido."""
    contents = dynamic.children("content")
    if not contents:
        return []
    values = _attrs(contents[0])
    iterator = as_text(dynamic.get("iterator")) or kind
    if isinstance(dynamic.get("iterator"), Ref):
        iterator = dynamic.get("iterator").raw
    items, _indirect = module.resolve(dynamic.get("for_each"))
    if isinstance(items, dict):
        items = list(items.values())
    if not isinstance(items, list):
        return [(values, contents[0].line)]
    return [
        (
            {name: _substitute(value, iterator, item) for name, value in values.items()},
            contents[0].line,
        )
        for item in items
    ]


def _substitute(value: Any, iterator: str, item: Any) -> Any:
    """Troca ``ingress.value`` e ``ingress.value.campo`` pelo item atual do ``for_each``."""
    if isinstance(value, list):
        return [_substitute(element, iterator, item) for element in value]
    if not isinstance(value, Ref):
        return value
    prefix = f"{iterator}.value"
    if value.raw == prefix:
        return item
    if value.raw.startswith(prefix + ".") and isinstance(item, dict):
        return item.get(value.raw[len(prefix) + 1 :], value)
    return value


# -- AWS ------------------------------------------------------------------------------------


def _aws(run: TfRun, resource: Resource, values: dict[str, Any], line: int) -> None:
    module = run.module
    items, indirect = module.resolved_list(
        values.get("cidr_blocks"),
        values.get("ipv6_cidr_blocks"),
        values.get("cidr_ipv4"),
        values.get("cidr_ipv6"),
    )
    sources = _matching(items, _WORLD_CIDRS)
    if not sources:
        return
    protocol, via_protocol = module.resolve(values.get("protocol", values.get("ip_protocol")))
    low, via_low = module.resolve(values.get("from_port"))
    high, via_high = module.resolve(values.get("to_port"))
    ports = _aws_ports(low, high)
    fix = (
        f"# em {resource.address}: troque a origem pela faixa da VPN ou do escritório\n"
        'cidr_blocks = ["10.20.0.0/24"]'
        if resource.type != "aws_vpc_security_group_ingress_rule"
        else f'# em {resource.address}: troque a origem pela faixa da VPN ou do escritório\ncidr_ipv4 = "10.20.0.0/24"'
    )
    _report(
        run,
        _Rule(
            resource,
            line,
            protocol,
            ports,
            sources,
            indirect or via_low or via_high or via_protocol,
            fix,
        ),
    )


def _aws_ports(low: Any, high: Any) -> list[PortRange]:
    start, end = as_int(low), as_int(high)
    if start is None and end is None:
        return []
    first = start if start is not None else end
    last = end if end is not None else start
    return [(first, last)] if first is not None and last is not None else []


# -- Azure ----------------------------------------------------------------------------------


def _azure(run: TfRun, resource: Resource, values: dict[str, Any], line: int) -> None:
    module = run.module
    if as_text(module.resolve(values.get("direction"))[0]).lower() != "inbound":
        return
    if as_text(module.resolve(values.get("access"))[0]).lower() != "allow":
        return
    items, indirect = module.resolved_list(
        values.get("source_address_prefix"), values.get("source_address_prefixes")
    )
    sources = _matching(items, _AZURE_WORLD)
    if not sources:
        return
    specs, via_ports = module.resolved_list(
        values.get("destination_port_range"), values.get("destination_port_ranges")
    )
    protocol, via_protocol = module.resolve(values.get("protocol"))
    ports = [port for port in map(_parse_port_spec, specs) if port is not None]
    fix = (
        f"# em {resource.address}: troque a origem pela faixa da VPN ou do escritório\n"
        'source_address_prefix = "10.20.0.0/24"'
    )
    _report(
        run,
        _Rule(resource, line, protocol, ports, sources, indirect or via_ports or via_protocol, fix),
    )


def _parse_port_spec(value: Any) -> PortRange | None:
    """``22``, ``"1000-2000"`` ou ``"*"``."""
    if isinstance(value, bool):
        return None
    text = str(value).strip() if isinstance(value, (int, str)) else ""
    if text == "*":
        return _ALL_PORTS
    low, separator, high = text.partition("-")
    if low.isdigit() and (not separator or high.isdigit()):
        return int(low), int(high) if separator else int(low)
    return None


# -- Google Cloud ---------------------------------------------------------------------------


def _google(run: TfRun, resource: Resource) -> None:
    module = run.module
    block = resource.block
    if as_bool(module.resolve(block.get("disabled"))[0]) is True:
        return  # regra desligada não é aplicada à rede
    direction = as_text(module.resolve(block.get("direction"))[0]).upper()
    if direction not in ("", "INGRESS"):
        return
    items, indirect = module.resolved_list(block.get("source_ranges"))
    sources = _matching(items, _WORLD_CIDRS)
    if not sources:
        return
    fix = f'# em {resource.address}: troque a origem pela faixa da VPN ou do escritório\nsource_ranges = ["10.20.0.0/24"]'
    for allow in block.children("allow"):
        protocol, via_protocol = module.resolve(allow.get("protocol"))
        specs, via_ports = module.resolved_list(allow.get("ports"))
        ports = [port for port in map(_parse_port_spec, specs) if port is not None]
        if not allow.has("ports"):
            ports = [_ALL_PORTS]  # "sem ports, a regra vale para qualquer porta"
        rule_indirect = indirect or via_protocol or via_ports
        _report(run, _Rule(resource, allow.line, protocol, ports, sources, rule_indirect, fix))


# -- comum ------------------------------------------------------------------------------------


def _matching(items: Iterable[Any], accepted: frozenset[str]) -> list[str]:
    found: list[str] = []
    for item in items:
        if isinstance(item, str) and item.strip().lower() in accepted and item.strip() not in found:
            found.append(item.strip())
    return found


def _report(run: TfRun, rule: _Rule) -> None:
    protocol = as_text(rule.protocol).strip().lower()
    unknown_protocol = isinstance(rule.protocol, Ref) or rule.protocol is None
    all_traffic = protocol in _ALL_PROTOCOLS
    if not (all_traffic or protocol in _TCP_PROTOCOLS or protocol == "*" or unknown_protocol):
        return  # UDP, ICMP etc. não falam com SSH, RDP nem com os bancos da lista
    ranges = [_ALL_PORTS] if all_traffic else rule.ports
    hits = sorted(
        {port for low, high in ranges for port in _SENSITIVE_PORTS if low <= port <= high}
    )
    if not hits:
        return
    everything = any(low <= 1 and high >= 65535 for low, high in ranges)
    described = _describe(hits, everything)
    sources = ", ".join(rule.sources)
    span = ",".join(f"{low}-{high}" for low, high in ranges)
    run.issue(
        rule.resource,
        FIREWALL_OPEN,
        rule.line,
        f"{rule.resource.address} libera {described} para qualquer origem",
        f"{rule.resource.address}: entrada de {sources} em {described}",
        f"entrada:{span}:{sources}",
        rule.fix,
        confidence=Confidence.FIRM if unknown_protocol else Confidence.CONFIRMED,
        indirect=rule.indirect,
        portas=hits[:20],
        origens=rule.sources,
    )


def _describe(ports: list[int], everything: bool) -> str:
    if everything:
        return "todas as portas"
    names = [f"{_SENSITIVE_PORTS[port]} ({port})" for port in ports[:_MAX_NAMES]]
    extra = len(ports) - _MAX_NAMES
    return ", ".join(names) + (f" e mais {extra}" if extra > 0 else "")
