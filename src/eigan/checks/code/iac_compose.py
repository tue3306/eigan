"""Regras para docker-compose: privilégios, namespaces do host, docker.sock, portas e senhas.

Referência: especificação do Compose
(https://docs.docker.com/reference/compose-file/services/) e o OWASP Docker
Security Cheat Sheet. A entrada da base do banco publicado em todas as
interfaces fica aqui (só o compose publica portas); as demais estão em ``kb_iac``.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Severity
from .iac_common import (
    CAPABILITIES,
    DB_PORT,
    DB_PORTS,
    DOCKER_SOCK,
    HOST_NS,
    HOSTPATH,
    PRIVILEGED,
    ROOT,
    ROOT_USERS,
    SECRET,
    UNPINNED,
    IacIssue,
    IacReport,
    all_interfaces,
    caps_severity,
    expand_vars,
    image_tag_issue,
    is_runtime_socket,
    is_secret_name,
    literal_secret,
    mask_secret,
    mask_url_password,
    parse_port,
    risky_caps,
    sensitive_host_path,
    url_password,
    weak_secret,
)
from .yamlish import Node, parse_documents

kb.register(
    KBEntry(
        id=DB_PORT,
        title="Banco de dados publicado em todas as interfaces (docker-compose)",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "A porta de um banco, cache ou fila é publicada no servidor sem limitar o endereço: "
            "fica acessível pela rede."
        ),
        explanation=(
            "No docker-compose, 'ports: - \"5432:5432\"' publica a porta em todas as interfaces "
            "do servidor (0.0.0.0). A própria documentação do Compose avisa que, nesse caso, o "
            "Docker liga a porta em todas as interfaces passando por cima das regras de firewall "
            "do host (como o ufw). Bancos, caches e filas raramente precisam ser acessados de "
            "fora: os outros containers já falam com eles pela rede interna do compose, usando o "
            "nome do serviço."
        ),
        risk=(
            "Qualquer máquina que alcance o servidor — a Internet inteira, no caso de uma VPS — "
            "pode tentar senhas no banco, explorar falhas da versão em uso ou ler os dados "
            "diretamente se a autenticação estiver desligada."
        ),
        steps=(
            "Se só outros containers usam o serviço, remova o bloco 'ports': eles se conectam "
            "pelo nome do serviço (ex.: db:5432).",
            "Se você precisa acessar a partir do próprio servidor (administração, backup), "
            'publique só no loopback: "127.0.0.1:5432:5432".',
            "Não conte com o ufw/firewalld para fechar portas publicadas pelo Docker: elas passam "
            "por fora dessas regras.",
            "Mantenha senha forte no banco mesmo dentro da rede interna.",
        ),
        examples=(
            Fix(
                "docker-compose",
                "docker-compose",
                "services:\n"
                "  db:\n"
                "    image: postgres:16.4\n"
                "    ports:\n"
                '      - "127.0.0.1:5432:5432"   # só acessível desta máquina\n'
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    environment:\n"
                "      DATABASE_HOST: db         # pela rede interna, sem publicar porta",
                "yaml",
            ),
        ),
        verify=(
            "No servidor, 'docker compose ps' (ou 'ss -ltnp') deve mostrar a porta presa a "
            "127.0.0.1, e não a 0.0.0.0 ou [::]. Rode o EIGAN de novo."
        ),
        effort="baixo",
        fix_group="iac",
        references=(
            "https://docs.docker.com/reference/compose-file/services/#ports",
            "https://docs.docker.com/engine/network/packet-filtering-firewalls/",
        ),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        lgpd=True,
        tags=("docker", "rede", "banco-de-dados"),
    ),
)

_NAMESPACES = {
    "network_mode": "a rede",
    "pid": "os processos",
    "ipc": "a memória compartilhada (IPC)",
}
#: pedaços do nome da imagem que confirmam o serviço de cada porta (sem isso, o achado é indício)
_DB_IMAGE_HINTS: dict[int, tuple[str, ...]] = {
    1433: ("mssql", "sqlserver", "sql-server"),
    1521: ("oracle",),
    2379: ("etcd",),
    3306: ("mysql", "mariadb", "percona"),
    5432: ("postgres", "postgis", "timescale", "pgvector"),
    5672: ("rabbitmq",),
    5984: ("couchdb",),
    6379: ("redis", "valkey", "keydb", "dragonfly"),
    7474: ("neo4j",),
    8086: ("influx",),
    9042: ("cassandra", "scylla"),
    9200: ("elastic", "opensearch"),
    9300: ("elastic", "opensearch"),
    11211: ("memcached",),
    15672: ("rabbitmq",),
    27017: ("mongo",),
}


def check_compose(text: str, *, by_name: bool = True) -> IacReport:
    """Analisa os serviços. Sem nome de compose (``by_name=False``), só serviços com image/build."""
    report = IacReport()
    for document in parse_documents(text):
        services = document.get("services")
        if services is None or not services.is_map:
            continue
        for name, service in services.items():
            if not service.is_map:
                continue
            if not by_name and not (service.has("image") or service.has("build")):
                continue
            _service(report, name, service)
    return report


def _service(report: IacReport, name: str, service: Node) -> None:
    if service.flag("privileged"):
        report.add(
            IacIssue(
                PRIVILEGED,
                service.line_of("privileged"),
                f"Serviço '{name}' roda com privileged: true",
                f"services.{name}.privileged: true",
                confidence=Confidence.CONFIRMED,
                discriminator=f"{name}:privileged",
                details={"servico": name},
                fix="# remova 'privileged: true' e conceda só o necessário\n"
                "cap_drop: [ALL]\ncap_add: [NET_BIND_SERVICE]",
            )
        )
    for key, label in _NAMESPACES.items():
        if service.text(key).strip().lower() == "host":
            report.add(
                IacIssue(
                    HOST_NS,
                    service.line_of(key),
                    f"Serviço '{name}' compartilha {label} com o host ({key}: host)",
                    f"services.{name}.{key}: host",
                    severity=Severity.MEDIUM if key == "network_mode" else Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    discriminator=f"{name}:{key}",
                    details={"servico": name},
                    fix=(
                        "# remova 'network_mode: host' e publique só o necessário\n"
                        'ports:\n  - "127.0.0.1:8080:8080"'
                        if key == "network_mode"
                        else f"# remova a linha '{key}: host' (o padrão isola o container)"
                    ),
                )
            )
    _volumes(report, name, service)
    _ports(report, name, service)
    _environment(report, name, service)
    _image_user_caps(report, name, service)
    _hardening(report, name, service)


def _hardening(report: IacReport, name: str, service: Node) -> None:
    """Controles de endurecimento declarados no serviço (viram pontos fortes)."""
    if service.flag("read_only"):
        report.strength(
            "code.iac.fs_somente_leitura",
            f"Serviço '{name}': sistema de arquivos somente leitura (read_only: true)",
        )
    options = [node.text().replace("=", ":").lower() for node in service.seq("security_opt")]
    if any(option in ("no-new-privileges", "no-new-privileges:true") for option in options):
        report.strength(
            "code.iac.sem_escalacao",
            f"Serviço '{name}': processos não ganham novos privilégios (no-new-privileges)",
        )


def _volume_paths(item: Node) -> tuple[str, str]:
    """(origem no host, destino) de um volume; origem vazia = sem caminho do host.

    ``- /dados`` (um caminho só) é um volume anônimo dentro do container, e os
    volumes com ``type: volume``/``tmpfs`` também não apontam para o host.
    """
    if item.is_map:
        if item.text("type") not in ("", "bind"):
            return "", ""
        return expand_vars(item.text("source").strip()), item.text("target").strip()
    parts = expand_vars(item.text().strip()).split(":")
    return (parts[0], parts[1]) if len(parts) >= 2 else ("", parts[0])


def _volumes(report: IacReport, name: str, service: Node) -> None:
    for item in service.seq("volumes"):
        source, target = _volume_paths(item)
        line = item.line or service.line_of("volumes")
        unknown_source = "?" in source and is_runtime_socket(target)
        if is_runtime_socket(source) or unknown_source:
            report.add(
                IacIssue(
                    DOCKER_SOCK,
                    line,
                    f"Serviço '{name}' monta o socket do Docker ({source})",
                    f"services.{name}.volumes: {item.text() or source}",
                    confidence=Confidence.TENTATIVE if unknown_source else Confidence.CONFIRMED,
                    discriminator=f"{name}:{target if unknown_source else source}",
                    details={"servico": name, "origem": source, "destino": target},
                    fix="# remova o volume; se precisar da API, use um proxy que libere só o necessário\n"
                    "environment:\n  DOCKER_HOST: tcp://docker-proxy:2375",
                )
            )
        elif sensitive_host_path(source):
            read_only = _read_only(item)
            report.add(
                IacIssue(
                    HOSTPATH,
                    line,
                    f"Serviço '{name}' monta um diretório sensível do host ({source})",
                    f"services.{name}.volumes: {item.text() or source}",
                    severity=Severity.MEDIUM if read_only else Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    discriminator=f"{name}:{source}",
                    details={"servico": name, "origem": source, "somente_leitura": read_only},
                    fix=f"volumes:\n  - {source.rstrip('/')}/<só-o-necessário>:{target or '<destino>'}:ro",
                )
            )


def _read_only(item: Node) -> bool:
    if item.is_map:
        return bool(item.flag("read_only"))
    parts = item.text().split(":")
    return len(parts) >= 3 and "ro" in parts[-1].split(",")


def _ports(report: IacReport, name: str, service: Node) -> None:
    image = service.text("image").lower()
    for item in service.seq("ports"):
        if item.is_map:
            host = expand_vars(item.text("host_ip"))
            published = expand_vars(item.text("published"))
            target = _int(expand_vars(item.text("target")))
            shown = f"target: {item.text('target')}, published: {item.text('published') or '-'}"
        else:
            spec = parse_port(item.text())
            host, published, target = spec.host_ip, spec.published, spec.target
            shown = item.text()
        if target not in DB_PORTS:
            continue
        line = item.line or service.line_of("ports")
        if not all_interfaces(host):
            if host.strip("[]") in ("127.0.0.1", "::1"):
                report.strength(
                    "code.iac.portas_locais",
                    f"Serviço '{name}': {DB_PORTS[target]} publicado só no loopback ({host})",
                )
            continue
        confirmed = any(hint in image for hint in _DB_IMAGE_HINTS.get(target, ()))
        report.add(_db_port_issue(name, line, shown, published, target, confirmed))


def _db_port_issue(
    name: str, line: int, shown: str, published: str, target: int, confirmed: bool
) -> IacIssue:
    """``confirmed``: o nome da imagem confirma que a porta é mesmo desse banco."""
    service = DB_PORTS[target]
    random_port = not published
    unknown = "?" in published
    where = "uma porta escolhida pelo Docker" if random_port else f"a porta {published}"
    return IacIssue(
        DB_PORT,
        line,
        f"{service} do serviço '{name}' publicado em todas as interfaces",
        f"services.{name}.ports: {shown} -> {service} em {where} de todas as interfaces (0.0.0.0)",
        confidence=Confidence.FIRM if confirmed and not unknown else Confidence.TENTATIVE,
        discriminator=f"{name}:{published or target}",
        details={
            "servico": name,
            "tipo": service,
            "porta_publicada": published or "aleatória",
            "porta_container": target,
        },
        fix=f'ports:\n  - "127.0.0.1:{published if published and not unknown else target}:{target}"',
    )


def _int(text: str) -> int | None:
    head = text.strip().split("-", 1)[0]
    return int(head) if head.isdigit() else None


def _environment(report: IacReport, name: str, service: Node) -> None:
    env = service.get("environment")
    if env is None:
        return
    pairs: list[tuple[str, str, int]] = []
    if env.is_map:
        pairs = [(key, node.text(), env.line_of(key)) for key, node in env.items()]
    else:
        for item in env.seq():
            key, sep, value = item.text().partition("=")
            if sep:
                pairs.append((key.strip(), value, item.line or env.line))
    for key, value, line in pairs:
        if not is_secret_name(key):
            if url_password(value) is not None:
                report.add(_url_secret(name, key, value, line))
            continue
        if not literal_secret(value):
            if "${" in value or value.strip().startswith("$"):
                report.strength(
                    "code.iac.segredos_externos",
                    f"Serviço '{name}': {key} vem de variável de ambiente, não do arquivo",
                )
            continue
        weak = weak_secret(value)
        details: dict[str, object] = {"servico": name, "variavel": key, "valor": mask_secret(value)}
        if weak:
            details["senha_fraca"] = "valor padrão/conhecido (fácil de adivinhar)"
        report.add(
            IacIssue(
                SECRET,
                line,
                f"Senha em texto puro no docker-compose ({name}: {key})",
                f"services.{name}.environment.{key}={mask_secret(value)}",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE if weak else Confidence.FIRM,
                discriminator=f"{name}:{key}",
                details=details,
                fix=f"{key}: ${{{key}}}   # valor no .env fora do Git ou em 'secrets:'",
            )
        )


def _url_secret(name: str, key: str, value: str, line: int) -> IacIssue:
    shown = mask_url_password(value)
    return IacIssue(
        SECRET,
        line,
        f"Senha em texto puro na URL de conexão ({name}: {key})",
        f"services.{name}.environment.{key}={shown}",
        severity=Severity.HIGH,
        discriminator=f"{name}:{key}",
        details={"servico": name, "variavel": key, "valor": shown},
        fix=f"{key}: ${{{key}}}   # URL completa no .env fora do Git ou em 'secrets:'",
    )


def _image_user_caps(report: IacReport, name: str, service: Node) -> None:
    image = service.text("image")
    problem = image_tag_issue(image) if image and not service.has("build") else None
    if problem is not None:
        report.add(
            IacIssue(
                UNPINNED,
                service.line_of("image"),
                f"Serviço '{name}' usa imagem sem versão fixa: {image}",
                f"services.{name}.image: {image}"
                + (" (sem tag = latest)" if problem == "sem-tag" else ""),
                discriminator=f"{name}:{image}",
                details={"servico": name, "imagem": image},
                fix=f"image: {image.rsplit(':', 1)[0] if problem == 'latest' else image}:<versão>@sha256:<digest>",
            )
        )
    user = service.text("user").strip().lower()
    if user in ROOT_USERS:
        report.add(
            IacIssue(
                ROOT,
                service.line_of("user"),
                f"Serviço '{name}' roda como root (user: {user})",
                f"services.{name}.user: {user}",
                confidence=Confidence.CONFIRMED,
                discriminator=f"{name}:user",
                details={"servico": name},
                fix='user: "10001:10001"',
            )
        )
    caps = risky_caps([node.text() for node in service.seq("cap_add")])
    if caps:
        report.add(
            IacIssue(
                CAPABILITIES,
                service.line_of("cap_add"),
                f"Serviço '{name}' recebe capabilities perigosas: {', '.join(caps)}",
                f"services.{name}.cap_add: {caps}",
                severity=caps_severity(caps),
                confidence=Confidence.CONFIRMED,
                discriminator=f"{name}:cap_add",
                details={"servico": name, "capabilities": caps},
                fix="cap_drop: [ALL]\ncap_add: [<só-o-que-a-aplicação-precisa>]",
            )
        )
