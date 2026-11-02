"""Regras para Dockerfile: usuário root, imagem sem versão, downloads sem verificação e segredos.

Baseadas nas boas práticas oficiais do Docker
(https://docs.docker.com/build/building/best-practices/) e na verificação de
build ``SecretsUsedInArgOrEnv`` (https://docs.docker.com/reference/build-checks/).
Os achados que só existem em Dockerfile (ADD remoto, ``curl | sh`` e ``sudo``)
têm a entrada da base aqui; os compartilhados com compose/Kubernetes ficam em
``kb_iac``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Severity
from .iac_common import (
    ADD_REMOTE,
    CURL_SH,
    ROOT,
    SECRET,
    SUDO,
    UNPINNED,
    IacIssue,
    IacReport,
    image_tag_issue,
    is_secret_name,
    literal_secret,
    mask_secret,
    mask_url_password,
    scrub,
    url_password,
    weak_secret,
)

_DOCKER_PRACTICES = "https://docs.docker.com/build/building/best-practices/"
_DOCKERFILE_REF = "https://docs.docker.com/reference/dockerfile/"

kb.register(
    KBEntry(
        id=ADD_REMOTE,
        title="ADD baixa arquivo da Internet sem conferir a integridade",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="O Dockerfile usa ADD com uma URL e não confere o checksum do arquivo baixado.",
        explanation=(
            "ADD com http(s):// baixa o arquivo durante o build. Se o servidor de origem for "
            "invadido, se o arquivo for trocado por outro ou se o download for interceptado, a "
            "imagem passa a carregar um arquivo diferente do esperado — e ninguém percebe, porque "
            "nada confere o conteúdo. O build também deixa de ser reproduzível."
        ),
        risk=(
            "Um arquivo adulterado (com backdoor ou minerador) entra na imagem e vai para "
            "produção junto com a aplicação: é um ataque à cadeia de suprimentos."
        ),
        steps=(
            "Informe o hash esperado com ADD --checksum=sha256:<hash> (sintaxe do Dockerfile 1.6 "
            "ou mais nova; comece o arquivo com '# syntax=docker/dockerfile:1').",
            "Ou baixe com curl/wget e confira com 'sha256sum -c' antes de usar o arquivo.",
            "Use URLs com a versão exata do arquivo (nunca 'latest') e o hash publicado pelo fornecedor.",
            "Quando possível, prefira o pacote da distribuição ou copie o arquivo do repositório com COPY.",
        ),
        examples=(
            Fix(
                "dockerfile",
                "Dockerfile (ADD com checksum)",
                "# syntax=docker/dockerfile:1\n"
                "ADD --checksum=sha256:<hash-sha256-publicado-pelo-fornecedor> \\\n"
                "    https://exemplo.com.br/ferramenta-1.2.3.tar.gz /tmp/ferramenta.tar.gz",
                "dockerfile",
            ),
            Fix(
                "dockerfile",
                "Dockerfile (curl + sha256sum)",
                "RUN curl -fsSLo /tmp/ferramenta.tar.gz https://exemplo.com.br/ferramenta-1.2.3.tar.gz \\\n"
                ' && echo "<hash-sha256>  /tmp/ferramenta.tar.gz" | sha256sum -c - \\\n'
                " && tar -xzf /tmp/ferramenta.tar.gz -C /usr/local/bin \\\n"
                " && rm /tmp/ferramenta.tar.gz",
                "dockerfile",
            ),
        ),
        verify=(
            "Com --checksum (ou sha256sum -c), o build falha se o arquivo baixado não tiver o hash "
            "informado. Rode o EIGAN de novo e confirme que o achado sumiu."
        ),
        effort="baixo",
        fix_group="iac",
        references=(
            _DOCKERFILE_REF,
            _DOCKER_PRACTICES,
            "https://cwe.mitre.org/data/definitions/494.html",
        ),
        cwe="CWE-494",
        owasp="A08:2021",
        cis=("16.7",),
        tags=("docker", "cadeia-de-suprimentos"),
    ),
    KBEntry(
        id=CURL_SH,
        title="Script da Internet executado direto no shell (curl | sh)",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="O build baixa um script e o executa na hora, sem conferir o conteúdo.",
        explanation=(
            "Comandos como 'curl https://... | sh' executam, com os privilégios do build "
            "(normalmente root), o que o servidor remoto devolver naquele momento. Não há "
            "verificação de integridade e o script pode mudar a qualquer hora. Se o endereço "
            "for http://, qualquer pessoa no caminho da rede pode trocar o script."
        ),
        risk=(
            "Se o site do instalador for comprometido, ou se a resposta for alterada no caminho, "
            "código malicioso roda no build e fica dentro da imagem que vai para produção."
        ),
        steps=(
            "Baixe o script para um arquivo, confira o SHA-256 publicado pelo fornecedor "
            "(sha256sum -c) e só então execute.",
            "Prefira pacotes oficiais (apt, apk, dnf) ou binários com versão fixa e checksum.",
            "Nunca use http:// para baixar código que será executado.",
        ),
        examples=(
            Fix(
                "dockerfile",
                "Dockerfile",
                "RUN curl -fsSLo /tmp/instalar.sh https://exemplo.com.br/instalar-1.2.3.sh \\\n"
                ' && echo "<sha256-publicado-pelo-fornecedor>  /tmp/instalar.sh" | sha256sum -c - \\\n'
                " && sh /tmp/instalar.sh \\\n"
                " && rm /tmp/instalar.sh",
                "dockerfile",
            ),
        ),
        verify=(
            "O build deve falhar quando o script baixado não bate com o hash. Rode o EIGAN de "
            "novo e confirme que o achado sumiu."
        ),
        effort="baixo",
        fix_group="iac",
        references=(
            _DOCKER_PRACTICES,
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "https://cwe.mitre.org/data/definitions/494.html",
        ),
        cwe="CWE-494",
        owasp="A08:2021",
        cis=("16.7",),
        tags=("docker", "cadeia-de-suprimentos"),
    ),
    KBEntry(
        id=SUDO,
        title="Uso de sudo no Dockerfile",
        category=Category.CODE,
        severity=Severity.LOW,
        summary="O Dockerfile chama sudo, que a documentação do Docker recomenda evitar nas imagens.",
        explanation=(
            "O guia de boas práticas do Docker recomenda não instalar nem usar sudo dentro de "
            "imagens, porque ele tem comportamento imprevisível de TTY e de repasse de sinais. "
            "Além disso, sudo no build indica que a imagem tem um usuário com direito de virar "
            "root — quem invadir a aplicação ganha o mesmo direito."
        ),
        risk=(
            "Escalação de privilégio dentro do container (de usuário da aplicação para root) e "
            "falhas difíceis de diagnosticar ao parar ou reiniciar o container."
        ),
        steps=(
            "Rode os comandos que precisam de root antes da instrução USER (o build já roda como root até ali).",
            "Se o entrypoint precisa trocar de usuário em tempo de execução, use gosu ou su-exec em vez de sudo.",
            "Não instale o pacote sudo na imagem final.",
        ),
        examples=(
            Fix(
                "dockerfile",
                "Dockerfile",
                "# comandos de administração primeiro, ainda como root (sem sudo)\n"
                "RUN apt-get update \\\n"
                " && apt-get install -y --no-install-recommends curl \\\n"
                " && rm -rf /var/lib/apt/lists/*\n"
                "# depois troque para o usuário da aplicação\n"
                "USER 10001:10001",
                "dockerfile",
            ),
        ),
        verify="Procure 'sudo' no Dockerfile (não deve haver chamadas) e rode o EIGAN de novo.",
        effort="baixo",
        fix_group="iac",
        references=(_DOCKER_PRACTICES, "https://cwe.mitre.org/data/definitions/250.html"),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("docker", "privilegios"),
    ),
)

_SHELLS = r"(?:ba|z|da|k|a)?sh"
_OTHER_INTERPRETERS = r"(?:python[\d.]*|perl|ruby|php|node)"
_CURL_WORD = re.compile(r"\b(?:curl|wget)\b", re.I)
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")
_SEGMENT_SEP = re.compile(r";|&&|\n")
_RECEIVER = re.compile(
    r"\s*(?:sudo(?:\s+-\S+)*\s+)?(?:(?:/usr/bin/)?env\s+)?(?:/usr(?:/local)?)?(?:/bin/)?"
    r"(?:(?P<shell>" + _SHELLS + r")|(?P<other>" + _OTHER_INTERPRETERS + r"))(?![\w.\-])"
    r"(?P<rest>[^|;&\n]*)",
    re.I,
)
_MAX_RUN_CHARS = 100_000
_LOOPBACK = ("localhost", "127.", "[::1]", "0.0.0.0")  # nosec B104
_CURL_SUBST = re.compile(
    r"(?:\b(?:ba|z|da|k)?sh\s+(?:<\(\s*|-c\s+[\"']?\$\(\s*)|\beval\s+[\"']?\$\(\s*)"
    r"(?:curl|wget)\b[^)\n]{0,2000}\)",
    re.I,
)
_SUDO = re.compile(r"(?:^|[;&|(`]|\$\()\s*sudo(?:\s|$)", re.M)
_SUDO_WORD = re.compile(r"\bsudo\s+(?:-\S+\s+)*")
_URL = re.compile(r"https?://[^\s'\"|;&)<>]+", re.I)
_HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z_]\w*)\2")
_DIRECTIVE = re.compile(r"^#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$")
_ASSIGN = re.compile(r"""([A-Za-z_][\w.\-]*)(?:=("(?:[^"\\]|\\.)*"|'[^']*'|\S*))?""")
_DROP_PRIVS = re.compile(r"\b(?:gosu|su-exec|setpriv|runuser|s6-setuidgid)\b")
_NONROOT_MARKERS = ("nonroot", "rootless", "unprivileged")
_WINDOWS_MARKERS = ("mcr.microsoft.com/windows", "nanoserver", "servercore", "windowsservercore")
#: imagens oficiais cujo Dockerfile não troca o usuário (o processo roda como root)
_ROOT_BY_DEFAULT = frozenset(
    {
        "alpine",
        "almalinux",
        "amazonlinux",
        "busybox",
        "centos",
        "debian",
        "fedora",
        "golang",
        "httpd",
        "nginx",
        "node",
        "php",
        "python",
        "rockylinux",
        "ruby",
        "rust",
        "scratch",
        "ubuntu",
    }
)


@dataclass
class Instruction:
    """Uma instrução do Dockerfile já com as continuações e os heredocs juntados."""

    command: str
    args: str
    line: int


@dataclass
class Stage:
    """Um estágio do build (``FROM ... AS nome``) e o usuário em vigor no fim dele."""

    image: str
    alias: str
    line: int
    user: str | None = None
    user_line: int = 0
    parent: Stage | None = None
    drops_privileges: bool = False

    def effective_user(self) -> tuple[str | None, int]:
        if self.user is not None or self.parent is None:
            return self.user, self.user_line
        return self.parent.effective_user()

    def external_image(self) -> str:
        return self.parent.external_image() if self.parent is not None else self.image


# -- leitura do Dockerfile ---------------------------------------------------------------------


def parse_dockerfile(text: str) -> list[Instruction]:
    """Instruções na ordem, com a linha onde cada uma começa."""
    lines = text.splitlines()
    instructions: list[Instruction] = []
    escape = "\\"
    buffer: list[str] = []
    start = 0
    index = 0
    header = True
    while index < len(lines):
        number, stripped = index + 1, lines[index].strip()
        index += 1
        if header:
            directive = _DIRECTIVE.match(stripped)
            header = directive is not None
            if directive is not None and directive.group(1).lower() == "escape":
                escape = directive.group(2)[0]
        if not stripped or stripped.startswith("#"):
            continue  # linha vazia ou comentário (inclusive no meio de uma continuação)
        if not buffer:
            start = number
        if stripped.endswith(escape):
            buffer.append(stripped[: -len(escape)])
            continue
        buffer.append(stripped)
        continued = len(buffer) > 1
        command, args = _split_instruction(buffer)
        buffer = []
        if command in ("RUN", "COPY", "ADD") and not continued:
            args, index = _heredocs(args, lines, index)
        instructions.append(Instruction(command, args.strip(), start))
    if buffer:
        command, args = _split_instruction(buffer)
        instructions.append(Instruction(command, args.strip(), start))
    return instructions


def _split_instruction(parts: list[str]) -> tuple[str, str]:
    """``["RUN a ", "b"]`` -> (``RUN``, ``a b``)."""
    words = " ".join(part.strip() for part in parts if part.strip()).split(None, 1)
    if not words:
        return "", ""
    return words[0].upper(), words[1] if len(words) > 1 else ""


def _heredocs(args: str, lines: list[str], index: int) -> tuple[str, int]:
    """Junta o corpo dos heredocs (``RUN <<EOF`` ... ``EOF``) aos argumentos da instrução."""
    for _dash, _quote, word in _HEREDOC.findall(args):
        end = next((i for i in range(index, len(lines)) if lines[i].strip() == word), None)
        if end is None:
            break  # sem terminador: era só um "<<" do shell
        args = args + "\n" + "\n".join(lines[index:end])
        index = end + 1
    return args, index


# -- regras ---------------------------------------------------------------------------------


def check_dockerfile(text: str) -> IacReport:
    report = IacReport()
    stages: list[Stage] = []
    instructions = parse_dockerfile(text)
    last_from = max((i for i, it in enumerate(instructions) if it.command == "FROM"), default=-1)
    for index, item in enumerate(instructions):
        if item.command == "FROM":
            stage = _stage(item, stages)
            stages.append(stage)
            if stage.parent is None:
                report.add(_unpinned(stage))
            continue
        if item.command == "USER" and stages:
            stages[-1].user = item.args.split()[0] if item.args.split() else None
            stages[-1].user_line = item.line
        elif item.command == "ADD":
            report.issues.extend(_add_remote(item))
        elif item.command == "RUN":
            report.issues.extend(_run(item))
        elif item.command in ("ENV", "ARG"):
            report.issues.extend(_secrets(item, final_stage=index > last_from))
        if stages and item.command in ("RUN", "ENTRYPOINT", "CMD", "COPY"):
            if _DROP_PRIVS.search(item.args):
                stages[-1].drops_privileges = True
    if stages:
        _root(stages[-1], report)
    return report


def _stage(item: Instruction, previous: list[Stage]) -> Stage:
    words = [w for w in item.args.split() if not w.startswith("--")]
    image = words[0] if words else ""
    alias = words[2].lower() if len(words) >= 3 and words[1].lower() == "as" else ""
    parent = next((s for s in reversed(previous) if s.alias and s.alias == image.lower()), None)
    return Stage(image, alias, item.line, parent=parent)


def _unpinned(stage: Stage) -> IacIssue | None:
    image = stage.image
    if not image or image.lower() == "scratch":
        return None
    problem = image_tag_issue(image)
    if problem is None:
        return None
    shown = image if problem == "latest" else f"{image} (sem tag = latest)"
    return IacIssue(
        UNPINNED,
        stage.line,
        f"Imagem base sem versão fixa: {image}",
        f"FROM {shown}",
        discriminator=f"FROM {image}",
        details={"imagem": image},
        fix=f"FROM {image.rsplit(':', 1)[0] if problem == 'latest' else image}:<versão>@sha256:<digest>",
    )


def _root(stage: Stage, report: IacReport) -> None:
    user, user_line = stage.effective_user()
    external = stage.external_image().lower()
    if any(marker in external for marker in _WINDOWS_MARKERS):
        return  # contêiner Windows: usuários ContainerUser/ContainerAdministrator (fora do escopo)
    if user is not None and user.split(":")[0].lower() not in ("root", "0"):
        if "$" not in user:
            report.strength(
                "code.iac.usuario", f"A imagem final roda com o usuário '{user}' (USER)"
            )
        return
    if user is None and any(marker in external for marker in _NONROOT_MARKERS):
        return  # imagem base já roda sem privilégios (distroless :nonroot, rootless...)
    details: dict[str, object] = {"imagem_base": stage.external_image()}
    severity, confidence = None, Confidence.CONFIRMED
    if user is None:
        known = external.rsplit("/", 1)[-1].split(":")[0].split("@")[0] in _ROOT_BY_DEFAULT
        confidence = Confidence.FIRM if known else Confidence.TENTATIVE
        title = "Container roda como root (sem instrução USER)"
        evidence = (
            f"O último estágio (FROM {stage.image}, linha {stage.line}) não define USER: "
            "o processo principal roda como root (UID 0)."
        )
        line, discriminator = stage.line, "sem-user"
    else:
        title = f"Container roda como root (USER {user})"
        evidence = f"USER {user} (linha {user_line}) é o último usuário da imagem final."
        line, discriminator = user_line, "user-root"
    if stage.drops_privileges:
        severity, confidence = Severity.LOW, Confidence.TENTATIVE
        details["observacao"] = (
            "o Dockerfile usa gosu/su-exec/setpriv: o entrypoint pode trocar de usuário; confira"
        )
    report.add(
        IacIssue(
            ROOT,
            line,
            title,
            evidence,
            severity=severity,
            confidence=confidence,
            discriminator=discriminator,
            details=details,
            fix="# no fim do Dockerfile (o UID não precisa existir em /etc/passwd)\nUSER 10001:10001",
        )
    )


def _add_remote(item: Instruction) -> list[IacIssue]:
    words = _words(item.args)
    if any(w.startswith("--checksum") for w in words):
        return []
    sources = [w for w in words if not w.startswith("--")][:-1]
    return [
        IacIssue(
            ADD_REMOTE,
            item.line,
            "ADD baixa arquivo remoto sem verificar a integridade",
            f"ADD {scrub(src)}",
            severity=_insecure(src),
            discriminator=scrub(src),
            details={"url": scrub(src)},
            fix=f"ADD --checksum=sha256:<hash-publicado> {scrub(src)} <destino>",
        )
        for src in sources
        if _URL.match(src) and not _is_git_source(src)
    ]


def _words(args: str) -> list[str]:
    """Argumentos na forma de shell (``a b c``) ou JSON (``["a", "b", "c"]``)."""
    text = args.strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            return [str(part) for part in parsed]
    return text.split()


def _is_git_source(url: str) -> bool:
    lowered = url.lower()
    return lowered.endswith(".git") or ".git#" in lowered


def _curl_pipe_commands(args: str) -> list[str]:
    """Trechos ``curl ... | sh`` (tempo linear: um segmento por vez, sem retrocesso)."""
    found: list[str] = []
    text = args[:_MAX_RUN_CHARS]
    start = 0
    for sep in (*_SEGMENT_SEP.finditer(text), None):
        end = sep.start() if sep else len(text)
        segment = text[start:end]
        start = sep.end() if sep else end
        word = _CURL_WORD.search(segment)
        if word is None:
            continue
        for pipe in _PIPE.finditer(segment, word.end()):
            recv = _RECEIVER.match(segment, pipe.end())
            if recv is None:
                continue
            tokens = recv.group("rest").split()
            if recv.group("other") and tokens not in ([], ["-"]):
                continue  # ``python -m json.tool``, ``node -e``: o script não vem da rede
            found.append(segment[word.start() : recv.end()].strip())
            break
    return found


def _is_loopback(url: str) -> bool:
    host = url.split("://", 1)[-1].lower().split("@")[-1]
    return host.startswith(_LOOPBACK)


def _insecure(url: str) -> Severity | None:
    ok = url.lower().startswith("http://") and not _is_loopback(url)
    return Severity.HIGH if ok else None


def _run(item: Instruction) -> list[IacIssue]:
    issues: list[IacIssue] = []
    commands = [*_curl_pipe_commands(item.args)]
    commands += [m.group(0) for m in _CURL_SUBST.finditer(item.args[:_MAX_RUN_CHARS])]
    for command in commands[:1]:  # um achado por instrução basta
        command = scrub(command)
        url = _URL.search(command)
        target = url.group(0) if url else ""
        issues.append(
            IacIssue(
                CURL_SH,
                item.line,
                "Script baixado da Internet e executado sem verificação",
                f"RUN {command[:200]}",
                severity=_insecure(target),
                discriminator=target or f"linha {item.line}",
                details={"url": target} if target else {},
                fix=f"RUN curl -fsSLo /tmp/instalador {target or '<URL>'} \\\n"
                ' && echo "<sha256-publicado-pelo-fornecedor>  /tmp/instalador" | sha256sum -c - \\\n'
                " && sh /tmp/instalador",
            )
        )
    if _SUDO.search(item.args):
        shown = scrub(item.args)
        issues.append(
            IacIssue(
                SUDO,
                item.line,
                "Uso de sudo no Dockerfile",
                f"RUN {shown[:200]}",
                discriminator=f"sudo@{item.line}",
                fix="# antes da instrução USER o build já roda como root\n"
                f"RUN {_SUDO_WORD.sub('', shown)[:200]}",
            )
        )
    return issues


def _secrets(item: Instruction, *, final_stage: bool = True) -> list[IacIssue]:
    """Segredo literal em ENV/ARG (alta) ou segredo que chega por ARG/variável (média).

    O valor real de um ``ARG`` com nome de segredo chega por ``--build-arg`` e fica
    no histórico da imagem; ``ENV X=$Y`` grava o valor recebido. Em estágios
    intermediários o valor recebido não vai para a imagem final, mas o literal
    continua escrito no repositório. Flags (``yes``, ``true``) e caminhos não são segredos.
    """
    issues: list[IacIssue] = []
    for name, value in _assignments(item):
        text = (value or "").strip().strip("'\"")
        if not is_secret_name(name):
            if text and url_password(text):
                issues.append(_url_secret_issue(item, name, text))
            continue
        details: dict[str, object] = {"variavel": name, "instrucao": item.command}
        if text and literal_secret(text):
            evidence = f"{item.command} {name}={mask_secret(text)}"
            severity = Severity.HIGH
            title = f"Segredo gravado na imagem ({item.command} {name})"
            confidence = Confidence.TENTATIVE if weak_secret(text) else Confidence.FIRM
            details["valor"] = mask_secret(text)
            if weak_secret(text):
                details["senha_fraca"] = "valor padrão/conhecido (fácil de adivinhar)"
        elif final_stage and _passes_secret(item.command, text):
            shown = "" if not text else "=<referência a variável>" if "$" in text else "=<exemplo>"
            evidence = f"{item.command} {name}{shown}"
            severity, confidence = Severity.MEDIUM, Confidence.TENTATIVE
            title = f"Segredo passado por {item.command} fica guardado na imagem ({name})"
        else:
            continue
        issues.append(
            IacIssue(
                SECRET,
                item.line,
                title,
                evidence,
                severity=severity,
                confidence=confidence,
                discriminator=f"{item.command}:{name}",
                details=details,
                fix=f"RUN --mount=type=secret,id={name.lower()},env={name} <comando>",
            )
        )
    return issues


def _passes_secret(command: str, value: str) -> bool:
    """``ARG TOKEN`` (sem padrão ou com exemplo) e ``ENV X=$Y`` levam o segredo para a imagem."""
    if value.lower() in ("true", "false", "yes", "no", "on", "off", "0", "1"):
        return False  # flag, não segredo (ex.: MYSQL_ALLOW_EMPTY_PASSWORD=yes)
    if command == "ARG":
        return not value.startswith(("/", "./", "~/"))
    return "$" in value


def _assignments(item: Instruction) -> list[tuple[str, str | None]]:
    """``ENV A=1 B=2`` / ``ENV A 1`` (forma antiga) / ``ARG A`` / ``ARG A=padrao``."""
    args = item.args
    if item.command == "ENV" and "=" not in args.split(" ", 1)[0]:
        name, _, value = args.partition(" ")
        return [(name, value)] if name else []
    return [(match.group(1), match.group(2)) for match in _ASSIGN.finditer(args)]


def _url_secret_issue(item: Instruction, name: str, text: str) -> IacIssue:
    shown = mask_url_password(text)
    return IacIssue(
        SECRET,
        item.line,
        f"Senha em texto puro na URL de conexão ({item.command} {name})",
        f"{item.command} {name}={shown}",
        severity=Severity.HIGH,
        discriminator=f"{item.command}:{name}",
        details={"variavel": name, "instrucao": item.command, "valor": shown},
        fix=f"RUN --mount=type=secret,id={name.lower()},env={name} <comando>",
    )
