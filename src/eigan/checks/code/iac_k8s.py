"""Regras para manifestos Kubernetes: Pods e tudo o que cria Pods, em um ou vários documentos.

Baseadas nos Pod Security Standards
(https://kubernetes.io/docs/concepts/security/pod-security-standards/). Três cuidados
evitam falso positivo nas regras de "campo ausente":

- modelos de Helm (``{{ ... }}``): o valor pode vir de ``values.yaml``, então só o
  que está escrito de forma explícita conta;
- patches do Kustomize: um container sem ``image`` é pedaço de um manifesto, não um
  container completo;
- Pods Windows (``spec.os.name: windows``): os controles exclusivos de Linux não se aplicam.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ...core.models import Confidence, Severity
from .iac_common import (
    CAPABILITIES,
    DOCKER_SOCK,
    ESCALATION,
    HOST_NS,
    HOSTPATH,
    NO_LIMITS,
    PRIVILEGED,
    ROOT,
    SECRET,
    UNPINNED,
    WRITABLE_FS,
    IacIssue,
    IacReport,
    caps_severity,
    harmless_host_path,
    image_tag_issue,
    is_runtime_socket,
    is_secret_name,
    literal_secret,
    mask_secret,
    mask_url_password,
    normalize_cap,
    risky_caps,
    sensitive_host_path,
    url_password,
    weak_secret,
)
from .yamlish import Node, blank_template_actions, parse_documents

#: onde fica o ``spec`` do Pod em cada tipo de recurso (Pod, Deployment, CronJob, PodTemplate...)
_POD_PATHS = (
    ("spec",),
    ("spec", "template", "spec"),
    ("spec", "jobTemplate", "spec", "template", "spec"),
    ("template", "spec"),
)
_CONTAINER_GROUPS = ("containers", "initContainers", "ephemeralContainers")
_NAMESPACES = {
    "hostNetwork": "a rede",
    "hostPID": "os processos",
    "hostIPC": "a memória compartilhada (IPC)",
}
_LIMIT_RANGE = re.compile(r"(?m)^kind:\s*[\"']?LimitRange\b")
_PSA_LEVELS = ("baseline", "restricted")
_EMPTY = Node({}, 0)


def check_kubernetes(text: str, *, limit_ranges: frozenset[str] = frozenset()) -> IacReport:
    """Analisa o arquivo. ``limit_ranges``: namespaces com LimitRange (limite padrão de memória)."""
    report = IacReport()
    template = "{{" in text
    source = blank_template_actions(text) if template else text
    for document in parse_documents(source):
        for resource in _resources(document):
            _namespace_policy(report, resource)
            spec = _pod_spec(resource)
            if spec is not None:
                _Pod(report, resource, spec, template, limit_ranges).analyze()
    return report


def limit_range_namespaces(text: str) -> set[str]:
    """Namespaces (``""`` = não declarado) que têm um LimitRange neste arquivo."""
    if _LIMIT_RANGE.search(text) is None:
        return set()
    return {
        resource.text("metadata", "namespace")
        for document in parse_documents(blank_template_actions(text))
        for resource in _resources(document)
        if resource.text("kind") == "LimitRange"
    }


def _resources(document: Node) -> list[Node]:
    """O próprio documento ou os ``items`` de um ``kind: List``."""
    if not document.is_map:
        return []
    if document.text("kind").endswith("List") and document.get("items") is not None:
        return [item for item in document.seq("items") if item.is_map]
    return [document]


def _pod_spec(resource: Node) -> Node | None:
    for path in _POD_PATHS:
        spec = resource.get(*path)
        if spec is not None and spec.is_map and spec.seq("containers"):
            return spec
    return None


def _namespace_policy(report: IacReport, resource: Node) -> None:
    if resource.text("kind") != "Namespace":
        return
    level = resource.text("metadata", "labels", "pod-security.kubernetes.io/enforce").lower()
    if level in _PSA_LEVELS:
        name = resource.text("metadata", "name")
        report.strength(
            "code.iac.k8s_pod_security",
            f"Namespace '{name}' aplica o perfil '{level}' dos Pod Security Standards",
        )


@dataclass
class _Pod:
    """Um Pod (ou modelo de Pod) e as regras que se aplicam a ele."""

    report: IacReport
    resource: Node
    spec: Node
    template: bool
    limit_ranges: frozenset[str]

    @property
    def address(self) -> str:
        kind = self.resource.text("kind") or "Pod"
        name = self.resource.text("metadata", "name") or "?"
        namespace = self.resource.text("metadata", "namespace")
        return f"{kind}/{namespace}/{name}" if namespace else f"{kind}/{name}"

    @property
    def windows(self) -> bool:
        selector = self.spec.get("nodeSelector") or _EMPTY
        names = (
            self.spec.text("os", "name"),
            selector.text("kubernetes.io/os"),
            selector.text("beta.kubernetes.io/os"),
        )
        return any(name.lower() == "windows" for name in names)

    @property
    def security(self) -> Node:
        return self.spec.get("securityContext") or _EMPTY

    def analyze(self) -> None:
        self._host_namespaces()
        self._volumes()
        containers = self._containers()
        if self.spec.flag("securityContext", "windowsOptions", "hostProcess"):
            self.host_process(self.spec.line_of("securityContext"), self.address)
        results = [_Container(self, node, group).analyze() for group, node in containers]
        self._strengths([result for result in results if result is not None])

    def _containers(self) -> list[tuple[str, Node]]:
        return [
            (group, node)
            for group in _CONTAINER_GROUPS
            for node in self.spec.seq(group)
            if node.is_map
        ]

    def issue(
        self,
        finding: str,
        line: int,
        title: str,
        evidence: str,
        discriminator: str,
        fix: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        container: str = "",
        **details: Any,
    ) -> None:
        details["recurso"] = self.address
        if container:
            details["container"] = container
        self.report.add(
            IacIssue(
                finding,
                line,
                title,
                evidence,
                severity=severity,
                confidence=confidence,
                discriminator=f"{self.address}:{discriminator}",
                details=details,
                fix=fix,
            )
        )

    def _host_namespaces(self) -> None:
        for key, label in _NAMESPACES.items():
            if self.spec.flag(key):
                self.issue(
                    HOST_NS,
                    self.spec.line_of(key),
                    f"{self.address} compartilha {label} com o nó ({key}: true)",
                    f"{self.address}: spec.{key}: true",
                    key,
                    f"spec:\n  {key}: false",
                    severity=Severity.MEDIUM if key == "hostNetwork" else Severity.HIGH,
                )

    def host_process(self, line: int, where: str) -> None:
        self.issue(
            PRIVILEGED,
            line,
            f"{where} usa contêiner Windows HostProcess",
            f"{where}: securityContext.windowsOptions.hostProcess: true",
            f"{where}:hostProcess",
            "securityContext:\n  windowsOptions:\n    hostProcess: false",
        )

    # -- volumes -------------------------------------------------------------------------
    def _volumes(self) -> None:
        for volume in self.spec.seq("volumes"):
            path = volume.text("hostPath", "path").strip()
            if volume.get("hostPath") is not None:
                self._host_path(volume, path)

    def _mounts(self, name: str) -> list[Node]:
        return [
            mount
            for _group, container in self._containers()
            for mount in container.seq("volumeMounts")
            if mount.text("name") == name
        ]

    def _host_path(self, volume: Node, path: str) -> None:
        name = volume.text("name")
        line = volume.line
        mounts = self._mounts(name)
        read_only = bool(mounts) and all(mount.flag("readOnly") is True for mount in mounts)
        if is_runtime_socket(path):
            self.issue(
                DOCKER_SOCK,
                line,
                f"{self.address} monta o socket do runtime de containers ({path})",
                f"{self.address}: volumes[{name}].hostPath.path: {path}",
                f"hostPath:{path}",
                "# remova o volume hostPath do socket e o volumeMount correspondente",
                caminho=path,
            )
            return
        if harmless_host_path(path) and read_only:
            return  # fuso horário, certificados de CA...
        self._report_host_path(name, line, path, read_only, bool(mounts))

    def _report_host_path(
        self, name: str, line: int, path: str, read_only: bool, mounted: bool
    ) -> None:
        if harmless_host_path(path):
            severity = Severity.LOW
        elif sensitive_host_path(path):
            severity = Severity.MEDIUM if read_only else Severity.HIGH
        else:
            severity = Severity.LOW if read_only else Severity.MEDIUM
        self.issue(
            HOSTPATH,
            line,
            f"{self.address} monta um diretório do nó ({path or '?'})",
            f"{self.address}: volumes[{name}].hostPath.path: {path or '?'}"
            + (" (somente leitura)" if read_only and mounted else ""),
            f"hostPath:{path}",
            "volumes:\n"
            f"  - name: {name or 'dados'}\n"
            "    persistentVolumeClaim:\n"
            f"      claimName: {name or 'dados'}",
            severity=severity,
            confidence=Confidence.TENTATIVE if "{{" in path or not path else Confidence.CONFIRMED,
            caminho=path,
            somente_leitura=read_only,
            montado=mounted,
        )

    # -- pontos fortes ------------------------------------------------------------------
    def _strengths(self, results: list[_Result]) -> None:
        if not results:
            return
        where = self.address
        if all(result.non_root for result in results):
            self.report.strength("code.iac.k8s_nao_root", f"{where}: containers rodam sem ser root")
        if all(result.no_escalation for result in results):
            self.report.strength(
                "code.iac.k8s_sem_escalacao", f"{where}: allowPrivilegeEscalation: false em todos"
            )
        if all(result.read_only for result in results):
            self.report.strength(
                "code.iac.k8s_fs_somente_leitura", f"{where}: readOnlyRootFilesystem: true em todos"
            )
        if all(result.drops_all for result in results):
            self.report.strength(
                "code.iac.k8s_capabilities", f"{where}: containers removem todas as capabilities"
            )
        if all(result.has_limits for result in results):
            self.report.strength("code.iac.k8s_limites", f"{where}: limite de memória em todos")


@dataclass
class _Result:
    """O que um container já cumpre (só vira ponto forte quando todos do Pod cumprem)."""

    non_root: bool
    no_escalation: bool
    read_only: bool
    drops_all: bool
    has_limits: bool


@dataclass
class _Container:
    pod: _Pod
    node: Node
    group: str

    @property
    def name(self) -> str:
        return self.node.text("name") or "?"

    @property
    def security(self) -> Node:
        return self.node.get("securityContext") or _EMPTY

    @property
    def complete(self) -> bool:
        """Dá para concluir pela ausência de um campo? (nem modelo de Helm, nem patch)."""
        return not self.pod.template and self.node.has("image")

    @property
    def tag(self) -> str:
        return f"{self.pod.address} (container {self.name})"

    def analyze(self) -> _Result | None:
        linux = not self.pod.windows
        privileged = self._privileged()
        self._image()
        self._secrets()
        has_limits = self._limits()
        if not linux:
            return None
        non_root = self._root()
        no_escalation = self._escalation(privileged)
        drops_all = self._capabilities()
        read_only = self._writable()
        if not self.complete:
            return None
        return _Result(non_root, no_escalation, read_only, drops_all, has_limits)

    def _privileged(self) -> bool:
        security = self.security
        if security.flag("windowsOptions", "hostProcess"):
            self.pod.host_process(security.line_of("windowsOptions"), self.tag)
        if not security.flag("privileged"):
            return False
        self.pod.issue(
            PRIVILEGED,
            security.line_of("privileged"),
            f"{self.tag} roda com privileged: true",
            f"{self.tag}: securityContext.privileged: true",
            f"{self.name}:privileged",
            "securityContext:\n"
            "  privileged: false\n"
            "  allowPrivilegeEscalation: false\n"
            "  capabilities:\n"
            "    drop: [ALL]",
            container=self.name,
        )
        return True

    def _escalation(self, privileged: bool) -> bool:
        """Campo ausente vale ``true`` (padrão documentado), exceto no privilegiado, já reportado."""
        fix = "securityContext:\n  allowPrivilegeEscalation: false"
        security = self.security
        value = security.flag("allowPrivilegeEscalation")
        if value is False:
            return True
        if value is True:
            self.pod.issue(
                ESCALATION,
                security.line_of("allowPrivilegeEscalation"),
                f"{self.tag} permite escalação de privilégio",
                f"{self.tag}: securityContext.allowPrivilegeEscalation: true",
                f"{self.name}:allowPrivilegeEscalation",
                fix,
                container=self.name,
            )
        elif self.complete and not privileged and not security.has("allowPrivilegeEscalation"):
            self.pod.issue(
                ESCALATION,
                self.node.line,
                f"{self.tag} não desliga a escalação de privilégio",
                f"{self.tag}: allowPrivilegeEscalation não definido (o padrão é true)",
                f"{self.name}:allowPrivilegeEscalation",
                fix,
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                container=self.name,
            )
        return False

    def _root(self) -> bool:
        """``True`` quando a configuração garante um usuário sem privilégios."""
        security, pod_security = self.security, self.pod.security
        owner = security if security.has("runAsUser") else pod_security
        user = owner.text("runAsUser").strip()
        non_root = security.flag("runAsNonRoot")
        if non_root is None:
            non_root = pod_security.flag("runAsNonRoot")
        fix = "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001"
        if user == "0":
            self.pod.issue(
                ROOT,
                owner.line_of("runAsUser") or self.node.line,
                f"{self.tag} roda como root (runAsUser: 0)",
                f"{self.tag}: securityContext.runAsUser: 0",
                f"{self.name}:runAsUser",
                fix,
                container=self.name,
            )
            return False
        if user or non_root is True:
            return user.isdigit() or non_root is True
        if non_root is False:
            self._may_run_as_root(
                "runAsNonRoot: false", Severity.MEDIUM, self._root_line("runAsNonRoot"), fix
            )
        elif self.complete and not (
            security.has("runAsNonRoot") or pod_security.has("runAsNonRoot")
        ):
            self._may_run_as_root("runAsNonRoot ausente", Severity.LOW, self.node.line, fix)
        return False

    def _root_line(self, key: str) -> int:
        owner = self.security if self.security.has(key) else self.pod.security
        return owner.line_of(key) or self.node.line

    def _may_run_as_root(self, reason: str, severity: Severity, line: int, fix: str) -> None:
        """A imagem decide o usuário: é indício, e o ``USER`` do Dockerfile pode resolver."""
        self.pod.issue(
            ROOT,
            line,
            f"{self.tag} não garante rodar sem ser root ({reason})",
            f"{self.tag}: {reason} e sem runAsUser (quem decide o usuário é a imagem)",
            f"{self.name}:runAsNonRoot",
            fix,
            severity=severity,
            confidence=Confidence.TENTATIVE,
            container=self.name,
        )

    def _capabilities(self) -> bool:
        security = self.security
        added = [node.text() for node in security.seq("capabilities", "add")]
        dropped = [normalize_cap(node.text()) for node in security.seq("capabilities", "drop")]
        caps = risky_caps(added)
        if caps:
            line = (security.get("capabilities") or _EMPTY).line_of("add") or self.node.line
            self.pod.issue(
                CAPABILITIES,
                line,
                f"{self.tag} recebe capabilities perigosas: {', '.join(caps)}",
                f"{self.tag}: securityContext.capabilities.add: {caps}",
                f"{self.name}:capabilities",
                "securityContext:\n  capabilities:\n    drop: [ALL]\n    add: [NET_BIND_SERVICE]   # só se precisar",
                severity=caps_severity(caps),
                container=self.name,
                capabilities=caps,
            )
        return "ALL" in dropped and not caps

    def _image(self) -> None:
        image = self.node.text("image")
        problem = image_tag_issue(image) if image else None
        if problem is None:
            return
        base = image.rsplit(":", 1)[0] if problem == "latest" else image
        self.pod.issue(
            UNPINNED,
            self.node.line_of("image"),
            f"{self.tag} usa imagem sem versão fixa: {image}",
            f"{self.tag}: image: {image}" + (" (sem tag = latest)" if problem == "sem-tag" else ""),
            f"{self.name}:{image}",
            f"image: {base}:<versão>@sha256:<digest>",
            confidence=Confidence.FIRM,
            container=self.name,
            imagem=image,
        )

    def _limits(self) -> bool:
        """Limite de memória (um LimitRange do mesmo namespace dá o padrão)."""
        if self.node.text("resources", "limits", "memory"):
            return True
        namespace = self.pod.resource.text("metadata", "namespace")
        ranges = self.pod.limit_ranges
        covered = namespace in ranges or "" in ranges or (not namespace and bool(ranges))
        if self.group == "ephemeralContainers" or not self.complete or covered:
            return False
        self.pod.issue(
            NO_LIMITS,
            self.node.line,
            f"{self.tag} não define limite de memória",
            f"{self.tag}: resources.limits.memory ausente",
            f"{self.name}:limits",
            "resources:\n  requests:\n    cpu: 100m\n    memory: 128Mi\n  limits:\n    memory: 256Mi",
            confidence=Confidence.FIRM,
            container=self.name,
        )
        return False

    def _writable(self) -> bool:
        security = self.security
        value = security.flag("readOnlyRootFilesystem")
        if value is False:
            self.pod.issue(
                WRITABLE_FS,
                security.line_of("readOnlyRootFilesystem"),
                f"{self.tag} deixa o sistema de arquivos gravável",
                f"{self.tag}: securityContext.readOnlyRootFilesystem: false",
                f"{self.name}:readOnlyRootFilesystem",
                "securityContext:\n  readOnlyRootFilesystem: true\n"
                "# grave só em volumes emptyDir (ex.: montado em /tmp)",
                container=self.name,
            )
        return value is True

    def _secrets(self) -> None:
        for entry in self.node.seq("env"):
            key, value = entry.text("name"), entry.text("value")
            if not key or not value:
                continue
            if is_secret_name(key) and literal_secret(value):
                self._secret(entry, key, mask_secret(value), weak_secret(value))
            elif url_password(value) is not None:
                self._secret(entry, key, mask_url_password(value), False)

    def _secret(self, entry: Node, key: str, shown: str, weak: bool) -> None:
        details: dict[str, Any] = {"variavel": key, "valor": shown}
        if weak:
            details["senha_fraca"] = "valor padrão/conhecido (fácil de adivinhar)"
        self.pod.issue(
            SECRET,
            entry.line_of("value"),
            f"Segredo em texto puro no manifesto ({self.tag}: {key})",
            f"{self.tag}: env {key}={shown}",
            f"{self.name}:{key}",
            f"- name: {key}\n"
            "  valueFrom:\n"
            "    secretKeyRef:\n"
            "      name: app-credenciais\n"
            f"      key: {key.lower().replace('_', '-')}",
            severity=Severity.HIGH,
            confidence=Confidence.TENTATIVE if weak else Confidence.FIRM,
            container=self.name,
            **details,
        )
