"""IaC: manifestos Kubernetes, inclusive YAML com vários documentos."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_iac import ids, lines_of, of, scan

from eigan.checks.code.iac_common import (
    CAPABILITIES,
    ESCALATION,
    HOST_NS,
    HOSTPATH,
    NO_LIMITS,
    PRIVILEGED,
    ROOT,
    UNPINNED,
    WRITABLE_FS,
)

HARDENED = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: app
          image: registry.example.test/web:1.4.2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              memory: 256Mi
              cpu: 500m
"""

PRIV = "      securityContext:\n        privileged: true\n"


def pod(container_extra: str = "", pod_extra: str = "", image: str = "web:1.0") -> str:
    """Pod mínimo; as strings extras já vêm com a indentação certa."""
    return (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
        f"{pod_extra}"
        "  containers:\n"
        f"    - name: c\n      image: {image}\n{container_extra}"
    )


def k8s(tmp_path: Path, text: str, name: str = "k8s/app.yaml"):
    return scan(tmp_path, {name: text})


def test_manifesto_endurecido_nao_gera_achados_e_vira_ponto_forte(tmp_path: Path) -> None:
    out = k8s(tmp_path, HARDENED)
    assert ids(out) == set()
    assert out.passed


def test_privileged_true(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod(PRIV))
    assert of(out, PRIVILEGED)
    assert of(out, PRIVILEGED)[0].asset == "k8s/app.yaml"
    assert lines_of(out, PRIVILEGED) == [10]


def test_privileged_false_nao_alerta(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod("      securityContext:\n        privileged: false\n"))
    assert not of(out, PRIVILEGED)


@pytest.mark.parametrize("campo", ["hostNetwork", "hostPID", "hostIPC"])
def test_namespaces_do_host(tmp_path: Path, campo: str) -> None:
    out = k8s(tmp_path, pod(pod_extra=f"  {campo}: true\n"))
    assert of(out, HOST_NS)


def test_host_false_nao_alerta(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod(pod_extra="  hostNetwork: false\n"))
    assert not of(out, HOST_NS)


def test_allow_privilege_escalation_ausente_ou_true(tmp_path: Path) -> None:
    ausente = k8s(tmp_path, pod())
    explicito = scan(
        tmp_path / "b",
        {"a.yaml": pod("      securityContext:\n        allowPrivilegeEscalation: true\n")},
    )
    fechado = scan(
        tmp_path / "c",
        {"a.yaml": pod("      securityContext:\n        allowPrivilegeEscalation: false\n")},
    )
    assert of(ausente, ESCALATION)
    assert of(explicito, ESCALATION)
    assert not of(fechado, ESCALATION)


def test_run_as_non_root_ausente_e_run_as_user_zero(tmp_path: Path) -> None:
    ausente = k8s(tmp_path, pod())
    zero = scan(
        tmp_path / "b",
        {"a.yaml": pod("      securityContext:\n        runAsUser: 0\n")},
    )
    ok = scan(
        tmp_path / "c",
        {"a.yaml": pod("      securityContext:\n        runAsNonRoot: true\n")},
    )
    assert of(ausente, ROOT)
    assert of(zero, ROOT)
    assert not of(ok, ROOT)


def test_run_as_non_root_no_nivel_do_pod_vale_para_containers(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod(pod_extra="  securityContext:\n    runAsNonRoot: true\n"))
    assert not of(out, ROOT)


@pytest.mark.parametrize("cap", ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE"])
def test_capabilities_perigosas(tmp_path: Path, cap: str) -> None:
    extra = f"      securityContext:\n        capabilities:\n          add: [{cap}]\n"
    assert of(k8s(tmp_path, pod(extra)), CAPABILITIES)


def test_capability_inofensiva_nao_alerta(tmp_path: Path) -> None:
    extra = "      securityContext:\n        capabilities:\n          add: [NET_BIND_SERVICE]\n"
    assert not of(k8s(tmp_path, pod(extra)), CAPABILITIES)


def test_hostpath_sensivel(tmp_path: Path) -> None:
    text = pod(
        "      volumeMounts:\n        - name: v\n          mountPath: /host\n",
        pod_extra="  volumes:\n    - name: v\n      hostPath:\n        path: /\n",
    )
    assert of(k8s(tmp_path, text), HOSTPATH)


def test_volume_emptydir_nao_e_hostpath(tmp_path: Path) -> None:
    text = pod(pod_extra="  volumes:\n    - name: v\n      emptyDir: {}\n")
    assert not of(k8s(tmp_path, text), HOSTPATH)


@pytest.mark.parametrize("image", ["nginx:latest", "nginx"])
def test_imagem_latest_ou_sem_tag(tmp_path: Path, image: str) -> None:
    assert of(k8s(tmp_path, pod(image=image)), UNPINNED)


def test_imagem_com_digest_e_aceita(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod(image="nginx@sha256:" + "b" * 64))
    assert not of(out, UNPINNED)


def test_sem_limites_e_informativo(tmp_path: Path) -> None:
    found = of(k8s(tmp_path, pod()), NO_LIMITS)
    assert found
    assert found[0].severity.name == "INFO"


def test_com_limites_nao_alerta(tmp_path: Path) -> None:
    extra = "      resources:\n        limits:\n          memory: 128Mi\n"
    assert not of(k8s(tmp_path, pod(extra)), NO_LIMITS)


def test_sistema_de_arquivos_gravavel(tmp_path: Path) -> None:
    extra = "      securityContext:\n        readOnlyRootFilesystem: false\n"
    assert of(k8s(tmp_path, pod(extra)), WRITABLE_FS)
    ok = scan(
        tmp_path / "b",
        {"a.yaml": pod("      securityContext:\n        readOnlyRootFilesystem: true\n")},
    )
    assert not of(ok, WRITABLE_FS)


def test_multi_documento_aponta_cada_recurso(tmp_path: Path) -> None:
    segundo = pod(PRIV).replace("name: p", "name: q")
    out = k8s(tmp_path, pod(PRIV) + "---\n" + segundo)
    found = of(out, PRIVILEGED)
    assert len(found) == 2
    assert len({f.discriminator for f in found}) == 2
    assert len(set(lines_of(out, PRIVILEGED))) == 2


def test_deployment_e_cronjob_no_mesmo_arquivo(tmp_path: Path) -> None:
    deploy = HARDENED.replace("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true")
    cron = (
        "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: j\nspec:\n"
        "  jobTemplate:\n    spec:\n      template:\n        spec:\n          hostPID: true\n"
        "          containers:\n            - name: c\n              image: busybox:1.36\n"
    )
    out = k8s(tmp_path, deploy + "---\n" + cron)
    assert of(out, ESCALATION)
    assert of(out, HOST_NS)


def test_yaml_que_nao_e_kubernetes_e_ignorado(tmp_path: Path) -> None:
    text = "name: ci\non: push\njobs:\n  build:\n    privileged: true\n    hostNetwork: true\n"
    assert not scan(tmp_path, {"config/ci.yaml": text}).findings


def test_modelo_helm_com_chaves_nao_quebra(tmp_path: Path) -> None:
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n"
        "  containers:\n    - name: c\n      image: {{ .Values.image }}\n"
    )
    out = scan(tmp_path, {"chart/templates/pod.yaml": text})
    assert not of(out, UNPINNED)


def test_correcao_presente(tmp_path: Path) -> None:
    out = k8s(tmp_path, pod(PRIV))
    assert out.findings
    for f in out.findings:
        assert f.details["correcao"].strip()
        assert f.details["tipo"] == "Kubernetes"


# -- regressões da revisão ----------------------------------------------------------------------


def _deploy(extra_env: str = "", namespace: str = "", volumes: str = "") -> str:
    ns = f"  namespace: {namespace}\n" if namespace else ""
    return (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
        f"{ns}spec:\n  template:\n    spec:\n{volumes}      containers:\n"
        "        - name: app\n          image: r.test/web:1.0\n"
        "          securityContext:\n            privileged: true\n"
        f"{extra_env}"
    )


def test_referencia_de_variavel_do_k8s_nao_e_segredo(tmp_path: Path) -> None:
    env = (
        "          env:\n"
        '            - name: DB_PASSWORD\n              value: "$(POSTGRES_PASSWORD)"\n'
        "            - name: TOKEN_EXPIRY_SECONDS\n              value: '3600'\n"
        "            - name: PASSWORD_AUTH\n              value: disabled\n"
    )
    out = scan(tmp_path, {"k8s/d.yaml": _deploy(env)})
    assert "code.iac.segredo_em_texto" not in ids(out)


def test_segredo_literal_em_env_do_k8s_alerta(tmp_path: Path) -> None:
    env = "          env:\n            - name: DB_PASSWORD\n              value: Xk9fLq2mVz81\n"
    out = scan(tmp_path, {"k8s/d.yaml": _deploy(env)})
    assert "code.iac.segredo_em_texto" in ids(out)
    assert "Xk9fLq2mVz81" not in " ".join(repr(f) for f in out.findings)


def test_mesmo_nome_em_namespaces_diferentes_gera_dois_achados(tmp_path: Path) -> None:
    texto = _deploy(namespace="dev") + "---\n" + _deploy(namespace="prod")
    out = scan(tmp_path, {"k8s/all.yaml": texto})
    assert len(of(out, PRIVILEGED)) == 2


def test_hostpath_de_config_somente_leitura_nao_e_media(tmp_path: Path) -> None:
    volumes = (
        "      volumes:\n        - name: conf\n          hostPath:\n"
        "            path: /etc/nginx/conf.d\n"
    )
    texto = _deploy(volumes=volumes).replace(
        "          securityContext:",
        "          volumeMounts:\n            - name: conf\n              mountPath: /c\n"
        "              readOnly: true\n          securityContext:",
    )
    out = scan(tmp_path, {"k8s/d.yaml": texto})
    achados = of(out, HOSTPATH)
    assert all(f.severity.value in ("low", "info") for f in achados)


def test_hostpath_sem_volumemount_nao_conta_como_somente_leitura(tmp_path: Path) -> None:
    volumes = "      volumes:\n        - name: raiz\n          hostPath:\n            path: /etc\n"
    out = scan(tmp_path, {"k8s/d.yaml": _deploy(volumes=volumes)})
    assert of(out, HOSTPATH)[0].severity.value == "high"
