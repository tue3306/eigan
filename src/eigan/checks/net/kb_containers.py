"""Base de conhecimento: Docker, Kubernetes (API e kubelet) e etcd expostos."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_CONTAINER_RISK = (
    "Controle total da infraestrutura: quem fala com esta API cria containers privilegiados, "
    "lê segredos e variáveis de ambiente, monta o disco do servidor e se torna "
    "administrador (root) da máquina — e, no caso de um cluster, de todos os nós."
)

kb.register(
    KBEntry(
        id="net.docker.api_exposta",
        title="API do Docker exposta sem TLS",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O daemon do Docker responde na rede (porta 2375) sem criptografia nem autenticação.",
        explanation=(
            "O Docker pode aceitar comandos por TCP. Sem TLS com certificado de cliente "
            "(normalmente na porta 2376), qualquer um que alcance a porta controla o daemon como "
            "se estivesse no servidor — a documentação lembra que quem fala com o daemon tem "
            "acesso de root."
        ),
        risk=_CONTAINER_RISK,
        steps=(
            "Remova o socket TCP sem TLS da configuração do daemon (deixe só o socket local).",
            "Se o acesso remoto for necessário, use SSH (DOCKER_HOST=ssh://...) ou TLS com --tlsverify.",
            "Bloqueie as portas 2375/2376 para a Internet e revise containers e imagens criados recentemente.",
        ),
        examples=(
            Fix(
                "docker",
                "Docker (/etc/docker/daemon.json, só socket local)",
                '{\n  "hosts": ["unix:///var/run/docker.sock"]\n}\n'
                "# se o serviço do systemd usar '-H tcp://...', remova essa opção também",
                "json",
            ),
            Fix(
                "docker-tls",
                "Docker com TLS obrigatório (daemon.json)",
                '{\n  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],\n'
                '  "tlsverify": true,\n  "tlscacert": "/etc/docker/ca.pem",\n'
                '  "tlscert": "/etc/docker/server-cert.pem",\n'
                '  "tlskey": "/etc/docker/server-key.pem"\n}',
                "json",
            ),
            Fix(
                "windows",
                "Docker Desktop (Windows)",
                "Settings > General > desmarque 'Expose daemon on tcp://localhost:2375 without TLS'",
                "text",
            ),
            Fix(
                "linux",
                "Acesso remoto por SSH",
                "export DOCKER_HOST=ssh://usuario@servidor\ndocker ps",
                "bash",
            ),
        ),
        verify="'curl http://servidor:2375/version' não deve responder; com TLS, sem certificado de cliente deve falhar.",
        effort="baixo",
        fix_group="autenticacao",
        references=(
            "https://docs.docker.com/engine/security/protect-access/",
            "https://docs.docker.com/engine/security/",
        ),
        cwe="CWE-306",
        owasp="A05:2021",
        cis=("4.6", "12.2"),
        lgpd=True,
        tags=("docker", "container"),
    ),
    KBEntry(
        id="net.kubernetes.anonimo",
        title="API do Kubernetes permite leitura anônima",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="A API do Kubernetes entregou recursos do cluster a um usuário anônimo.",
        explanation=(
            "Requisições sem credenciais viram o usuário 'system:anonymous' (grupo "
            "'system:unauthenticated'). Por padrão esse usuário só vê informações públicas; "
            "aqui alguma regra RBAC deu a ele acesso a recursos do cluster."
        ),
        risk=_CONTAINER_RISK,
        steps=(
            "Procure e remova ClusterRoleBindings/RoleBindings que citam system:anonymous ou system:unauthenticated.",
            "Desative o acesso anônimo no kube-apiserver (--anonymous-auth=false) se não for necessário.",
            "Restrinja o acesso à porta da API (6443) a redes administrativas ou VPN.",
        ),
        examples=(
            Fix(
                "kubernetes",
                "kubectl (encontrar permissões anônimas)",
                "kubectl get clusterrolebindings,rolebindings -A -o wide "
                "| grep -E 'system:(anonymous|unauthenticated)'\n"
                "kubectl delete clusterrolebinding <nome-da-ligacao>",
                "bash",
            ),
            Fix(
                "kubernetes-apiserver",
                "kube-apiserver (manifesto estático)",
                "- --anonymous-auth=false\n- --authorization-mode=Node,RBAC",
                "yaml",
            ),
        ),
        verify="'curl -k https://servidor:6443/api/v1/namespaces' deve responder 401 ou 403.",
        effort="medio",
        fix_group="autenticacao",
        references=(
            "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        ),
        cwe="CWE-306",
        owasp="A01:2021",
        cis=("4.7", "5.4", "12.2"),
        lgpd=True,
        tags=("kubernetes", "container"),
    ),
    KBEntry(
        id="net.kubernetes.api_exposta",
        title="API do Kubernetes acessível pela Internet",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O painel de controle do cluster (kube-apiserver) responde para a Internet.",
        explanation=(
            "Mesmo exigindo autenticação, a API do Kubernetes exposta é alvo de varreduras, "
            "tentativas com credenciais vazadas e exploração de falhas do próprio servidor da "
            "API. A versão é revelada a qualquer um pelo endpoint /version."
        ),
        risk=(
            "Uma credencial vazada (kubeconfig, token de service account) ou uma falha nova "
            "do Kubernetes passa a ser explorável de qualquer lugar do mundo."
        ),
        steps=(
            "Restrinja o acesso à API a endereços administrativos (firewall, security group, lista de IPs autorizados do provedor).",
            "Prefira endpoint privado + VPN/bastion para administração.",
            "Mantenha o Kubernetes em uma versão com suporte.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux (ufw, só a rede administrativa)",
                "sudo ufw allow from 203.0.113.0/24 to any port 6443 proto tcp\n"
                "sudo ufw deny 6443/tcp",
                "bash",
            ),
        ),
        verify="De um endereço fora da lista autorizada, a porta 6443 deve aparecer filtrada.",
        effort="medio",
        fix_group="servicos",
        references=("https://kubernetes.io/docs/concepts/security/controlling-access/",),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        tags=("kubernetes", "exposicao"),
    ),
    KBEntry(
        id="net.kubelet.anonimo",
        title="Kubelet aceita requisições anônimas",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="A API do kubelet listou os pods do nó sem autenticação.",
        explanation=(
            "O kubelet (agente de cada nó do Kubernetes) tem uma API própria nas portas 10250 "
            "(completa) e 10255 (somente leitura). Com 'anonymous-auth' ligado e autorização "
            "'AlwaysAllow' (os padrões quando nada é configurado), qualquer um lista os pods e, na "
            "porta 10250, pode executar comandos dentro dos containers."
        ),
        risk=_CONTAINER_RISK,
        steps=(
            "Desative o acesso anônimo do kubelet e delegue a autorização ao API server (Webhook).",
            "Desligue a porta somente leitura (readOnlyPort: 0).",
            "Bloqueie as portas 10250/10255 para fora da rede do cluster.",
        ),
        examples=(
            Fix(
                "kubernetes",
                "KubeletConfiguration (/var/lib/kubelet/config.yaml)",
                "authentication:\n  anonymous:\n    enabled: false\n  webhook:\n    enabled: true\n"
                "authorization:\n  mode: Webhook\nreadOnlyPort: 0",
                "yaml",
            ),
        ),
        verify="'curl -k https://no:10250/pods' deve responder 401 (Unauthorized).",
        effort="medio",
        fix_group="autenticacao",
        references=(
            "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
        ),
        cwe="CWE-306",
        owasp="A01:2021",
        cis=("4.7", "12.2"),
        lgpd=True,
        tags=("kubernetes", "kubelet", "container"),
    ),
    KBEntry(
        id="net.etcd.sem_senha",
        title="etcd acessível sem autenticação",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O etcd respondeu a uma consulta de chaves sem credenciais nem certificado de cliente.",
        explanation=(
            "O etcd guarda o estado inteiro de um cluster Kubernetes — inclusive os Secrets. "
            "Sem autenticação (desligada até alguém rodar 'etcdctl auth enable') e sem "
            "certificado de cliente obrigatório, qualquer um que alcance a porta 2379 lê e "
            "altera esses dados."
        ),
        risk=_CONTAINER_RISK,
        steps=(
            "Exija certificado de cliente (--client-cert-auth) e TLS na porta de clientes.",
            "Crie o usuário root e ative a autenticação (etcdctl user add root; etcdctl auth enable).",
            "Faça o etcd escutar só na rede dos nós do plano de controle e bloqueie 2379/2380 para o resto.",
        ),
        examples=(
            Fix(
                "etcd",
                "etcd (parâmetros do serviço)",
                "--listen-client-urls=https://10.0.0.5:2379\n--client-cert-auth=true\n"
                "--trusted-ca-file=/etc/etcd/ca.crt\n--cert-file=/etc/etcd/server.crt\n"
                "--key-file=/etc/etcd/server.key",
                "text",
            ),
            Fix(
                "etcd-rbac",
                "etcdctl (ativar autenticação)",
                "etcdctl user add root\netcdctl auth enable",
                "bash",
            ),
        ),
        verify="'curl http://servidor:2379/v3/kv/range' sem certificado deve falhar.",
        effort="medio",
        fix_group="autenticacao",
        references=(
            "https://etcd.io/docs/v3.5/op-guide/authentication/rbac/",
            "https://etcd.io/docs/v3.5/op-guide/security/",
        ),
        cwe="CWE-306",
        owasp="A07:2021",
        cis=("3.3", "12.2"),
        lgpd=True,
        tags=("etcd", "kubernetes"),
    ),
)
