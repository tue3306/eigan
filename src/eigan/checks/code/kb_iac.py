"""Base de conhecimento dos achados de containers (Dockerfile, compose e Kubernetes).

Os achados exclusivos de um formato ficam junto das regras dele: ADD remoto,
``curl | sh`` e ``sudo`` em ``iac_docker``; banco publicado em ``iac_compose``.
Os achados de nuvem (Terraform) ficam em ``iac_kb_cloud``.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
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
)

_DOCKER_PRACTICES = "https://docs.docker.com/build/building/best-practices/"
_OWASP_DOCKER = "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
_COMPOSE = "https://docs.docker.com/reference/compose-file/services/"
_K8S_PSS = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
_K8S_CONTEXT = "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
_K8S_VOLUMES = "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"


def _dockerfile(code: str) -> Fix:
    return Fix("dockerfile", "Dockerfile", code, "dockerfile")


def _compose(code: str) -> Fix:
    return Fix("docker-compose", "docker-compose", code, "yaml")


def _k8s(code: str) -> Fix:
    return Fix("kubernetes", "Kubernetes", code, "yaml")


kb.register(
    KBEntry(
        id=ROOT,
        title="Container roda como root",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "O processo principal do container roda como root (UID 0), ou a configuração não "
            "garante que ele rode sem privilégios."
        ),
        explanation=(
            "Sem a instrução USER no Dockerfile, 'user:' no compose ou 'runAsUser'/'runAsNonRoot' "
            "no Kubernetes, o usuário do processo é o definido pela imagem — e, se a imagem não "
            "define nenhum, é root. O isolamento do container reduz o estrago, mas não o elimina: "
            "root no container continua sendo o UID 0 do kernel compartilhado com o servidor."
        ),
        risk=(
            "Se a aplicação for invadida, o atacante já começa como root dentro do container: pode "
            "alterar qualquer arquivo da imagem, instalar ferramentas e aproveitar qualquer falha "
            "do kernel ou volume montado para chegar ao servidor."
        ),
        steps=(
            "Crie um usuário sem privilégios na imagem (ou use um UID numérico) e termine o "
            "Dockerfile com USER.",
            "Garanta que as pastas em que a aplicação grava pertençam a esse usuário (COPY --chown ou chown no build).",
            "Aplicações que escutam em portas abaixo de 1024 devem passar a escutar em portas altas (ex.: 8080).",
            "No Kubernetes, declare runAsNonRoot: true e runAsUser com um valor diferente de zero.",
        ),
        examples=(
            _dockerfile(
                "FROM node:22.11-alpine\n"
                "WORKDIR /app\n"
                "COPY --chown=10001:10001 . .\n"
                "# última instrução de usuário da imagem final\n"
                "USER 10001:10001",
            ),
            _compose('services:\n  app:\n    image: minha-app:1.4.2\n    user: "10001:10001"'),
            _k8s(
                "spec:\n"
                "  securityContext:\n"
                "    runAsNonRoot: true\n"
                "    runAsUser: 10001\n"
                "    runAsGroup: 10001\n"
                "  containers:\n"
                "    - name: app\n"
                "      image: minha-app:1.4.2",
            ),
        ),
        verify=(
            "'docker run --rm --entrypoint id <imagem>' ou 'kubectl exec <pod> -- id' deve mostrar um "
            "uid diferente de 0. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(_DOCKER_PRACTICES, _OWASP_DOCKER, _COMPOSE, _K8S_PSS),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("container", "privilegios"),
    ),
    KBEntry(
        id=UNPINNED,
        title="Imagem de container sem versão fixa",
        category=Category.CODE,
        severity=Severity.LOW,
        summary="A imagem usa a tag latest ou nenhuma tag: o que roda pode mudar sem aviso.",
        explanation=(
            "Tags são mutáveis: quem publica a imagem pode apontar a mesma tag para outro conteúdo. "
            "Sem tag, o Docker e o Kubernetes assumem 'latest'. Assim, duas execuções do mesmo "
            "arquivo podem usar imagens diferentes. A documentação do Kubernetes recomenda evitar "
            ":latest em produção porque fica difícil saber qual versão está rodando e voltar atrás."
        ),
        risk=(
            "Uma atualização com defeito ou uma imagem adulterada entra em produção sem revisão, "
            "e fica difícil investigar um incidente ou desfazer a mudança."
        ),
        steps=(
            "Use uma tag de versão específica (ex.: postgres:16.4).",
            "Para garantir o conteúdo exato, fixe também o digest (imagem@sha256:...).",
            "Atualize as versões de forma planejada, com uma ferramenta como Dependabot ou Renovate.",
        ),
        examples=(
            _dockerfile("FROM python:3.13.1-slim-bookworm@sha256:<digest-da-imagem>"),
            _compose("services:\n  db:\n    image: postgres:16.4"),
            _k8s(
                "containers:\n  - name: app\n    image: minha-app:1.4.2@sha256:<digest-da-imagem>"
            ),
        ),
        verify="Procure ':latest' e imagens sem tag nos arquivos e rode o EIGAN de novo.",
        effort="baixo",
        fix_group="iac",
        references=(
            _DOCKER_PRACTICES,
            "https://kubernetes.io/docs/concepts/containers/images/",
            "https://cwe.mitre.org/data/definitions/1357.html",
        ),
        cwe="CWE-1357",
        owasp="A08:2021",
        cis=("16.4", "16.7"),
        tags=("container", "cadeia-de-suprimentos"),
    ),
    KBEntry(
        id=SECRET,
        title="Segredo em texto puro na configuração de container",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Uma senha, token ou chave está escrita no Dockerfile, no compose ou no manifesto.",
        explanation=(
            "Quem lê o repositório lê o segredo. No Dockerfile é pior: valores em ENV e ARG ficam "
            "guardados na imagem final e nos metadados dela, e qualquer um que baixe a imagem pode "
            "vê-los com 'docker history' ou 'docker inspect'. A documentação do Docker recomenda "
            "usar montagens de segredo no build, que não ficam na imagem."
        ),
        risk=(
            "Vazamento da credencial para todos com acesso ao repositório ou à imagem. Com ela, um "
            "atacante acessa o banco de dados ou a API diretamente, sem precisar explorar nenhuma falha."
        ),
        steps=(
            "Considere o segredo comprometido: troque-o agora (o valor continua no histórico do Git).",
            "No Dockerfile, passe o valor só durante o build com RUN --mount=type=secret.",
            "No compose, leia o valor de um .env fora do Git ou use o bloco 'secrets:'.",
            "No Kubernetes, use um Secret (ou um gerenciador externo) e referencie com secretKeyRef.",
        ),
        examples=(
            _dockerfile(
                "# syntax=docker/dockerfile:1\n"
                "RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci\n"
                "# build: docker build --secret id=npm_token,env=NPM_TOKEN .",
            ),
            _compose(
                "services:\n"
                "  db:\n"
                "    image: postgres:16.4\n"
                "    environment:\n"
                "      POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n"
                "    secrets:\n"
                "      - db_password\n"
                "secrets:\n"
                "  db_password:\n"
                "    file: ./segredos/db_password.txt   # fora do Git",
            ),
            _k8s(
                "env:\n"
                "  - name: DB_PASSWORD\n"
                "    valueFrom:\n"
                "      secretKeyRef:\n"
                "        name: app-credenciais\n"
                "        key: db-password",
            ),
        ),
        verify=(
            "O arquivo não deve ter mais o valor. Em imagens, confira 'docker history --no-trunc "
            "<imagem>'. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="segredos",
        references=(
            "https://docs.docker.com/reference/build-checks/secrets-used-in-arg-or-env/",
            _OWASP_DOCKER,
            "https://kubernetes.io/docs/concepts/configuration/secret/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        lgpd=True,
        tags=("container", "segredos"),
    ),
    KBEntry(
        id=PRIVILEGED,
        title="Container com privilégios totais (privileged)",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="O container roda em modo privilegiado: praticamente sem isolamento do servidor.",
        explanation=(
            "O modo privilegiado dá ao container todas as capabilities do Linux e acesso a todos os "
            "dispositivos do servidor, e relaxa as proteções do AppArmor/SELinux. A documentação do "
            "Docker avisa que esse container não é um ambiente isolado de forma segura, e o padrão "
            "de segurança do Kubernetes proíbe o modo privilegiado já no perfil básico (baseline). "
            "Os contêineres Windows 'hostProcess' têm efeito parecido."
        ),
        risk=(
            "Quem invadir a aplicação consegue escapar para o servidor com facilidade (montando o "
            "disco, carregando módulos do kernel) e, a partir dele, chegar ao resto da infraestrutura."
        ),
        steps=(
            "Remova 'privileged: true'.",
            "Descubra o que a aplicação realmente precisa e conceda só isso, com capabilities específicas.",
            "Se o serviço precisa mesmo de acesso ao servidor (ex.: agente de monitoramento), isole-o "
            "em nós dedicados e documente a exceção.",
        ),
        examples=(
            _compose(
                "services:\n"
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    cap_drop: [ALL]\n"
                "    cap_add: [NET_BIND_SERVICE]   # só o necessário\n"
                "    security_opt:\n"
                "      - no-new-privileges:true",
            ),
            _k8s(
                "securityContext:\n"
                "  privileged: false\n"
                "  allowPrivilegeEscalation: false\n"
                "  capabilities:\n"
                "    drop: [ALL]",
            ),
        ),
        verify=(
            "'docker inspect -f \"{{.HostConfig.Privileged}}\" <container>' deve mostrar false e a "
            "aplicação deve continuar funcionando. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(
            "https://docs.docker.com/reference/cli/docker/container/run/",
            "https://docs.docker.com/engine/containers/run/",
            _OWASP_DOCKER,
            _K8S_PSS,
        ),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("container", "privilegios"),
    ),
    KBEntry(
        id=HOST_NS,
        title="Container compartilha rede, processos ou IPC com o servidor",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "O container usa um namespace do servidor (rede, processos ou memória compartilhada) "
            "em vez de um isolado."
        ),
        explanation=(
            "Containers são isolados por namespaces do Linux. Com 'network_mode: host' ou "
            "'hostNetwork: true', a rede do container não fica isolada do servidor. Com 'pid: host' "
            "ou 'hostPID: true', ele enxerga os processos do servidor. Com 'ipc: host' ou "
            "'hostIPC: true', compartilha a memória entre processos. O padrão de segurança do "
            "Kubernetes proíbe os três no perfil básico (baseline)."
        ),
        risk=(
            "Um atacante dentro do container pode alcançar serviços que só escutam em localhost no "
            "servidor, observar e interferir em outros processos e ler dados em memória compartilhada."
        ),
        steps=(
            "Remova a opção: o padrão já isola o container.",
            "Para expor um serviço, publique só as portas necessárias em vez de usar a rede do servidor.",
            "Mantenha exceções (ex.: CNI, agentes de monitoramento) em nós dedicados e documentadas.",
        ),
        examples=(
            _compose(
                "services:\n"
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    # sem network_mode: host, pid: host nem ipc: host\n"
                "    ports:\n"
                '      - "127.0.0.1:8080:8080"',
            ),
            _k8s(
                "spec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false",
            ),
        ),
        verify=(
            "'docker inspect' deve mostrar NetworkMode, PidMode e IpcMode diferentes de host. Rode "
            "o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(
            _K8S_PSS,
            "https://docs.docker.com/engine/network/drivers/host/",
            "https://docs.docker.com/reference/cli/docker/container/run/",
            "https://cwe.mitre.org/data/definitions/653.html",
        ),
        cwe="CWE-653",
        owasp="A05:2021",
        cis=("4.1", "12.2"),
        tags=("container", "isolamento"),
    ),
    KBEntry(
        id=DOCKER_SOCK,
        title="Socket do Docker montado dentro do container",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "O container tem acesso ao socket do Docker (ou de outro runtime), o que equivale a ser "
            "root no servidor."
        ),
        explanation=(
            "O socket /var/run/docker.sock é a porta de comando do Docker. Segundo o guia de "
            "segurança da OWASP, dar acesso a ele equivale a dar acesso root irrestrito ao servidor. "
            "Montá-lo como somente leitura não resolve: a API continua aceitando comandos. O mesmo "
            "vale para os sockets do containerd, do CRI-O e do Podman."
        ),
        risk=(
            "Quem invadir esse container cria outro container privilegiado com o disco do servidor "
            "montado e assume o controle da máquina e de todos os containers dela."
        ),
        steps=(
            "Remova o volume, se o serviço não precisar da API do Docker.",
            "Se precisar (painéis, proxies reversos), coloque um proxy que libere só as chamadas "
            "necessárias e somente leitura, e deixe o socket apenas nesse proxy.",
            "Para construir imagens em CI, prefira builders sem daemon (rootless).",
        ),
        examples=(
            _compose(
                "services:\n"
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    # volumes:\n"
                "    #   - /var/run/docker.sock:/var/run/docker.sock   # remova",
            ),
            _k8s(
                "# remova o volume hostPath do socket e o volumeMount correspondente\n"
                "volumes:\n"
                "  - name: dados\n"
                "    emptyDir: {}",
            ),
        ),
        verify="Dentro do container, 'ls /var/run/docker.sock' não deve encontrar o arquivo. Rode o EIGAN de novo.",
        effort="medio",
        fix_group="iac",
        references=(_OWASP_DOCKER, _K8S_VOLUMES, "https://cwe.mitre.org/data/definitions/668.html"),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("container", "privilegios"),
    ),
    KBEntry(
        id=ESCALATION,
        title="Container permite escalação de privilégio",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "allowPrivilegeEscalation está ligado ou ausente: um processo pode ganhar mais "
            "privilégios que o processo pai."
        ),
        explanation=(
            "allowPrivilegeEscalation controla se um processo pode ganhar mais privilégios que o "
            "pai, por exemplo executando um binário setuid. Quando o campo não é definido, o valor "
            "padrão é true. O perfil restrito (restricted) do Kubernetes exige false."
        ),
        risk=(
            "Um atacante que entre como usuário comum pode virar root no container por meio de um "
            "binário setuid (como sudo ou su) presente na imagem."
        ),
        steps=(
            "Defina allowPrivilegeEscalation: false no securityContext de cada container.",
            "Teste a aplicação: quase nenhuma precisa de setuid em tempo de execução.",
            "Aplique o perfil restricted no namespace para impedir que isso volte.",
        ),
        examples=(
            _k8s(
                "containers:\n"
                "  - name: app\n"
                "    image: minha-app:1.4.2\n"
                "    securityContext:\n"
                "      allowPrivilegeEscalation: false",
            ),
            _k8s(
                "# no namespace, para rejeitar pods fora do padrão\n"
                "metadata:\n"
                "  labels:\n"
                "    pod-security.kubernetes.io/enforce: restricted",
            ),
        ),
        verify=(
            "'kubectl get pod <pod> -o jsonpath=\"{.spec.containers[*].securityContext"
            ".allowPrivilegeEscalation}\"' deve mostrar false. Rode o EIGAN de novo."
        ),
        effort="baixo",
        fix_group="iac",
        references=(_K8S_CONTEXT, _K8S_PSS),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("kubernetes", "privilegios"),
    ),
    KBEntry(
        id=CAPABILITIES,
        title="Container recebe capabilities perigosas do Linux",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "O container ganha capabilities fora da lista aceita pelo perfil básico do Kubernetes."
        ),
        explanation=(
            "Capabilities dividem os poderes do root em partes. Algumas são quase equivalentes a "
            "root no servidor: SYS_ADMIN (várias operações de administração, como montar discos), "
            "SYS_MODULE (carregar módulos do kernel), SYS_PTRACE (inspecionar qualquer processo), "
            "DAC_READ_SEARCH (ler qualquer arquivo), NET_ADMIN (mudar a rede). O perfil básico do "
            "Kubernetes só aceita uma lista curta: AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, "
            "KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID e SYS_CHROOT."
        ),
        risk=(
            "Quem invadir a aplicação usa essas capabilities para escapar do container, ler dados "
            "de outros processos ou interceptar o tráfego da rede."
        ),
        steps=(
            "Comece sem nenhuma capability: cap_drop: [ALL] (compose) ou drop: [ALL] (Kubernetes).",
            "Adicione de volta só o que a aplicação comprovadamente precisa, de preferência nada "
            "além de NET_BIND_SERVICE.",
            "Se o programa precisa de SYS_ADMIN, revise o desenho: normalmente há alternativa sem isso.",
        ),
        examples=(
            _compose(
                "services:\n"
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    cap_drop: [ALL]\n"
                "    cap_add: [NET_BIND_SERVICE]",
            ),
            _k8s(
                "securityContext:\n  capabilities:\n    drop: [ALL]\n    add: [NET_BIND_SERVICE]",
            ),
        ),
        verify="Dentro do container, 'grep Cap /proc/1/status' mostra as capabilities em uso. Rode o EIGAN de novo.",
        effort="medio",
        fix_group="iac",
        references=(
            _K8S_PSS,
            _OWASP_DOCKER,
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
        ),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("container", "privilegios"),
    ),
    KBEntry(
        id=HOSTPATH,
        title="Container monta um diretório do servidor (hostPath)",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="O container acessa diretamente um caminho do disco do servidor.",
        explanation=(
            "Um volume hostPath (Kubernetes) ou bind mount (compose) liga o container ao disco do "
            "servidor. A documentação do Kubernetes avisa que isso traz muitos riscos e deve ser "
            "evitado: o acesso pode expor credenciais privilegiadas do servidor (como as do kubelet) "
            "e APIs privilegiadas (como o socket do runtime), usadas para escapar do container. "
            "Até no modo somente leitura é preciso cuidado. Montar a raiz, /etc, /proc ou "
            "/var/lib/kubelet é o caso mais grave."
        ),
        risk=(
            "Um atacante no container lê chaves e senhas do servidor e, com permissão de escrita, "
            "altera arquivos do sistema para assumir a máquina. O uso de disco do hostPath também "
            "não é contabilizado e pode encher o disco do nó."
        ),
        steps=(
            "Troque por um volume gerenciado (PersistentVolume, volume nomeado do compose ou emptyDir).",
            "Se precisar mesmo do caminho do servidor, monte só o arquivo ou a pasta necessários, "
            "nunca a raiz, e em modo somente leitura.",
            "No Kubernetes, adote o perfil baseline, que proíbe hostPath, e documente as exceções.",
        ),
        examples=(
            _k8s(
                "volumes:\n  - name: dados\n    persistentVolumeClaim:\n      claimName: dados-app",
            ),
            _compose(
                "services:\n"
                "  app:\n"
                "    image: minha-app:1.4.2\n"
                "    volumes:\n"
                "      - dados:/var/lib/app\n"
                "      - ./config/app.conf:/etc/app/app.conf:ro\n"
                "volumes:\n"
                "  dados:",
            ),
        ),
        verify="Confira os volumes com 'docker inspect' ou 'kubectl get pod -o yaml' e rode o EIGAN de novo.",
        effort="medio",
        fix_group="iac",
        references=(
            _K8S_VOLUMES,
            _K8S_PSS,
            "https://docs.docker.com/engine/security/",
            "https://cwe.mitre.org/data/definitions/668.html",
        ),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        tags=("container", "isolamento"),
    ),
    KBEntry(
        id=NO_LIMITS,
        title="Container sem limite de memória",
        category=Category.CODE,
        severity=Severity.INFO,
        summary="O manifesto não define um limite de memória para o container.",
        explanation=(
            "Sem limite de memória, o container pode usar toda a memória disponível no nó, o que "
            "pode acionar o OOM Killer do Linux e derrubar outros serviços. A exceção é o namespace "
            "com um LimitRange, que atribui um limite padrão automaticamente."
        ),
        risk=(
            "Um erro da aplicação, um pico de uso ou um ataque de negação de serviço em um único "
            "container pode afetar todos os outros serviços do mesmo nó."
        ),
        steps=(
            "Meça o consumo normal da aplicação.",
            "Defina resources.limits.memory (e requests) um pouco acima desse valor.",
            "Adote um LimitRange no namespace para dar um padrão a quem não definir nada.",
        ),
        examples=(
            _k8s(
                "containers:\n"
                "  - name: app\n"
                "    image: minha-app:1.4.2\n"
                "    resources:\n"
                "      requests:\n"
                "        cpu: 100m\n"
                "        memory: 128Mi\n"
                "      limits:\n"
                "        memory: 256Mi",
            ),
        ),
        verify="'kubectl describe pod <pod>' deve mostrar Limits com memory. Rode o EIGAN de novo.",
        effort="baixo",
        fix_group="iac",
        references=(
            "https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/",
            "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
            _OWASP_DOCKER,
        ),
        cwe="CWE-770",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kubernetes", "disponibilidade"),
    ),
    KBEntry(
        id=WRITABLE_FS,
        title="Sistema de arquivos do container permite escrita",
        category=Category.CODE,
        severity=Severity.LOW,
        summary="readOnlyRootFilesystem está explicitamente desligado no container.",
        explanation=(
            "readOnlyRootFilesystem monta a raiz do sistema de arquivos do container como somente "
            "leitura. Desligado, qualquer processo pode alterar os arquivos da imagem durante a "
            "execução. O guia de segurança da OWASP recomenda rodar containers somente leitura."
        ),
        risk=(
            "Um atacante pode gravar ferramentas, trocar binários ou deixar um script malicioso "
            "persistente enquanto o container existir."
        ),
        steps=(
            "Defina readOnlyRootFilesystem: true.",
            "Dê volumes emptyDir só às pastas em que a aplicação precisa gravar (ex.: /tmp).",
        ),
        examples=(
            _k8s(
                "containers:\n"
                "  - name: app\n"
                "    image: minha-app:1.4.2\n"
                "    securityContext:\n"
                "      readOnlyRootFilesystem: true\n"
                "    volumeMounts:\n"
                "      - name: tmp\n"
                "        mountPath: /tmp\n"
                "volumes:\n"
                "  - name: tmp\n"
                "    emptyDir: {}",
            ),
        ),
        verify="Dentro do container, 'touch /teste' deve falhar com 'Read-only file system'. Rode o EIGAN de novo.",
        effort="medio",
        fix_group="iac",
        references=(_K8S_CONTEXT, _OWASP_DOCKER),
        cwe="CWE-732",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kubernetes", "endurecimento"),
    ),
)
