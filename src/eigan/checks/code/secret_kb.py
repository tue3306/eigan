"""Base de conhecimento dos segredos encontrados no código."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .secret_rules import (
    CLOUD,
    CONNECTION,
    ENV_FILE,
    GENERIC,
    JWT,
    PRIVATE_KEY,
    SENSITIVE_FILE,
    TOKEN,
)

_SECRET_REFS = (
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
)

#: ler o segredo do ambiente/cofre em vez de escrevê-lo no código
ENV_EXAMPLES = (
    Fix(
        "python",
        "Python",
        'import os\n\nAPI_KEY = os.environ["API_KEY"]  # falha cedo se não estiver definida',
        "python",
    ),
    Fix(
        "javascript",
        "Node.js",
        'const apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error("API_KEY não definida");',
        "javascript",
    ),
    Fix(
        "php",
        "PHP",
        "$apiKey = getenv('API_KEY');\n// Laravel: env('API_KEY') só em config/*.php",
        "php",
    ),
    Fix(
        "java",
        "Java / Spring",
        'String apiKey = System.getenv("API_KEY");\n// Spring: api.key=${API_KEY}',
        "java",
    ),
    Fix(
        "csharp",
        "C# / .NET",
        'var apiKey = builder.Configuration["ApiKey"];\n'
        "// desenvolvimento: dotnet user-secrets set ApiKey <valor>\n"
        "// produção: Azure Key Vault ou variável de ambiente ApiKey",
        "csharp",
    ),
    Fix(
        "go",
        "Go",
        'apiKey := os.Getenv("API_KEY")\nif apiKey == "" {\n\tlog.Fatal("API_KEY não definida")\n}',
        "go",
    ),
    Fix(
        "dockerfile",
        "Dockerfile (segredo de build)",
        "# syntax=docker/dockerfile:1\n"
        "RUN --mount=type=secret,id=npm_token \\\n"
        "    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci\n"
        "# docker build --secret id=npm_token,env=NPM_TOKEN .",
        "dockerfile",
    ),
    Fix(
        "kubernetes",
        "Kubernetes",
        "env:\n  - name: API_KEY\n    valueFrom:\n      secretKeyRef:\n"
        "        name: app-secrets\n        key: api-key",
        "yaml",
    ),
    Fix(
        "git",
        "Git (limpar o histórico, depois de revogar)",
        "git filter-repo --invert-paths --path config/credenciais.json\n"
        "git push --force --all && git push --force --tags",
        "bash",
    ),
)

_STEPS = (
    "Considere o segredo vazado: revogue ou troque-o AGORA no serviço de origem (o "
    "'como revogar' está nos detalhes do achado). Apagar do código não basta.",
    "Tire o valor do código e leia de variável de ambiente ou de um cofre (AWS Secrets "
    "Manager, Azure Key Vault, HashiCorp Vault, GitHub Actions secrets).",
    "Se o arquivo já foi para o Git, o segredo continua no histórico: depois de revogar, "
    "limpe o histórico (git filter-repo ou BFG) e avise quem tem cópias do repositório.",
    "Confira nos registros do provedor se o segredo foi usado por terceiros.",
    "Previna: hook de pre-commit com gitleaks/detect-secrets e 'secret scanning' do GitHub/GitLab.",
)

kb.register(
    KBEntry(
        id=PRIVATE_KEY,
        title="Chave privada dentro do projeto",
        category=Category.CODE,
        severity=Severity.CRITICAL,
        summary="Uma chave privada (TLS, SSH, PGP ou de conta de serviço) está gravada em um arquivo do projeto.",
        explanation=(
            "Chave privada é o que prova a identidade de um servidor, usuário ou aplicação. "
            "Quem tem uma cópia pode se passar pelo dono: abrir sessões SSH, decifrar ou forjar "
            "tráfego TLS, assinar código ou acessar a nuvem (chaves de conta de serviço)."
        ),
        risk=(
            "Acesso direto a servidores e serviços, interceptação de tráfego e assinatura de "
            "artefatos falsos. Repositórios são copiados com frequência (forks, CI, notebooks): "
            "a chave deve ser considerada comprometida."
        ),
        steps=(
            "Gere um novo par de chaves e substitua a chave pública/certificado em todos os "
            "lugares que confiam nela (authorized_keys, servidor web, nuvem).",
            "Revogue o certificado antigo na autoridade certificadora, se houver.",
            *_STEPS[1:],
        ),
        examples=(
            Fix(
                "bash",
                "Novo par SSH",
                'ssh-keygen -t ed25519 -C "deploy@empresa"\n# chave fica em ~/.ssh, fora do projeto',
                "bash",
            ),
            Fix("gitignore", ".gitignore", "*.pem\n*.key\nid_rsa*\nid_ed25519*\n*.ppk", "text"),
            *ENV_EXAMPLES[-3:],
        ),
        verify="Nenhuma chave privada no projeto e a chave antiga não é mais aceita pelos serviços.",
        effort="medio",
        fix_group="segredos",
        references=(
            "https://cwe.mitre.org/data/definitions/321.html",
            *_SECRET_REFS,
        ),
        cwe="CWE-321",
        owasp="A02:2021",
        cis=("3.11", "16.12"),
        lgpd=True,
        tags=("segredos", "chave-privada"),
    ),
    KBEntry(
        id=CLOUD,
        title="Credencial de nuvem no código",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Uma chave de acesso da AWS, Google Cloud, Azure ou outro provedor de nuvem está no código.",
        explanation=(
            "Chaves de nuvem dão acesso programático à conta: criar máquinas, ler buckets e "
            "bancos, mexer em permissões. Robôs varrem repositórios públicos atrás desses "
            "formatos e usam as chaves em minutos (mineração de criptomoeda é o caso mais comum)."
        ),
        risk=(
            "Vazamento de dados armazenados na nuvem, contas enormes de consumo e controle da "
            "infraestrutura pelo atacante."
        ),
        steps=_STEPS,
        examples=ENV_EXAMPLES,
        verify="A chave antiga aparece como desativada/excluída no provedor e não está mais no código.",
        effort="medio",
        fix_group="segredos",
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "https://cloud.google.com/docs/authentication/api-keys",
            "https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage",
            *_SECRET_REFS,
        ),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        lgpd=True,
        tags=("segredos", "nuvem"),
    ),
    KBEntry(
        id=TOKEN,
        title="Token de serviço no código",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Um token de API (GitHub, GitLab, Slack, Stripe, npm, PyPI...) está escrito no código.",
        explanation=(
            "Tokens de API funcionam como senha da conta ou do sistema que os emitiu. Com eles é "
            "possível publicar pacotes, ler repositórios privados, enviar mensagens ou fazer "
            "cobranças, sem precisar de usuário e senha."
        ),
        risk=(
            "Ataque à cadeia de suprimentos (publicar versão maliciosa de um pacote), vazamento "
            "de código e dados, fraude financeira (chaves de pagamento)."
        ),
        steps=_STEPS,
        examples=ENV_EXAMPLES,
        verify="O token antigo foi revogado no serviço e não está mais no código.",
        effort="baixo",
        fix_group="segredos",
        references=_SECRET_REFS,
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        tags=("segredos", "token"),
    ),
    KBEntry(
        id=JWT,
        title="Token JWT gravado no código",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="Um token JWT (sessão/credencial assinada) está escrito em um arquivo do projeto.",
        explanation=(
            "JWTs são credenciais portáteis: quem tem o token age como o usuário ou serviço até "
            "ele expirar. Tokens gravados em código costumam ter validade longa ou nenhuma."
        ),
        risk="Uso da identidade do token para acessar a API enquanto ele for válido.",
        steps=(
            "Verifique se o token ainda é aceito (campo exp) e, se for, invalide-o no emissor ou "
            "troque a chave de assinatura.",
            "Gere tokens em tempo de execução, com validade curta, em vez de deixá-los no código.",
            *_STEPS[2:],
        ),
        examples=ENV_EXAMPLES[:6],
        verify="O token não está mais no código e não é aceito pela API.",
        effort="baixo",
        fix_group="segredos",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html",
            *_SECRET_REFS,
        ),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        tags=("segredos", "jwt"),
    ),
    KBEntry(
        id=GENERIC,
        title="Senha ou chave escrita no código",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="Uma variável com nome de senha/chave recebe um valor fixo com cara de segredo real.",
        explanation=(
            "Senhas no código vão parar no Git, em backups, em imagens de container e nas máquinas "
            "de todos os desenvolvedores. Também ficam iguais em todos os ambientes, então quem vê "
            "o código de teste conhece a senha de produção."
        ),
        risk="Acesso indevido ao banco, à API ou ao serviço protegido pela senha.",
        steps=_STEPS,
        examples=ENV_EXAMPLES,
        verify="O valor fixo saiu do código, a senha foi trocada e a aplicação lê o segredo do ambiente/cofre.",
        effort="baixo",
        fix_group="segredos",
        references=("https://cwe.mitre.org/data/definitions/259.html", *_SECRET_REFS),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        tags=("segredos", "senha"),
    ),
    KBEntry(
        id=CONNECTION,
        title="Senha em URL ou string de conexão",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Uma URL (postgres://usuario:senha@...) ou string de conexão traz a senha embutida.",
        explanation=(
            "Strings de conexão com senha costumam apontar para bancos de dados, filas e "
            "servidores FTP. Além de vazar pelo código, aparecem em mensagens de erro e logs."
        ),
        risk="Acesso direto ao banco de dados ou serviço, com leitura e alteração de dados.",
        steps=_STEPS,
        examples=(
            Fix("python", "Python", 'DATABASE_URL = os.environ["DATABASE_URL"]', "python"),
            Fix(
                "javascript",
                "Node.js",
                "const pool = new Pool({ connectionString: process.env.DATABASE_URL });",
                "javascript",
            ),
            Fix(
                "csharp",
                ".NET (appsettings + user-secrets/Key Vault)",
                'dotnet user-secrets set "ConnectionStrings:Default" "Server=...;Password=..."\n'
                '// código: builder.Configuration.GetConnectionString("Default")',
                "csharp",
            ),
            Fix("java", "Spring", "spring.datasource.password=${DB_PASSWORD}", "properties"),
            *ENV_EXAMPLES[6:8],
        ),
        verify="A senha foi trocada no banco/serviço e a string de conexão vem do ambiente ou cofre.",
        effort="baixo",
        fix_group="segredos",
        references=_SECRET_REFS,
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.1", "16.12"),
        lgpd=True,
        tags=("segredos", "banco-de-dados"),
    ),
    KBEntry(
        id=ENV_FILE,
        title="Arquivo .env versionado ou fora do .gitignore",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Um arquivo .env com variáveis de configuração está no Git ou pode entrar no próximo commit.",
        explanation=(
            "O .env existe justamente para guardar senhas e chaves fora do código. Quando ele é "
            "versionado, todos os segredos vão para o repositório e para o histórico, e qualquer "
            "pessoa com acesso ao repositório passa a conhecê-los."
        ),
        risk="Vazamento de todas as credenciais da aplicação de uma vez (banco, APIs, chaves de sessão).",
        steps=(
            "Adicione .env ao .gitignore e tire o arquivo do índice: git rm --cached .env.",
            "Troque todos os segredos que estavam no arquivo (eles já estão no histórico).",
            "Versione apenas um modelo sem valores reais: .env.example.",
            "Se o repositório é público ou compartilhado, limpe o histórico (git filter-repo).",
        ),
        examples=(
            Fix("gitignore", ".gitignore", ".env\n.env.*\n!.env.example", "text"),
            Fix(
                "git",
                "Git",
                'git rm --cached .env\ngit commit -m "remove .env do repositório"',
                "bash",
            ),
            ENV_EXAMPLES[-1],
        ),
        verify="git ls-files não lista o .env e git check-ignore .env confirma que ele é ignorado.",
        effort="baixo",
        fix_group="segredos",
        references=(
            "https://git-scm.com/docs/gitignore",
            "https://12factor.net/config",
            *_SECRET_REFS[1:],
        ),
        cwe="CWE-540",
        owasp="A05:2021",
        cis=("16.1", "16.12"),
        lgpd=True,
        tags=("segredos", "dotenv", "git"),
    ),
    KBEntry(
        id=SENSITIVE_FILE,
        title="Arquivo de credenciais no projeto",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="Um arquivo que guarda credenciais (keystore, .pfx, .git-credentials, estado do Terraform...) está no projeto.",
        explanation=(
            "Alguns arquivos são, por natureza, cofres de segredos: keystores Java e .pfx/.p12 "
            "trazem chaves privadas; .git-credentials, .netrc e .pgpass guardam senhas em texto; "
            "o terraform.tfstate guarda em texto puro todas as senhas criadas pela infraestrutura."
        ),
        risk="Quem obtém o arquivo extrai chaves e senhas (a senha de keystores costuma ser fraca ou padrão).",
        steps=(
            "Tire o arquivo do repositório (git rm --cached) e inclua o padrão no .gitignore.",
            "Troque as chaves/senhas contidas nele.",
            "Terraform: use backend remoto com criptografia (S3 + KMS, Azure Storage, Terraform Cloud).",
            "Guarde keystores e certificados em cofre (Key Vault, Secrets Manager) e injete no deploy.",
        ),
        examples=(
            Fix(
                "gitignore",
                ".gitignore",
                "*.pfx\n*.p12\n*.jks\n*.keystore\n*.tfstate\n*.tfstate.*\n.git-credentials",
                "text",
            ),
            Fix(
                "terraform",
                "Terraform (backend remoto)",
                'terraform {\n  backend "s3" {\n    bucket  = "meu-estado-terraform"\n'
                '    key     = "prod/terraform.tfstate"\n    region  = "sa-east-1"\n    encrypt = true\n  }\n}',
                "hcl",
            ),
        ),
        verify="git ls-files não lista o arquivo e as credenciais foram trocadas.",
        effort="medio",
        fix_group="segredos",
        references=(
            "https://developer.hashicorp.com/terraform/language/state/sensitive-data",
            *_SECRET_REFS,
        ),
        cwe="CWE-540",
        owasp="A05:2021",
        cis=("3.11", "16.12"),
        lgpd=True,
        tags=("segredos", "arquivo"),
    ),
)
