"""Base de conhecimento das dependências vulneráveis e maliciosas."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

VULNERABLE = "code.dependencia.vulneravel"
MALICIOUS = "code.dependencia.maliciosa"

_UPGRADE_EXAMPLES = (
    Fix(
        "npm",
        "npm",
        "npm install lodash@4.17.21\n"
        "# dependência indireta: package.json\n"
        '# "overrides": { "lodash": "4.17.21" }\n'
        "npm audit",
        "bash",
    ),
    Fix(
        "yarn",
        "Yarn",
        'yarn up lodash@4.17.21\n# dependência indireta (package.json):\n# "resolutions": { "lodash": "4.17.21" }',
        "bash",
    ),
    Fix(
        "python",
        "pip / Poetry",
        'pip install --upgrade "requests>=2.32.0"\npip freeze > requirements.txt\n'
        "# Poetry:\npoetry add requests@^2.32.0\n# conferir: pip-audit",
        "bash",
    ),
    Fix(
        "maven",
        "Maven (pom.xml)",
        "<!-- versão direta ou forçada para dependências indiretas -->\n"
        "<dependencyManagement>\n  <dependencies>\n    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "      <version>2.17.1</version>\n"
        "    </dependency>\n  </dependencies>\n</dependencyManagement>",
        "xml",
    ),
    Fix(
        "gradle",
        "Gradle",
        "dependencies {\n"
        '    implementation("org.apache.logging.log4j:log4j-core:2.17.1")\n'
        "}\n// depois: ./gradlew dependencies --write-locks",
        "kotlin",
    ),
    Fix(
        "composer",
        "Composer (PHP)",
        'composer require "guzzlehttp/guzzle:^7.4.5"\ncomposer update --with-dependencies guzzlehttp/guzzle\ncomposer audit',
        "bash",
    ),
    Fix(
        "bundler",
        "Bundler (Ruby)",
        "bundle update --conservative nokogiri\nbundle exec bundler-audit check --update",
        "bash",
    ),
    Fix(
        "dotnet",
        ".NET (NuGet)",
        "dotnet add package Newtonsoft.Json --version 13.0.3\n"
        "dotnet list package --vulnerable --include-transitive",
        "bash",
    ),
    Fix(
        "go",
        "Go modules",
        "go get golang.org/x/crypto@latest\ngo mod tidy\ngovulncheck ./...",
        "bash",
    ),
    Fix("cargo", "Cargo (Rust)", "cargo update -p smallvec\ncargo audit", "bash"),
)

kb.register(
    KBEntry(
        id=VULNERABLE,
        title="Dependência com vulnerabilidade conhecida",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="O projeto usa uma versão de biblioteca com falha de segurança publicada.",
        explanation=(
            "Bibliotecas de terceiros fazem parte da aplicação: se a versão instalada tem uma "
            "vulnerabilidade pública (CVE/GHSA), o seu sistema herda a falha. O EIGAN comparou as "
            "versões do manifesto/lockfile com avisos publicados e encontrou esta versão dentro "
            "da faixa afetada. A versão corrigida e o link de cada aviso estão nos detalhes."
        ),
        risk=(
            "Falhas publicadas têm descrição e, muitas vezes, código de exploração disponível. "
            "Dependendo do aviso, um atacante pode executar código no servidor (ex.: Log4Shell), "
            "ler dados, derrubar o serviço ou contornar a autenticação. Avisos marcados como KEV "
            "já são explorados em ataques reais."
        ),
        steps=(
            "Veja nos detalhes a versão corrigida indicada e atualize o pacote.",
            "Se a dependência é indireta (vem de outro pacote), atualize o pacote 'pai' ou force "
            "a versão (overrides/resolutions no npm, dependencyManagement no Maven, constraints no pip).",
            "Regere o lockfile, rode os testes e publique a nova versão da aplicação.",
            "Sem correção publicada (pacote abandonado)? Troque por uma alternativa mantida ou "
            "aplique a mitigação descrita no aviso.",
            "Automatize: alertas de dependências (Dependabot/Renovate) e o EIGAN no CI.",
        ),
        examples=_UPGRADE_EXAMPLES,
        verify=(
            "Rode o EIGAN de novo (ou npm audit, pip-audit, dotnet list package --vulnerable): "
            "o pacote não deve mais aparecer."
        ),
        effort="medio",
        fix_group="dependencias",
        references=(
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://github.com/advisories",
            "https://osv.dev/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.4", "16.4"),
        tags=("dependencias", "sca", "cve"),
    ),
    KBEntry(
        id=MALICIOUS,
        title="Pacote malicioso ou sequestrado nas dependências",
        category=Category.CODE,
        severity=Severity.CRITICAL,
        summary="Uma versão instalada foi publicada com código malicioso (ataque à cadeia de suprimentos).",
        explanation=(
            "Algumas versões de pacotes foram publicadas por invasores (conta do mantenedor "
            "sequestrada) ou de propósito com código nocivo: roubo de credenciais, mineração de "
            "criptomoedas, apagamento de arquivos. Não é um defeito, é um ataque que roda já na "
            "instalação (scripts de install) ou no uso do pacote."
        ),
        risk=(
            "Qualquer máquina que instalou a versão (estações de desenvolvimento, CI, servidores) "
            "deve ser considerada comprometida: tokens, chaves SSH, variáveis de ambiente e senhas "
            "salvas podem ter sido enviados ao atacante."
        ),
        steps=(
            "Remova a versão maliciosa e fixe uma versão limpa indicada no aviso; regere o lockfile.",
            "Trate como incidente: descubra quais máquinas e pipelines instalaram o pacote.",
            "A partir de uma máquina limpa, troque todos os segredos acessíveis nessas máquinas "
            "(tokens de nuvem, npm/PyPI, GitHub, chaves SSH, senhas de banco).",
            "Reinstale ou restaure as máquinas afetadas a partir de imagem confiável.",
            "Previna: lockfiles com integridade, 'npm ci', revisão de dependências novas e "
            "scripts de instalação desligados quando possível (npm --ignore-scripts).",
        ),
        examples=(
            Fix(
                "npm",
                "npm",
                "npm uninstall flatmap-stream event-stream\n"
                "npm install ua-parser-js@0.7.30\n"
                "npm ci --ignore-scripts",
                "bash",
            ),
            Fix(
                "python",
                "pip",
                "pip uninstall -y <pacote>\npip install --require-hashes -r requirements.txt",
                "bash",
            ),
            Fix(
                "yarn",
                "Yarn",
                "yarn remove <pacote>\nyarn install --frozen-lockfile --ignore-scripts",
                "bash",
            ),
            Fix(
                "maven",
                "Maven",
                "# remova o <dependency> do pom.xml e reconstrua\nmvn -U clean verify",
                "bash",
            ),
            Fix(
                "gradle",
                "Gradle",
                "# remova a linha do build.gradle\n./gradlew dependencies --write-locks",
                "bash",
            ),
            Fix(
                "composer",
                "Composer",
                "composer remove <vendor>/<pacote>\ncomposer install --no-scripts",
                "bash",
            ),
            Fix("bundler", "Bundler", "bundle remove <gem>\nbundle install", "bash"),
            Fix(
                "dotnet",
                ".NET",
                "dotnet remove package <Pacote>\ndotnet restore --locked-mode",
                "bash",
            ),
            Fix("go", "Go", "go get <modulo>@none\ngo mod tidy && go mod verify", "bash"),
            Fix("cargo", "Cargo", "cargo remove <crate>\ncargo update && cargo audit", "bash"),
        ),
        verify="O lockfile não contém mais a versão maliciosa e os segredos expostos foram trocados.",
        effort="alto",
        fix_group="dependencias",
        references=(
            "https://github.com/advisories?query=type%3Amalware",
            "https://github.com/ossf/malicious-packages",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ),
        cwe="CWE-506",
        owasp="A08:2021",
        cis=("16.4", "16.11"),
        tags=("dependencias", "cadeia-de-suprimentos", "malware"),
    ),
)
