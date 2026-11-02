"""Base de conhecimento: bancos de dados e caches expostos ou sem autenticação."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity


def _no_auth(
    *,
    id: str,
    product: str,
    summary: str,
    explanation: str,
    steps: tuple[str, ...],
    examples: tuple[Fix, ...],
    verify: str,
    references: tuple[str, ...],
    severity: Severity = Severity.CRITICAL,
    tags: tuple[str, ...] = (),
) -> KBEntry:
    """Entrada padrão de "serviço de dados sem senha" (mesmo risco, correção específica)."""
    return KBEntry(
        id=id,
        title=f"{product} aceita comandos sem autenticação",
        category=Category.NETWORK,
        severity=severity,
        summary=summary,
        explanation=explanation,
        risk=(
            "Quem alcança a porta lê, altera ou apaga os dados sem precisar de senha. Esse tipo "
            "de serviço exposto é varrido continuamente por robôs que copiam as bases, deixam "
            "pedidos de resgate ou instalam mineradores — e configura incidente de segurança "
            "com dados pessoais (LGPD)."
        ),
        steps=steps,
        examples=examples,
        verify=verify,
        effort="medio",
        fix_group="autenticacao",
        references=references,
        cwe="CWE-306",
        owasp="A07:2021",
        cis=("3.3", "4.7", "12.2"),
        lgpd=True,
        tags=("banco-de-dados", "sem-senha", *tags),
    )


kb.register(
    KBEntry(
        id="net.banco.exposto",
        title="Banco de dados ou cache acessível pela rede",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="A porta de um banco de dados ou cache aceita conexões vindas de fora do servidor.",
        explanation=(
            "Bancos de dados (MySQL, PostgreSQL, SQL Server, Oracle, MongoDB...) e caches "
            "(Redis, Memcached) foram feitos para conversar com a aplicação, não com a Internet. "
            "A porta aberta permite que qualquer um tente senhas, explore falhas do produto e "
            "descubra a versão em uso."
        ),
        risk=(
            "Ataques de força bruta contra o banco, exploração de vulnerabilidades sem "
            "autenticação e, com uma senha fraca, o vazamento de toda a base — com impacto "
            "direto na LGPD."
        ),
        steps=(
            "Faça o banco escutar apenas em 127.0.0.1 ou na rede interna da aplicação.",
            "Restrinja a porta no firewall aos servidores de aplicação que realmente a usam.",
            "Para acesso administrativo remoto, use VPN ou túnel SSH em vez de abrir a porta.",
            "Confirme que todas as contas têm senha forte e que o TLS está ativo no banco.",
        ),
        examples=(
            Fix("mysql", "MySQL/MariaDB (my.cnf)", "[mysqld]\nbind-address = 127.0.0.1", "text"),
            Fix(
                "postgresql",
                "PostgreSQL (postgresql.conf e pg_hba.conf)",
                "listen_addresses = 'localhost'\n"
                "# pg_hba.conf: só a rede da aplicação, com senha forte\n"
                "hostssl  app_db  app_user  10.0.0.0/24  scram-sha-256",
                "text",
            ),
            Fix(
                "mongodb",
                "MongoDB (mongod.conf)",
                "net:\n  bindIp: 127.0.0.1\n  port: 27017",
                "yaml",
            ),
            Fix("redis", "Redis (redis.conf)", "bind 127.0.0.1 -::1\nprotected-mode yes", "text"),
            Fix(
                "linux",
                "Linux (ufw)",
                "sudo ufw deny 3306/tcp\nsudo ufw allow from 10.0.0.10 to any port 5432 proto tcp",
                "bash",
            ),
            Fix(
                "windows",
                "Windows (PowerShell, firewall do SQL Server)",
                'New-NetFirewallRule -DisplayName "SQL Server so da aplicacao" -Direction Inbound '
                "-Protocol TCP -LocalPort 1433 -RemoteAddress 10.0.0.10 -Action Allow",
                "powershell",
            ),
            Fix(
                "docker",
                "Docker Compose (publicar só no localhost)",
                'services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"',
                "yaml",
            ),
        ),
        verify="De um endereço externo, a porta do banco deve aparecer como fechada ou filtrada.",
        effort="baixo",
        fix_group="servicos",
        references=(
            "https://www.mongodb.com/docs/manual/administration/security-checklist/",
            "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        lgpd=True,
        tags=("banco-de-dados", "exposicao"),
    ),
    _no_auth(
        id="net.redis.sem_senha",
        product="Redis",
        summary="O Redis respondeu a comandos sem pedir senha.",
        explanation=(
            "O Redis foi projetado para redes confiáveis e, sem 'requirepass' ou ACL, aceita "
            "qualquer comando de quem alcançar a porta — inclusive comandos que alteram a "
            "configuração e gravam arquivos no disco do servidor."
        ),
        steps=(
            "Faça o Redis escutar só em 127.0.0.1 (ou na rede interna) e mantenha o modo protegido.",
            "Defina uma senha longa e aleatória (requirepass) ou usuários com ACL (Redis 6+).",
            "Desative ou renomeie comandos perigosos (CONFIG, FLUSHALL, MODULE) para a aplicação.",
            "Bloqueie a porta 6379 no firewall para endereços externos.",
        ),
        examples=(
            Fix(
                "redis",
                "Redis (redis.conf)",
                "bind 127.0.0.1 -::1\nprotected-mode yes\n"
                'requirepass <senha-longa-e-aleatoria>\nrename-command CONFIG ""',
                "text",
            ),
            Fix("linux", "Linux (ufw)", "sudo ufw deny 6379/tcp", "bash"),
        ),
        verify="'redis-cli -h servidor ping' deve responder NOAUTH (ou não conectar).",
        references=("https://redis.io/docs/latest/operate/oss_and_stack/management/security/",),
        tags=("redis",),
    ),
    _no_auth(
        id="net.mongodb.sem_senha",
        product="MongoDB",
        summary="O MongoDB listou os bancos de dados sem pedir credenciais.",
        explanation=(
            "Sem 'security.authorization' ativo, o MongoDB entrega todos os bancos a quem "
            "conectar. É uma das causas mais comuns de vazamentos em massa e de bases apagadas "
            "com pedido de resgate."
        ),
        steps=(
            "Crie um usuário administrador e ative a autorização (security.authorization: enabled).",
            "Faça o MongoDB escutar só em 127.0.0.1 ou na rede interna (net.bindIp).",
            "Crie usuários com o mínimo de privilégio para cada aplicação.",
            "Bloqueie a porta 27017 para a Internet e revise os logs em busca de acessos estranhos.",
        ),
        examples=(
            Fix(
                "mongodb",
                "MongoDB (mongosh + mongod.conf)",
                'use admin\ndb.createUser({user: "admin", pwd: passwordPrompt(),\n'
                '  roles: [{role: "userAdminAnyDatabase", db: "admin"}]})\n\n'
                "# mongod.conf\nnet:\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled",
                "yaml",
            ),
        ),
        verify="'mongosh --host servidor --eval \"db.adminCommand({listDatabases: 1})\"' deve falhar com erro de autenticação.",
        references=("https://www.mongodb.com/docs/manual/administration/security-checklist/",),
        tags=("mongodb",),
    ),
    _no_auth(
        id="net.elasticsearch.sem_senha",
        product="Elasticsearch/OpenSearch",
        summary="O cluster Elasticsearch/OpenSearch respondeu sem pedir usuário e senha.",
        explanation=(
            "Com a segurança desligada, a API REST do Elasticsearch permite ler, alterar e "
            "apagar índices inteiros. Versões 8.0+ ativam a segurança por padrão; clusters "
            "antigos ou configurados com 'xpack.security.enabled: false' ficam abertos."
        ),
        steps=(
            "Ative a segurança (xpack.security.enabled: true) e defina as senhas dos usuários internos.",
            "Faça o cluster escutar só na rede interna (network.host) e ative TLS na camada HTTP.",
            "Bloqueie as portas 9200/9300 para a Internet.",
        ),
        examples=(
            Fix(
                "elasticsearch",
                "Elasticsearch (elasticsearch.yml)",
                "xpack.security.enabled: true\nxpack.security.http.ssl.enabled: true\n"
                "network.host: 10.0.0.5\n\n# depois: bin/elasticsearch-reset-password -u elastic",
                "yaml",
            ),
            Fix(
                "opensearch",
                "OpenSearch (opensearch.yml)",
                "plugins.security.disabled: false\nnetwork.host: 10.0.0.5",
                "yaml",
            ),
        ),
        verify="'curl http://servidor:9200/_cluster/health' deve responder 401 (autenticação exigida).",
        references=("https://www.elastic.co/docs/deploy-manage/security/set-up-minimal-security",),
        tags=("elasticsearch",),
    ),
    _no_auth(
        id="net.memcached.sem_senha",
        product="Memcached",
        severity=Severity.HIGH,
        summary="O Memcached entregou estatísticas e aceita comandos sem autenticação.",
        explanation=(
            "O protocolo texto do Memcached não tem autenticação: quem alcança a porta lê e "
            "grava qualquer chave do cache (sessões, tokens, dados de usuários). Com UDP "
            "ativo, ele ainda serve de amplificador em ataques DDoS."
        ),
        steps=(
            "Faça o Memcached escutar só em 127.0.0.1 ou na rede da aplicação (-l).",
            "Desative o UDP (-U 0), que não é necessário para a maioria das aplicações.",
            "Se precisar de acesso remoto, use SASL (-S, só protocolo binário) e firewall.",
        ),
        examples=(
            Fix(
                "memcached",
                "Memcached (/etc/memcached.conf)",
                "-l 127.0.0.1\n-U 0",
                "text",
            ),
            Fix("linux", "Linux (ufw)", "sudo ufw deny 11211", "bash"),
        ),
        verify="'printf \"stats\\r\\nquit\\r\\n\" | nc servidor 11211' de fora não deve responder.",
        references=(
            "https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks",
            "https://github.com/memcached/memcached/wiki/SASLHowto",
        ),
        tags=("memcached",),
    ),
    _no_auth(
        id="net.couchdb.sem_senha",
        product="CouchDB",
        summary="O CouchDB listou os bancos de dados (/_all_dbs) sem autenticação.",
        explanation=(
            "Instalações antigas do CouchDB (o chamado 'admin party') ou configuradas sem "
            "exigir usuário válido deixam a API HTTP aberta: a lista de bancos — e muitas vezes "
            "os documentos — fica disponível para qualquer um."
        ),
        steps=(
            "Crie um administrador e exija usuário válido em todas as requisições.",
            "Atualize para a versão 3.x, que exige administrador para iniciar.",
            "Faça o CouchDB escutar só na rede interna e bloqueie a porta 5984 para a Internet.",
        ),
        examples=(
            Fix(
                "couchdb",
                "CouchDB (local.ini)",
                "[admins]\nadmin = <senha-longa>\n\n[chttpd]\nrequire_valid_user = true\n"
                "bind_address = 127.0.0.1",
                "text",
            ),
        ),
        verify="'curl http://servidor:5984/_all_dbs' deve responder 401.",
        references=("https://docs.couchdb.org/en/stable/intro/security.html",),
        tags=("couchdb",),
    ),
    _no_auth(
        id="net.influxdb.sem_senha",
        product="InfluxDB",
        severity=Severity.HIGH,
        summary="O InfluxDB executou uma consulta (SHOW DATABASES) sem credenciais.",
        explanation=(
            "No InfluxDB 1.x a autenticação vem desligada por padrão: todas as credenciais são "
            "ignoradas e qualquer cliente tem todos os privilégios — ler métricas, apagar "
            "bancos e criar usuários."
        ),
        steps=(
            "Crie um usuário administrador e ative auth-enabled na seção [http].",
            "Faça o serviço escutar só na rede interna e bloqueie a porta 8086 para a Internet.",
            "Considere migrar para uma versão atual do InfluxDB, que exige token por padrão.",
        ),
        examples=(
            Fix(
                "influxdb",
                "InfluxDB 1.x (influxdb.conf)",
                "CREATE USER admin WITH PASSWORD '<senha-longa>' WITH ALL PRIVILEGES\n\n"
                '[http]\n  auth-enabled = true\n  bind-address = "127.0.0.1:8086"',
                "text",
            ),
        ),
        verify="'curl \"http://servidor:8086/query?q=SHOW%20DATABASES\"' deve responder 401.",
        references=(
            "https://docs.influxdata.com/influxdb/v1/administration/authentication_and_authorization/",
        ),
        tags=("influxdb",),
    ),
    _no_auth(
        id="net.clickhouse.sem_senha",
        product="ClickHouse",
        summary="O ClickHouse executou uma consulta (SELECT version()) sem credenciais.",
        explanation=(
            "A interface HTTP do ClickHouse aceitou uma consulta sem usuário e senha — ou seja, "
            "o usuário 'default' está sem senha e aberto para a rede. Ele costuma ter acesso a "
            "todas as tabelas."
        ),
        steps=(
            "Defina senha (hash SHA-256) para o usuário 'default' ou desative-o após criar um administrador.",
            "Restrinja de quais redes cada usuário pode conectar (<networks>).",
            "Bloqueie as portas 8123 e 9000 para a Internet.",
        ),
        examples=(
            Fix(
                "clickhouse",
                "ClickHouse (users.d/default.xml)",
                "<clickhouse>\n  <users>\n    <default>\n"
                "      <password_sha256_hex>HASH_SHA256_DA_SENHA</password_sha256_hex>\n"
                "      <networks><ip>127.0.0.1</ip><ip>10.0.0.0/24</ip></networks>\n"
                "    </default>\n  </users>\n</clickhouse>",
                "xml",
            ),
        ),
        verify="'curl \"http://servidor:8123/?query=SELECT%201\"' deve recusar a consulta com erro de autenticação.",
        references=("https://clickhouse.com/docs/en/operations/access-rights",),
        tags=("clickhouse",),
    ),
    _no_auth(
        id="net.cassandra.sem_senha",
        product="Cassandra",
        severity=Severity.HIGH,
        summary="O Cassandra aceitou a conexão CQL sem pedir autenticação (AllowAllAuthenticator).",
        explanation=(
            "O autenticador padrão do Cassandra (AllowAllAuthenticator) não verifica "
            "credenciais: qualquer cliente que alcance a porta 9042 pode ler e alterar as "
            "tabelas."
        ),
        steps=(
            "Ative PasswordAuthenticator e CassandraAuthorizer no cassandra.yaml e reinicie os nós.",
            "Crie um superusuário novo e desative o padrão 'cassandra'.",
            "Restrinja a porta 9042 (e 7000/7199) à rede da aplicação.",
        ),
        examples=(
            Fix(
                "cassandra",
                "Cassandra (cassandra.yaml + cqlsh)",
                "authenticator: PasswordAuthenticator\nauthorizer: CassandraAuthorizer\n\n"
                "-- depois, no cqlsh:\n"
                "CREATE ROLE admin WITH SUPERUSER = true AND LOGIN = true AND PASSWORD = '<senha>';\n"
                "ALTER ROLE cassandra WITH SUPERUSER = false AND LOGIN = false;",
                "yaml",
            ),
        ),
        verify="'cqlsh servidor' sem usuário deve falhar pedindo autenticação.",
        references=(
            "https://cassandra.apache.org/doc/latest/cassandra/managing/operating/security.html",
        ),
        tags=("cassandra",),
    ),
)
