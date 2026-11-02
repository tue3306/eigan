"""Base de conhecimento dos padrões inseguros no código (SAST por regras)."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .sast_common import (
    CLASSIFICATION,
    COMMAND,
    DESER,
    EVAL,
    JWT,
    PHP_EXTRACT,
    PHP_INCLUDE,
    SQL,
    TLS,
    WEAK_HASH,
    WEAK_RANDOM,
    XSS,
    XXE,
)

_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_REVIEW = (
    "Este achado vem de uma regra sobre o texto do código: ele aponta onde olhar, não prova "
    "que há falha. Se o valor é sempre fixo ou vem de uma lista fechada pelo próprio programa, "
    "registre a exceção; se alguma parte vem de quem usa o sistema, corrija."
)
_CIS = ("16.12", "16.1")


def _entry(
    finding: str,
    *,
    title: str,
    severity: Severity,
    summary: str,
    explanation: str,
    risk: str,
    steps: tuple[str, ...],
    verify: str,
    examples: tuple[Fix, ...],
    references: tuple[str, ...],
    cis: tuple[str, ...] = _CIS,
    lgpd: bool = False,
) -> KBEntry:
    cwe, owasp = CLASSIFICATION[finding]
    return KBEntry(
        id=finding,
        title=title,
        category=Category.CODE,
        severity=severity,
        summary=summary,
        explanation=f"{explanation} {_REVIEW}",
        risk=risk,
        steps=steps,
        verify=verify,
        examples=examples,
        effort="medio",
        fix_group="codigo",
        references=(
            *references,
            f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
        ),
        cwe=cwe,
        owasp=owasp,
        cis=cis,
        lgpd=lgpd,
        tags=("sast", "codigo"),
    )


kb.register(
    _entry(
        EVAL,
        title="Código executa texto montado em tempo de execução (eval/exec)",
        severity=Severity.HIGH,
        summary="Uma função como eval, exec ou um motor de scripts recebe um valor que não é fixo.",
        explanation=(
            "eval, exec, new Function, ScriptEngine.eval, CSharpScript e parecidos transformam texto em "
            "código e o rodam com as permissões do programa. Se qualquer parte do texto vem de um "
            "formulário, de um parâmetro de URL, de um arquivo enviado ou de um banco de dados que "
            "outras pessoas preenchem, quem controla essa parte controla o programa."
        ),
        risk=(
            "Execução remota de código: o atacante lê arquivos, apaga dados, abre conexões para fora "
            "e assume o servidor onde o sistema roda."
        ),
        steps=(
            "Troque a execução dinâmica por uma tabela de funções permitidas (dicionário de nome para função).",
            "Para ler dados, use um analisador próprio do formato: json.loads, JSON.parse, ast.literal_eval.",
            "Para cálculos informados pelo usuário, use uma biblioteca de expressões com lista fechada de operações.",
            "Se for inevitável, rode em processo isolado, sem rede e com usuário sem privilégios.",
        ),
        verify="Procure de novo por eval/exec/Function no projeto: sobram só usos com texto fixo.",
        examples=(
            Fix(
                "python",
                "Python: tabela de operações e ast.literal_eval",
                "OPERACOES = {'soma': soma, 'media': media}\nresultado = OPERACOES[nome](*valores)  # nome vem de lista fechada\n"
                "import ast\ndados = ast.literal_eval(texto)  # só literais, nunca chamadas",
                "python",
            ),
            Fix(
                "javascript",
                "JavaScript: JSON.parse e mapa de funções",
                "const dados = JSON.parse(texto);\nconst OPERACOES = { soma, media };\n"
                "const fn = Object.hasOwn(OPERACOES, nome) ? OPERACOES[nome] : null;",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: lista de ações permitidas",
                "$acoes = ['listar' => 'listar', 'excluir' => 'excluir'];\n"
                "if (isset($acoes[$_GET['acao']])) { $acoes[$_GET['acao']](); }",
                "php",
            ),
            Fix(
                "java",
                "Java: mapa de operações em vez de ScriptEngine",
                'Map<String, DoubleBinaryOperator> ops = Map.of("soma", Double::sum);\n'
                "double r = ops.get(nome).applyAsDouble(a, b);",
                "java",
            ),
            Fix(
                "csharp",
                "C#: dicionário de operações",
                'var ops = new Dictionary<string, Func<double, double, double>> { ["soma"] = (a, b) => a + b };\n'
                "var r = ops[nome](a, b);",
                "csharp",
            ),
            Fix(
                "ruby",
                "Ruby: public_send só com lista permitida",
                "PERMITIDOS = %w[listar excluir].freeze\nobj.public_send(acao) if PERMITIDOS.include?(acao)",
                "ruby",
            ),
        ),
        references=(f"{_CS}Injection_Prevention_Cheat_Sheet.html",),
    ),
    _entry(
        COMMAND,
        title="Comando de sistema montado com texto variável",
        severity=Severity.HIGH,
        summary="O código chama um shell ou um programa externo com um comando que inclui variáveis.",
        explanation=(
            "Quando o comando passa por um shell (shell=True, os.system, child_process.exec, sh -c, "
            "cmd /c, crases do PHP e do Ruby), caracteres como ; & | $( ) viram novos comandos. Basta um "
            "nome de arquivo ou um host digitado pelo usuário conter esses caracteres."
        ),
        risk="Execução de comandos no servidor com as permissões do programa (injeção de comando).",
        steps=(
            "Chame o programa sem shell, com os argumentos em lista: cada argumento é um item separado.",
            "Prefira a biblioteca da linguagem à ferramenta de linha de comando (por exemplo, zipfile em vez de zip).",
            "Valide o valor contra uma lista permitida ou um padrão estrito antes de usá-lo.",
            "Se precisar mesmo de shell, escape cada valor com a função da linguagem (shlex.quote, escapeshellarg).",
        ),
        verify="Teste com um valor como `a; id`: o programa deve tratá-lo como um nome qualquer, sem rodar `id`.",
        examples=(
            Fix(
                "python",
                "Python: lista de argumentos, sem shell",
                "import subprocess\nsubprocess.run(['ping', '-c', '1', host], check=True, timeout=10)",
                "python",
            ),
            Fix(
                "javascript",
                "Node.js: execFile com argumentos separados",
                "const { execFile } = require('node:child_process');\nexecFile('ping', ['-c', '1', host], { timeout: 10000 }, cb);",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: escapeshellarg",
                "$saida = shell_exec('ping -c 1 ' . escapeshellarg($host));",
                "php",
            ),
            Fix(
                "java",
                "Java: ProcessBuilder com lista, sem shell",
                'new ProcessBuilder("ping", "-c", "1", host).redirectErrorStream(true).start();',
                "java",
            ),
            Fix(
                "csharp",
                "C#: ArgumentList em vez de Arguments",
                'var psi = new ProcessStartInfo("ping") { UseShellExecute = false };\npsi.ArgumentList.Add("-n");\n'
                'psi.ArgumentList.Add("1");\npsi.ArgumentList.Add(host);',
                "csharp",
            ),
            Fix(
                "go",
                "Go: argumentos separados",
                'cmd := exec.Command("ping", "-c", "1", host)\nout, err := cmd.Output()',
                "go",
            ),
            Fix(
                "ruby",
                "Ruby: system com argumentos separados",
                "system('ping', '-c', '1', host)",
                "ruby",
            ),
        ),
        references=(
            f"{_CS}OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://docs.python.org/3/library/subprocess.html#security-considerations",
        ),
    ),
    _entry(
        DESER,
        title="Desserialização de dados que podem ser controlados por terceiros",
        severity=Severity.HIGH,
        summary="O código recria objetos a partir de bytes ou texto com um formato que pode executar código.",
        explanation=(
            "pickle, yaml.load sem SafeLoader, unserialize do PHP, ObjectInputStream, XMLDecoder, "
            "BinaryFormatter, Marshal.load e node-serialize reconstroem objetos de qualquer classe "
            "disponível. Um atacante monta bytes que, ao serem lidos, encadeiam chamadas até rodar código. "
            "A documentação da Microsoft diz que o BinaryFormatter não pode ser tornado seguro."
        ),
        risk="Execução remota de código ao ler um arquivo, cookie ou mensagem preparado.",
        steps=(
            "Troque o formato por JSON (ou outro formato só de dados) e valide os campos.",
            "yaml: use yaml.safe_load. PHP: use json_decode, ou unserialize com allowed_classes => false.",
            "Java: use uma lista de classes permitidas (ObjectInputFilter) ou abandone a serialização nativa.",
            "C#: substitua BinaryFormatter por System.Text.Json; não use TypeNameHandling.All/Auto.",
            "Se precisa manter o formato, assine os dados (HMAC) e só leia o que foi assinado por você.",
        ),
        verify="Procure por pickle.load, unserialize, ObjectInputStream e BinaryFormatter: não devem ler dados externos.",
        examples=(
            Fix(
                "python",
                "Python: safe_load e json",
                "import yaml, json\ndados = yaml.safe_load(texto)\ndados = json.loads(texto)",
                "python",
            ),
            Fix(
                "php",
                "PHP: JSON ou classes proibidas",
                "$dados = json_decode($texto, true);\n$obj = unserialize($texto, ['allowed_classes' => false]);",
                "php",
            ),
            Fix(
                "java",
                "Java: filtro de classes (JEP 290)",
                'ObjectInputFilter filtro = ObjectInputFilter.Config.createFilter("com.minhaempresa.dto.*;!*");\n'
                "ois.setObjectInputFilter(filtro);",
                "java",
            ),
            Fix(
                "csharp",
                "C#: System.Text.Json",
                "var dados = System.Text.Json.JsonSerializer.Deserialize<Pedido>(texto);",
                "csharp",
            ),
            Fix(
                "ruby",
                "Ruby: YAML seguro e JSON",
                "dados = YAML.safe_load(texto, permitted_classes: [Symbol])\ndados = JSON.parse(texto)",
                "ruby",
            ),
            Fix(
                "javascript",
                "Node.js: JSON.parse",
                "const dados = JSON.parse(texto);",
                "javascript",
            ),
        ),
        references=(
            f"{_CS}Deserialization_Cheat_Sheet.html",
            "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
            "https://docs.python.org/3/library/pickle.html",
        ),
    ),
    _entry(
        SQL,
        title="Consulta SQL montada com texto variável (injeção de SQL)",
        severity=Severity.HIGH,
        summary="Uma consulta ao banco é montada juntando texto e variáveis em vez de usar parâmetros.",
        explanation=(
            "Concatenar, usar format, f-string ou interpolação dentro do SQL faz o valor virar parte do "
            "comando. Um nome como `' OR '1'='1` muda o significado da consulta. Consultas parametrizadas "
            "enviam o comando e os valores separados, e o banco nunca confunde um com o outro."
        ),
        risk="Leitura, alteração ou apagamento de qualquer dado do banco, e login sem senha.",
        steps=(
            "Troque os valores por marcadores (?, %s, @nome, $1) e passe os valores à parte.",
            "Para nomes de tabela ou coluna (que não aceitam parâmetros), escolha de uma lista fixa.",
            "Use o ORM com filtros por parâmetro em vez de montar SQL na mão.",
            "Dê ao usuário do banco só as permissões que o sistema usa.",
        ),
        verify="Envie `'` e `' OR '1'='1` nos campos: a aplicação deve tratar como texto comum, sem erro de SQL.",
        examples=(
            Fix(
                "python",
                "Python: parâmetros do driver",
                "cur.execute('SELECT * FROM usuarios WHERE id = %s', (uid,))",
                "python",
            ),
            Fix(
                "javascript",
                "Node.js: placeholders",
                "await pool.query('SELECT * FROM usuarios WHERE id = $1', [uid]);",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: PDO com prepare",
                "$st = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id');\n$st->execute(['id' => $uid]);",
                "php",
            ),
            Fix(
                "java",
                "Java: PreparedStatement",
                'PreparedStatement ps = con.prepareStatement("SELECT * FROM usuarios WHERE id = ?");\nps.setLong(1, uid);',
                "java",
            ),
            Fix(
                "csharp",
                "C#: SqlParameter",
                'var cmd = new SqlCommand("SELECT * FROM Usuarios WHERE Id = @id", con);\ncmd.Parameters.AddWithValue("@id", uid);',
                "csharp",
            ),
            Fix(
                "go",
                "Go: database/sql com ?",
                'row := db.QueryRowContext(ctx, "SELECT * FROM usuarios WHERE id = ?", uid)',
                "go",
            ),
            Fix(
                "ruby",
                "Ruby: ActiveRecord com hash",
                "Usuario.where(id: uid)\nUsuario.where('email = ?', email)",
                "ruby",
            ),
        ),
        references=(
            f"{_CS}SQL_Injection_Prevention_Cheat_Sheet.html",
            f"{_CS}Query_Parameterization_Cheat_Sheet.html",
        ),
        lgpd=True,
    ),
    _entry(
        TLS,
        title="Código desliga a validação do certificado TLS",
        severity=Severity.HIGH,
        summary="Uma conexão HTTPS/TLS é aberta sem conferir o certificado ou o nome do servidor.",
        explanation=(
            "verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, InsecureSkipVerify, "
            "TrustManager vazio e callbacks que retornam true fazem o programa aceitar qualquer certificado. "
            "Isso costuma ser posto para 'fazer funcionar' com um certificado de teste e esquecido em produção."
        ),
        risk="Um atacante na rede lê e altera o tráfego (inclusive senhas e tokens) sem que o programa perceba.",
        steps=(
            "Remova a opção que desliga a validação.",
            "Instale o certificado da sua autoridade interna no repositório de confiança, ou aponte para ele (CA bundle).",
            "Em desenvolvimento, use um certificado de teste confiável (mkcert) em vez de desligar a validação.",
            "Nunca defina NODE_TLS_REJECT_UNAUTHORIZED=0 no ambiente de produção.",
        ),
        verify="A conexão deve falhar ao apontar para um servidor com certificado inválido (por exemplo, um host com certificado vencido).",
        examples=(
            Fix(
                "python",
                "Python: CA própria",
                "requests.get(url, verify='/etc/ssl/certs/minha-ca.pem', timeout=10)",
                "python",
            ),
            Fix(
                "javascript",
                "Node.js: CA própria",
                "const agent = new https.Agent({ ca: fs.readFileSync('minha-ca.pem') });\nhttps.get(url, { agent });",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: cURL validando",
                "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);\ncurl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);",
                "php",
            ),
            Fix(
                "java",
                "Java: truststore com a CA",
                "-Djavax.net.ssl.trustStore=/etc/app/truststore.p12 -Djavax.net.ssl.trustStorePassword=...",
                "text",
            ),
            Fix(
                "csharp",
                "C#: sem callback permissivo",
                "var handler = new HttpClientHandler(); // validação padrão ligada\nvar http = new HttpClient(handler);",
                "csharp",
            ),
            Fix(
                "go",
                "Go: RootCAs com a CA",
                "pool := x509.NewCertPool()\npool.AppendCertsFromPEM(pem)\ncfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}",
                "go",
            ),
            Fix(
                "ruby", "Ruby: VERIFY_PEER", "http.verify_mode = OpenSSL::SSL::VERIFY_PEER", "ruby"
            ),
        ),
        references=(
            f"{_CS}Transport_Layer_Security_Cheat_Sheet.html",
            "https://pkg.go.dev/crypto/tls#Config",
        ),
        cis=("3.10", "16.12"),
    ),
    _entry(
        WEAK_HASH,
        title="Senha protegida com hash rápido e fraco (MD5 ou SHA-1)",
        severity=Severity.HIGH,
        summary="O código usa MD5 ou SHA-1 para guardar ou comparar senhas.",
        explanation=(
            "MD5 e SHA-1 são rápidos de propósito e já têm colisões conhecidas. Uma placa de vídeo testa "
            "bilhões de senhas por segundo contra eles; sem sal (salt), tabelas prontas quebram a maioria "
            "das senhas em minutos. Senhas pedem algoritmos lentos e com sal: Argon2id, scrypt, bcrypt ou PBKDF2."
        ),
        risk="Se a tabela de usuários vazar, quase todas as senhas são descobertas e reusadas em outros serviços.",
        steps=(
            "Troque por Argon2id (preferido), scrypt ou bcrypt, usando a biblioteca padrão do framework.",
            "Migre sem pedir reset: no próximo login correto, recalcule o hash com o novo algoritmo.",
            "Se precisa de hash para outra finalidade (integridade, cache), use SHA-256 e deixe claro no nome da função.",
        ),
        verify="Procure por md5/sha1 perto de senhas: o armazenamento deve usar a função de senha do framework.",
        examples=(
            Fix(
                "python",
                "Python: argon2-cffi ou hashlib.scrypt",
                "from argon2 import PasswordHasher\nph = PasswordHasher()\nhash_ = ph.hash(senha)\nph.verify(hash_, senha)",
                "python",
            ),
            Fix(
                "javascript",
                "Node.js: crypto.scrypt ou bcrypt",
                "const hash = await bcrypt.hash(senha, 12);\nawait bcrypt.compare(senha, hash);",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: password_hash",
                "$hash = password_hash($senha, PASSWORD_ARGON2ID);\npassword_verify($senha, $hash);",
                "php",
            ),
            Fix(
                "java",
                "Java: Spring Security",
                "PasswordEncoder enc = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();\nString hash = enc.encode(senha);",
                "java",
            ),
            Fix(
                "csharp",
                "C#: PasswordHasher do Identity",
                "var hasher = new PasswordHasher<Usuario>();\nvar hash = hasher.HashPassword(usuario, senha);",
                "csharp",
            ),
            Fix(
                "go",
                "Go: bcrypt",
                "hash, err := bcrypt.GenerateFromPassword([]byte(senha), bcrypt.DefaultCost)",
                "go",
            ),
            Fix(
                "ruby",
                "Ruby: bcrypt (has_secure_password)",
                "class Usuario < ApplicationRecord\n  has_secure_password\nend",
                "ruby",
            ),
        ),
        references=(f"{_CS}Password_Storage_Cheat_Sheet.html",),
        cis=("3.11", "16.12"),
        lgpd=True,
    ),
    _entry(
        WEAK_RANDOM,
        title="Valor secreto gerado com aleatoriedade previsível",
        severity=Severity.MEDIUM,
        summary="Token, senha temporária ou identificador de sessão é gerado com um sorteador comum.",
        explanation=(
            "random (Python), Math.random (JavaScript), rand/mt_rand (PHP), java.util.Random, System.Random, "
            "math/rand (Go) e Random (Ruby) são feitos para simulações, não para segurança: conhecendo "
            "alguns valores gerados, dá para calcular os próximos. Segredos precisam de um gerador "
            "criptográfico do sistema operacional."
        ),
        risk="Tokens de redefinição de senha, convites e sessões podem ser adivinhados, levando à tomada de contas.",
        steps=(
            "Use o gerador criptográfico da linguagem (veja os exemplos) com pelo menos 128 bits.",
            "Invalide os tokens já emitidos com o gerador antigo.",
            "Faça os tokens expirarem em pouco tempo e valham para uso único.",
        ),
        verify="Procure o gerador comum perto de nomes como token, senha, secret: devem usar o gerador criptográfico.",
        examples=(
            Fix(
                "python",
                "Python: secrets",
                "import secrets\ntoken = secrets.token_urlsafe(32)",
                "python",
            ),
            Fix(
                "javascript",
                "Node.js: crypto",
                "const token = require('node:crypto').randomBytes(32).toString('base64url');",
                "javascript",
            ),
            Fix("php", "PHP: random_bytes", "$token = bin2hex(random_bytes(32));", "php"),
            Fix(
                "java",
                "Java: SecureRandom",
                "byte[] b = new byte[32];\nnew SecureRandom().nextBytes(b);\nString token = Base64.getUrlEncoder().withoutPadding().encodeToString(b);",
                "java",
            ),
            Fix(
                "csharp",
                "C#: RandomNumberGenerator",
                "var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));",
                "csharp",
            ),
            Fix(
                "go",
                "Go: crypto/rand",
                'b := make([]byte, 32)\n_, err := rand.Read(b) // import "crypto/rand"',
                "go",
            ),
            Fix("ruby", "Ruby: SecureRandom", "token = SecureRandom.urlsafe_base64(32)", "ruby"),
        ),
        references=("https://docs.python.org/3/library/secrets.html",),
        cis=("16.12", "16.11"),
    ),
    _entry(
        XSS,
        title="Escrita de texto variável na página como HTML (XSS)",
        severity=Severity.MEDIUM,
        summary="O código insere um valor variável na página sem escapar, podendo executar scripts de terceiros.",
        explanation=(
            "innerHTML, document.write, insertAdjacentHTML, dangerouslySetInnerHTML, v-html, "
            "bypassSecurityTrust, Html.Raw, template.HTML e escrita direta na resposta tratam o texto como HTML. "
            "Se o valor traz um <script> ou um atributo onerror, ele roda no navegador da vítima."
        ),
        risk="Roubo de sessão, ações em nome do usuário e desfiguração da página.",
        steps=(
            "Use textContent (ou o escape automático do framework) em vez de HTML.",
            "Se precisa mesmo de HTML do usuário, limpe com DOMPurify (navegador) ou uma biblioteca de sanitização no servidor.",
            "Ative uma Content-Security-Policy que bloqueie scripts inline como segunda camada.",
        ),
        verify="Digite `<img src=x onerror=alert(1)>` no campo: deve aparecer como texto, sem abrir o alerta.",
        examples=(
            Fix(
                "javascript",
                "JavaScript: textContent ou DOMPurify",
                "el.textContent = valor;\nel.innerHTML = DOMPurify.sanitize(valorHtml);",
                "javascript",
            ),
            Fix(
                "php",
                "PHP: htmlspecialchars",
                "echo htmlspecialchars($valor, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');",
                "php",
            ),
            Fix(
                "java",
                "Java: OWASP Java Encoder",
                'out.println(Encode.forHtml(request.getParameter("nome")));',
                "java",
            ),
            Fix(
                "csharp",
                "C#: Razor escapa sozinho",
                "<p>@Model.Nome</p>  @* sem Html.Raw *@",
                "csharp",
            ),
            Fix(
                "go",
                "Go: html/template escapa sozinho",
                "tmpl.Execute(w, dados) // sem template.HTML()",
                "go",
            ),
        ),
        references=(
            f"{_CS}Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            f"{_CS}DOM_based_XSS_Prevention_Cheat_Sheet.html",
        ),
    ),
    _entry(
        PHP_INCLUDE,
        title="PHP inclui arquivo cujo nome vem da requisição",
        severity=Severity.HIGH,
        summary="include/require recebe um valor de $_GET, $_POST ou $_REQUEST.",
        explanation=(
            "Quando o nome do arquivo incluído vem do usuário, ele escolhe qual arquivo do servidor roda "
            "(inclusão local, com ../ ou wrappers como php://filter) e, com allow_url_include ligado, até "
            "código de outro site."
        ),
        risk="Leitura de arquivos do servidor e execução de código escolhido pelo atacante.",
        steps=(
            "Mapeie opções para arquivos: um array fixo de 'página' para caminho; rejeite o que não estiver nele.",
            "Nunca monte o caminho com o valor recebido; se precisar, use basename() e uma pasta fixa.",
            "Mantenha allow_url_include = Off no php.ini.",
        ),
        verify="Peça ?pagina=../../etc/passwd: deve cair na página padrão ou em erro 404.",
        examples=(
            Fix(
                "php",
                "PHP: lista de páginas permitidas",
                "$paginas = ['inicio' => 'inicio.php', 'contato' => 'contato.php'];\n"
                "$p = $_GET['p'] ?? 'inicio';\ninclude __DIR__ . '/paginas/' . ($paginas[$p] ?? 'inicio.php');",
                "php",
            ),
        ),
        references=("https://www.php.net/manual/en/ini.core.php#ini.allow-url-include",),
    ),
    _entry(
        PHP_EXTRACT,
        title="PHP usa extract() sobre dados da requisição",
        severity=Severity.MEDIUM,
        summary="extract($_GET), extract($_POST) ou parecido cria variáveis com nomes escolhidos pelo usuário.",
        explanation=(
            "extract transforma cada chave do array em uma variável. Com dados da requisição, o usuário "
            "cria ou sobrescreve variáveis do programa (como $admin, $caminho ou $conexao) apenas "
            "acrescentando ?admin=1 na URL."
        ),
        risk="Troca de variáveis internas, desvio de verificações de acesso e porta de entrada para outras falhas.",
        steps=(
            "Leia só os campos que espera, um por um: $nome = $_POST['nome'] ?? ''.",
            "Se usar extract, passe EXTR_SKIP e uma lista de chaves permitidas (array_intersect_key).",
        ),
        verify="Envie um parâmetro extra, como ?admin=1: nenhuma variável do programa deve mudar.",
        examples=(
            Fix(
                "php",
                "PHP: só as chaves esperadas",
                "$dados = array_intersect_key($_POST, array_flip(['nome', 'email']));\n$nome = $dados['nome'] ?? '';",
                "php",
            ),
        ),
        references=("https://www.php.net/manual/en/function.extract.php",),
    ),
    _entry(
        JWT,
        title="Token JWT lido sem verificar a assinatura",
        severity=Severity.HIGH,
        summary="O código decodifica um JWT sem conferir a assinatura, ou aceita tokens sem assinatura.",
        explanation=(
            "Um JWT é só texto em Base64: qualquer pessoa pode alterar o conteúdo (por exemplo, trocar "
            "'role': 'user' por 'admin'). Só a verificação da assinatura prova que o servidor emitiu o "
            "token. Decodificar sem verificar, usar o algoritmo 'none' ou desligar a validação da chave "
            "equivale a confiar no que o cliente disse."
        ),
        risk="Falsificação de identidade e de permissões: qualquer usuário vira administrador.",
        steps=(
            "Use a função que verifica (jwt.decode com key e algorithms, jwt.verify, Jwts.parser().verifyWith).",
            "Fixe a lista de algoritmos aceitos no servidor; nunca aceite 'none'.",
            "Confira também exp, iss e aud do token.",
        ),
        verify="Altere um byte do token: o servidor deve responder 401.",
        examples=(
            Fix(
                "python",
                "PyJWT: verificar com algoritmo fixo",
                "dados = jwt.decode(token, chave, algorithms=['HS256'], audience='meu-app')",
                "python",
            ),
            Fix(
                "javascript",
                "jsonwebtoken: verify",
                "const dados = jwt.verify(token, chave, { algorithms: ['HS256'] });",
                "javascript",
            ),
            Fix(
                "java",
                "java-jwt: verifier",
                "JWT.require(Algorithm.HMAC256(segredo)).build().verify(token);",
                "java",
            ),
            Fix(
                "csharp",
                "ASP.NET Core: validação ligada",
                "options.TokenValidationParameters.ValidateIssuerSigningKey = true;\noptions.TokenValidationParameters.RequireSignedTokens = true;",
                "csharp",
            ),
            Fix(
                "go",
                "golang-jwt: Parse com keyfunc e métodos",
                'tok, err := jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{"HS256"}))',
                "go",
            ),
            Fix(
                "ruby",
                "ruby-jwt: verify true",
                "JWT.decode(token, chave, true, algorithm: 'HS256')",
                "ruby",
            ),
        ),
        references=(
            f"{_CS}JSON_Web_Token_Cheat_Sheet.html",
            "https://datatracker.ietf.org/doc/html/rfc8725",
        ),
        cis=("16.12", "16.11"),
    ),
    _entry(
        XXE,
        title="Leitor de XML com entidades externas habilitadas (XXE)",
        severity=Severity.MEDIUM,
        summary="O parser de XML pode ser configurado, ou está por padrão, para resolver entidades externas.",
        explanation=(
            "Um XML pode declarar entidades que apontam para arquivos locais ou endereços de rede. Se o "
            "parser as resolve, quem envia o XML faz o servidor ler arquivos (/etc/passwd), acessar a rede "
            "interna ou ficar sem memória (bilhão de risadas). Várias bibliotecas Java vêm com isso ligado; "
            "em outras linguagens, só quando alguém habilita."
        ),
        risk="Leitura de arquivos do servidor, requisições à rede interna (SSRF) e negação de serviço.",
        steps=(
            "Desligue o DOCTYPE e as entidades externas no parser (veja os exemplos).",
            "Prefira bibliotecas seguras por padrão (defusedxml em Python).",
            "Se o formato não precisa de XML, troque por JSON.",
        ),
        verify='Envie um XML com <!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]>: deve ser rejeitado.',
        examples=(
            Fix(
                "python",
                "Python: defusedxml",
                "from defusedxml import ElementTree\nraiz = ElementTree.fromstring(texto)",
                "python",
            ),
            Fix(
                "java",
                "Java: DocumentBuilderFactory seguro",
                'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
                "dbf.setXIncludeAware(false);\ndbf.setExpandEntityReferences(false);",
                "java",
            ),
            Fix(
                "csharp",
                "C#: DTD proibido",
                "var cfg = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };",
                "csharp",
            ),
            Fix(
                "php",
                "PHP: sem LIBXML_NOENT",
                "$doc->loadXML($texto, LIBXML_NONET); // nunca LIBXML_NOENT",
                "php",
            ),
            Fix(
                "ruby",
                "Ruby: Nokogiri sem NOENT",
                "Nokogiri::XML(texto) { |c| c.nonet.strict }",
                "ruby",
            ),
            Fix(
                "javascript",
                "Node.js (libxmljs): sem noent",
                "libxmljs.parseXml(texto, { noent: false, nonet: true });",
                "javascript",
            ),
        ),
        references=(f"{_CS}XML_External_Entity_Prevention_Cheat_Sheet.html",),
    ),
)
