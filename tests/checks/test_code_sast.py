"""SAST por regras: cada achado com um caso positivo e variantes seguras (falsos positivos)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_sast import scan

from eigan.checks.code import sast
from eigan.checks.code import sast_common as sc
from eigan.core import kb
from eigan.core.models import Confidence, Severity

CHECK = "code.sast"
PHP_OPEN = "<" + "?php\n"


def rules(text: str, language: str) -> set[str]:
    return {hit.rule.id for hit in sast.scan_text(text, language)}


def findings(text: str, language: str) -> set[str]:
    return {hit.rule.finding for hit in sast.scan_text(text, language)}


def test_every_finding_has_complete_kb() -> None:
    for fid in sc.SAST_FINDINGS:
        entry = kb.get(fid)
        assert entry is not None, fid
        assert entry.steps and entry.references and entry.cwe.startswith("CWE-")
        assert entry.examples, fid


def test_every_rule_maps_to_registered_finding() -> None:
    for language in ("python", "javascript", "php", "java", "csharp", "go", "ruby"):
        for rule in sast.rules_for(language):
            assert rule.finding in sc.SAST_FINDINGS


POSITIVE = [
    # execução dinâmica
    ("python", 'eval(request.args["x"])\n', "py.eval"),
    ("python", 'exec(request.form["c"])\n', "py.eval"),
    ("javascript", "app.get('/', (req, res) => { eval(req.query.x); });\n", "js.eval"),
    ("php", PHP_OPEN + "eval($_GET['c']);\n", "php.eval"),
    ("ruby", "def f\n  eval(params[:x])\nend\n", "rb.eval"),
    # comandos
    ("python", 'subprocess.run("ls " + request.args["d"], shell=True)\n', "py.shell_true"),
    ("python", 'os.system("ping " + request.args.get("h"))\n', "py.os_system"),
    (
        "javascript",
        'const cp = require("child_process");\ncp.exec("ls " + req.query.d);\n',
        "js.child_process",
    ),
    ("php", PHP_OPEN + "system($_GET['cmd']);\n", "php.exec"),
    ("ruby", 'def f\n  system("ls #{params[:d]}")\nend\n', "rb.system"),
    ("go", 'exec.Command("sh", "-c", "ls "+r.URL.Query().Get("d"))\n', "go.exec_command"),
    # desserialização
    ("python", "pickle.loads(request.data)\n", "py.pickle"),
    ("python", "yaml.load(request.data)\n", "py.yaml_load"),
    ("php", PHP_OPEN + "unserialize($_COOKIE['d']);\n", "php.unserialize"),
    (
        "java",
        "class A { void f(java.net.Socket sock) throws Exception {\n"
        " ObjectInputStream in = new ObjectInputStream(sock.getInputStream());\n"
        " in.readObject(); } }\n",
        "java.object_input_stream",
    ),
    (
        "csharp",
        "class A { void F() { var bf = new BinaryFormatter(); bf.Deserialize(s); } }\n",
        "cs.binary_formatter",
    ),
    ("ruby", "def f\n  Marshal.load(params[:d])\nend\n", "rb.marshal"),
    # SQL
    ("python", 'cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])\n', "py.sql"),
    ("python", "cur.execute(f\"SELECT * FROM t WHERE id={request.args['id']}\")\n", "py.sql"),
    ("javascript", 'db.query("SELECT * FROM t WHERE id=" + req.query.id);\n', "js.sql"),
    ("javascript", "db.query(`SELECT * FROM t WHERE id=${req.query.id}`);\n", "js.sql"),
    ("php", PHP_OPEN + "mysql_query(\"SELECT * FROM t WHERE id=\" . $_GET['id']);\n", "php.sql"),
    (
        "java",
        "class A { void f(HttpServletRequest request) {\n"
        ' stmt.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id")); } }\n',
        "java.sql",
    ),
    (
        "csharp",
        'new SqlCommand("SELECT * FROM t WHERE id=" + Request.QueryString["id"], c);\n',
        "cs.sql",
    ),
    ("go", 'db.Query("SELECT * FROM t WHERE id=" + r.URL.Query().Get("id"))\n', "go.sql"),
    ("ruby", 'def f\n  User.where("id = #{params[:id]}")\nend\n', "rb.active_record"),
    # TLS
    ("python", "requests.get(u, verify=False)\n", "py.verify_false"),
    (
        "javascript",
        "const a = new https.Agent({ rejectUnauthorized: false });\n",
        "js.reject_unauthorized",
    ),
    ("javascript", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n', "js.node_tls_env"),
    ("php", PHP_OPEN + "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n", "php.curl_verify"),
    (
        "java",
        "class A { void f() { new X509TrustManager() {\n"
        " public void checkServerTrusted(X509Certificate[] c, String a) {} }; } }\n",
        "java.trust_manager",
    ),
    (
        "csharp",
        "ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;\n",
        "cs.cert_callback",
    ),
    ("go", "cfg := &tls.Config{InsecureSkipVerify: true}\n", "go.insecure_skip_verify"),
    ("ruby", "def f\n  OpenSSL::SSL::VERIFY_NONE\nend\n", "rb.verify_none"),
    # hash fraco de senha
    ("python", "hashlib.md5(password.encode()).hexdigest()\n", "py.hash_password"),
    (
        "javascript",
        'const crypto = require("crypto");\ncrypto.createHash("md5").update(password).digest("hex");\n',
        "js.hash_password",
    ),
    ("php", PHP_OPEN + "$h = md5($password);\n", "php.hash_password"),
    ("go", "h := md5.Sum([]byte(password))\n", "go.hash_sum"),
    ("ruby", "def f\n  Digest::MD5.hexdigest(password)\nend\n", "rb.hash_password"),
    # aleatoriedade
    ("python", "token = random.randint(0, 99999)\n", "py.random_assign"),
    ("javascript", "const token = Math.random().toString(36);\n", "js.random_assign"),
    # XSS
    ("javascript", "el.innerHTML = location.hash;\n", "js.inner_html"),
    ("javascript", "document.write(req.query.q);\n", "js.document_write"),
    # JWT
    ("python", 'jwt.decode(t, options={"verify_signature": False})\n', "py.jwt_options"),
    # XXE
    ("python", "etree.XMLParser(resolve_entities=True)\n", "py.lxml_entities"),
    (
        "java",
        "class A { void f() throws Exception {\n"
        " DocumentBuilderFactory.newInstance().newDocumentBuilder(); } }\n",
        "java.xxe_factory",
    ),
]


@pytest.mark.parametrize(("language", "text", "rule_id"), POSITIVE)
def test_positive(language: str, text: str, rule_id: str) -> None:
    assert rule_id in rules(text, language)


def test_ten_findings_are_exercised_by_positives() -> None:
    covered = {
        hit.rule.finding for language, text, _ in POSITIVE for hit in sast.scan_text(text, language)
    }
    assert covered >= set(sc.SAST_FINDINGS) - {sc.PHP_INCLUDE, sc.PHP_EXTRACT}


def test_php_include_extract() -> None:
    text = PHP_OPEN + "include $_GET['page'];\nextract($_POST);\n"
    assert findings(text, "php") >= {sc.PHP_INCLUDE, sc.PHP_EXTRACT}


SAFE = [
    ("python", 'eval("1 + 1")\n'),
    ("python", "import ast\nast.literal_eval(request.args['x'])\n"),
    ("python", 'subprocess.run(["ls", request.args["d"]])\n'),
    ("python", 'subprocess.run("ls -l", shell=True)\n'),
    ("python", 'os.system("clear")\n'),
    ("python", "json.loads(request.data)\n"),
    ("python", "yaml.safe_load(request.data)\n"),
    ("python", "yaml.load(data, Loader=yaml.SafeLoader)\n"),
    ("python", 'cur.execute("SELECT * FROM t WHERE id=%s", (request.args["id"],))\n'),
    ("python", 'cur.execute("SELECT * FROM t")\n'),
    ("python", "requests.get(u, verify=True)\n"),
    ("python", "hashlib.sha256(data).hexdigest()\n"),
    ("python", "token = secrets.token_urlsafe(32)\n"),
    ("python", "jwt.decode(t, key, algorithms=['HS256'])\n"),
    ("python", "# eval(request.args['x'])\n# requests.get(u, verify=False)\n"),
    ("python", 'msg = "use eval(request.args) and verify=False here"\n'),
    ("javascript", "// eval(req.query.x)\n"),
    ("javascript", "const a = new https.Agent({ rejectUnauthorized: true });\n"),
    ("javascript", "el.textContent = location.hash;\n"),
    ("javascript", "el.innerHTML = '<b>fixo</b>';\n"),
    ("javascript", "db.query('SELECT * FROM t WHERE id = ?', [req.query.id]);\n"),
    ("javascript", "const n = Math.random() * 10;\n"),
    ("php", PHP_OPEN + "include 'header.php';\n"),
    ("php", PHP_OPEN + "$h = password_hash($password, PASSWORD_DEFAULT);\n"),
    ("php", PHP_OPEN + "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);\n"),
    ("go", "cfg := &tls.Config{InsecureSkipVerify: false}\n"),
    ("go", 'exec.Command("ls", "-l")\n'),
    ("csharp", "ServicePointManager.ServerCertificateValidationCallback = null;\n"),
    ("ruby", "def f\n  User.where(id: params[:id])\nend\n"),
    ("ruby", "def f\n  YAML.safe_load(params[:y])\nend\n"),
]


@pytest.mark.parametrize(("language", "text"), SAFE)
def test_safe_variants_not_reported(language: str, text: str) -> None:
    assert not rules(text, language)


def test_definition_of_eval_is_not_a_call() -> None:
    assert not rules("def eval(request):\n    return 1\n", "python")


def test_input_raises_confidence_over_constant_variable() -> None:
    direct = sast.scan_text('eval(request.args["x"])\n', "python")[0]
    severity, confidence = sast.grade(direct.rule, direct.verdict)
    assert confidence is Confidence.FIRM
    assert severity.rank >= Severity.HIGH.rank


# -- no nível do projeto ----------------------------------------------------------------------

BAD = 'import os\ndef f(request):\n    os.system("ping " + request.args["h"])\n'


def test_project_reports_with_location(tmp_path: Path) -> None:
    out = scan(CHECK, tmp_path, {"app/views.py": BAD})
    found = out.by_id(sc.COMMAND)
    assert found
    assert found[0].asset == "app/views.py:3"
    assert not out.passed


def test_tests_folder_is_tentative_and_low(tmp_path: Path) -> None:
    out = scan(CHECK, tmp_path, {"tests/test_views.py": BAD})
    found = out.by_id(sc.COMMAND)
    assert found
    assert found[0].confidence is Confidence.TENTATIVE
    assert found[0].severity.rank <= Severity.LOW.rank


@pytest.mark.parametrize(
    "rel",
    ["node_modules/x/index.js", "vendor/lib/a.py", "static/app.min.js", "gen/api_pb2.py"],
)
def test_vendored_and_generated_skipped(tmp_path: Path, rel: str) -> None:
    text = "eval(req.query.x);\n" if rel.endswith(".js") else BAD
    assert not scan(CHECK, tmp_path, {rel: text}).findings


def test_generated_header_skipped(tmp_path: Path) -> None:
    text = "# Code generated by tool. DO NOT EDIT.\n" + BAD
    assert not scan(CHECK, tmp_path, {"app/gen.py": text}).findings


def test_minified_blob_skipped(tmp_path: Path) -> None:
    blob = "var a=1;" * 2000 + "eval(req.query.x);"
    assert not scan(CHECK, tmp_path, {"public/bundle.js": blob}).findings


def test_clean_project_gets_strength(tmp_path: Path) -> None:
    out = scan(CHECK, tmp_path, {"app.py": "print('ok')\n"})
    assert not out.findings
    assert out.passed


def test_caps_per_file(tmp_path: Path) -> None:
    body = "def f(request):\n" + "".join(
        f'    os.system("ping " + request.args["h{i}"])\n' for i in range(60)
    )
    out = scan(CHECK, tmp_path, {"a.py": "import os\n" + body})
    assert 0 < len(out.findings) <= sast.MAX_PER_FILE


def test_non_code_files_ignored(tmp_path: Path) -> None:
    assert not scan(CHECK, tmp_path, {"README.md": BAD, "notes.txt": BAD}).findings


# -- regressões da revisão ------------------------------------------------------------------


def _r(text: str, language: str) -> list[sast.RawHit]:
    return sast.scan_text(text, language)


def test_java_runtime_exec_fires() -> None:
    java = "class A { void f(HttpServletRequest request) throws Exception {\n"
    assert "java.runtime_exec" in rules(
        java + 'Runtime.getRuntime().exec("ping " + request.getParameter("h"));\n}}\n', "java"
    )
    assert "java.runtime_exec" in rules(
        java + 'Runtime.getRuntime().exec(new String[]{"sh", "-c", c});\n}}\n', "java"
    )
    assert not rules(java + 'Runtime.getRuntime().exec("ls -l");\n}}\n', "java")


def test_php_server_constants_are_not_input() -> None:
    safe = PHP_OPEN + "include $_SERVER['DOCUMENT_ROOT'] . '/inc/header.php';\n"
    hits = [h for h in _r(safe, "php") if h.rule.finding == sc.PHP_INCLUDE]
    assert all(h.verdict.input_kind == "" for h in hits)
    risky = PHP_OPEN + "include $_SERVER['HTTP_X_PAGE'] . '.php';\n"
    assert any(h.verdict.input_kind == "direta" for h in _r(risky, "php"))


@pytest.mark.parametrize(
    ("language", "text"),
    [
        ("php", PHP_OPEN + "$pass = md5($_POST['password']);\n"),
        ("python", 'h = hashlib.md5(request.form["password"].encode()).hexdigest()\n'),
        ("go", 'h := md5.Sum([]byte(r.FormValue("password")))\n'),
    ],
)
def test_weak_hash_with_keyed_password(language: str, text: str) -> None:
    assert sc.WEAK_HASH in findings(text, language)


def test_weak_hash_not_for_security_is_ignored() -> None:
    assert not findings("h = hashlib.md5(password.encode(), usedforsecurity=False)\n", "python")


@pytest.mark.parametrize(
    "text",
    [
        'session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})\n',
        'cur.execute(sql.SQL("SELECT * FROM users"))\n',
    ],
)
def test_sql_wrappers_are_not_flagged(text: str) -> None:
    assert sc.SQL not in findings(text, "python")


def test_taint_dies_in_other_function_and_after_reassignment() -> None:
    other = (
        'def a():\n    d = request.args["d"]\n    return d\n\ndef b(d):\n    os.system("ls " + d)\n'
    )
    assert all(h.verdict.input_kind == "" for h in _r(other, "python"))
    again = 'd = request.args["d"]\nd = "fixed"\nos.system("ls " + d)\n'
    assert all(h.verdict.input_kind == "" for h in _r(again, "python"))
    still = 'd = request.args["d"]\nd = d + "x"\nos.system("ls " + d)\n'
    assert any(h.verdict.input_kind == "indireta" for h in _r(still, "python"))


def test_indirect_input_is_never_firm() -> None:
    hit = next(h for h in _r(PHP_OPEN + '$f = $_GET["f"];\ninclude $f . ".php";\n', "php"))
    _severity, confidence = sast.grade(hit.rule, hit.verdict)
    assert confidence is not Confidence.FIRM


def test_snippet_masks_credentials() -> None:
    line = 'requests.get("https://user:p4ssw0rdZ@host/x", verify=False)'
    out = sast._snippet(line, 0)
    assert "p4ssw0rdZ" not in out
    key = "k" * 30 + "9z"
    assert key not in sast._snippet(f"headers={{'x': '{key}'}} + request.args['q']", 0)


def test_external_dir_is_analysed_and_inc_is_php() -> None:
    assert not sast.is_vendored("src/external/pay.py")
    assert sast._LANGUAGE_BY_EXT[".inc"] == "php"


def test_hand_written_do_not_edit_comment_is_not_generated() -> None:
    text = "# Do not edit the section below without review\nimport os\n"
    assert sast._GENERATED_HEADER.search(text[:400]) is None


def test_match_cap_keeps_big_files_fast() -> None:
    import time

    begin = time.monotonic()
    sast.scan_text("eval(\n" * 40000, "python")
    assert time.monotonic() - begin < 20


def test_js_spawn_shell_dash_c_and_jwt_scope() -> None:
    spawn = "const cp = require('child_process');\ncp.spawn('sh', ['-c', cmd]);\n"
    assert "js.spawn_shell" in rules(spawn, "javascript")
    assert "js.spawn_shell" not in rules(
        "const cp = require('child_process');\ncp.spawn('sh', ['-c', 'ls']);\n", "javascript"
    )
    jwt = (
        "const jwt = require('jsonwebtoken');\n"
        "function a(token) { return jwt.decode(token); }\n"
        "function v(t, k) { return jwt.verify(t, k); }\n"
    )
    assert "js.jwt_decode" in rules(jwt, "javascript")


def test_php_unserialize_allowed_classes_and_yaml_fullloader() -> None:
    assert not findings(PHP_OPEN + "$o = unserialize($s, ['allowed_classes' => false]);\n", "php")
    hits = _r("yaml.load(data, Loader=yaml.FullLoader)\n", "python")
    assert hits and hits[0].verdict.confidence is Confidence.TENTATIVE


def test_boolean_random_name_is_not_token() -> None:
    assert not findings("const randomToken = Math.random() > 0.5 ? 'a' : 'b';\n", "javascript")


def test_caps_prefer_severe_findings(tmp_path: Path) -> None:
    files: dict[str, str | bytes] = {f"a{i}.js": "el.innerHTML = x;\n" * 20 for i in range(3)}
    files["z.py"] = 'import os\nos.system("ls " + request.args["d"])\n'
    outcome = scan("code.sast", tmp_path, files)
    assert any(f.severity is Severity.CRITICAL for f in outcome.findings)
