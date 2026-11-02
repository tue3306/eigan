"""Arquivos de configuração inseguros: servidores web, PHP, IIS e frameworks."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_sast import ids_in, scan

from eigan.checks.code import config_common as cc
from eigan.core import kb

CHECK = "code.config"
KEY = "x7k2p9q4w8e1r5t3y6u0i2o4p6a8s0d2f4g6h8j1k3l5"


def test_findings_have_complete_kb() -> None:
    for fid in cc.CONFIG_FINDINGS:
        entry = kb.get(fid)
        assert entry is not None, fid
        assert entry.steps and entry.references and entry.cwe.startswith("CWE-")


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        ("conf/nginx.conf", "server {\n listen 80;\n server_tokens on;\n}\n", cc.VERSION),
        ("conf/nginx.conf", "server {\n listen 80;\n autoindex on;\n}\n", cc.LISTING),
        (
            "conf/nginx.conf",
            "server {\n listen 443 ssl;\n ssl_protocols TLSv1 TLSv1.2;\n}\n",
            cc.TLS_OLD,
        ),
        ("apache2.conf", "ServerTokens Full\n", cc.VERSION),
        ("apache2.conf", "ServerSignature On\n", cc.VERSION),
        ("apache2.conf", "TraceEnable On\n", cc.TRACE),
        (
            "apache2.conf",
            "<Directory /srv>\n Options Indexes FollowSymLinks\n</Directory>\n",
            cc.LISTING,
        ),
        ("apache2.conf", "SSLProtocol all\n", cc.TLS_OLD),
        (
            "web.config",
            '<configuration><system.web><customErrors mode="Off"/></system.web></configuration>',
            cc.ERRORS,
        ),
        (
            "web.config",
            '<configuration><system.web><compilation debug="true"/></system.web></configuration>',
            cc.DEBUG,
        ),
        (
            "web.config",
            '<configuration><system.webServer><directoryBrowse enabled="true"/></system.webServer></configuration>',
            cc.LISTING,
        ),
        (
            "web.config",
            '<configuration><system.webServer><httpErrors errorMode="Detailed"/></system.webServer></configuration>',
            cc.ERRORS,
        ),
        ("php.ini", "display_errors = On\n", cc.ERRORS),
        ("php.ini", "expose_php = On\n", cc.VERSION),
        ("php.ini", "allow_url_include = On\n", cc.URL_INCLUDE),
        ("site/settings.py", "DEBUG = True\n", cc.DEBUG),
        ("site/settings.py", "ALLOWED_HOSTS = ['*']\n", cc.HOSTS),
        ("site/settings.py", "SESSION_COOKIE_SECURE = False\n", cc.COOKIE),
        (
            "app.py",
            "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n",
            cc.DEBUG,
        ),
        (
            "src/main/resources/application.properties",
            "management.endpoints.web.exposure.include=*\n",
            cc.ACTUATOR,
        ),
        (".env", "APP_NAME=x\nAPP_DEBUG=true\n", cc.DEBUG),
    ],
)
def test_positive(tmp_path: Path, rel: str, text: str, expected: str) -> None:
    files = {rel: text}
    if rel.endswith("settings.py"):
        files["manage.py"] = ""
    assert expected in ids_in(CHECK, tmp_path, files)


def test_django_secret_key_is_masked(tmp_path: Path) -> None:
    out = scan(CHECK, tmp_path, {"manage.py": "", "site/settings.py": f"SECRET_KEY = '{KEY}'\n"})
    found = out.by_id(cc.SECRET_KEY)
    assert found
    assert KEY not in repr(found[0].evidence) + repr(found[0].details) + found[0].title


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (
            "conf/nginx.conf",
            "server {\n listen 80;\n server_tokens off;\n autoindex off;\n ssl_protocols TLSv1.2 TLSv1.3;\n}\n",
        ),
        ("conf/nginx.conf", "server {\n listen 80;\n # server_tokens on;\n # autoindex on;\n}\n"),
        (
            "apache2.conf",
            "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n",
        ),
        (
            "web.config",
            '<configuration><system.web><customErrors mode="RemoteOnly"/><compilation debug="false"/></system.web></configuration>',
        ),
        ("php.ini", "display_errors = Off\nexpose_php = Off\nallow_url_include = Off\n"),
        ("php.ini", "; display_errors = On\n; allow_url_include = On\n"),
        (
            "site/settings.py",
            "import os\nDEBUG = False\nALLOWED_HOSTS = ['example.com']\nSECRET_KEY = os.environ['SECRET_KEY']\nSESSION_COOKIE_SECURE = True\n",
        ),
        ("app.py", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n"),
        (
            "src/main/resources/application.properties",
            "management.endpoints.web.exposure.include=health,info\n",
        ),
        (".env", "APP_NAME=x\nAPP_DEBUG=false\n"),
    ],
)
def test_safe_variants(tmp_path: Path, rel: str, text: str) -> None:
    files = {rel: text}
    if rel.endswith("settings.py"):
        files["manage.py"] = ""
    assert not ids_in(CHECK, tmp_path, files)


def test_commented_apache_directives_ignored(tmp_path: Path) -> None:
    text = "# TraceEnable On\n# Options Indexes\n"
    ids = ids_in(CHECK, tmp_path, {"apache2.conf": text})
    assert cc.TRACE not in ids
    assert cc.LISTING not in ids


def test_dev_settings_not_reported(tmp_path: Path) -> None:
    files = {"manage.py": "", "site/settings/dev.py": "DEBUG = True\nALLOWED_HOSTS = ['*']\n"}
    assert not ids_in(CHECK, tmp_path, files)


def test_non_project_python_not_treated_as_settings(tmp_path: Path) -> None:
    assert not ids_in(CHECK, tmp_path, {"util.py": "DEBUG = True\nALLOWED_HOSTS = ['*']\n"})


def test_apache_options_last_wins_and_all_minus_indexes(tmp_path: Path) -> None:
    for body in (
        "<Directory /x>\n Options Indexes\n Options -Indexes\n</Directory>\n",
        "<Directory /srv>\n Options All -Indexes\n</Directory>\n",
    ):
        files: dict[str, str | bytes] = {
            "apache2.conf": body + "ServerTokens Prod\nTraceEnable Off\n"
        }
        assert cc.LISTING not in ids_in(CHECK, tmp_path, files)


def test_apache_sslprotocol_all_is_tentative(tmp_path: Path) -> None:
    out = scan(CHECK, tmp_path, {"httpd.conf": "SSLProtocol all -SSLv3\nServerTokens Prod\n"})
    hit = out.by_id(cc.TLS_OLD)[0]
    assert hit.confidence.value == "tentative"
    out2 = scan(
        CHECK, tmp_path / "b", {"httpd.conf": "SSLProtocol +TLSv1 +TLSv1.2\nServerTokens Prod\n"}
    )
    assert out2.by_id(cc.TLS_OLD)[0].confidence.value == "firm"


def test_apache_comment_only_file_has_no_version_warning(tmp_path: Path) -> None:
    assert cc.VERSION not in ids_in(CHECK, tmp_path, {"httpd.conf": "# ServerTokens Full\n"})


def test_spring_multidoc_no_strength_when_exposed(tmp_path: Path) -> None:
    yml = (
        "management:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n"
        "---\nspring:\n  config:\n    activate:\n      on-profile: prod\n"
        "management:\n  endpoints:\n    web:\n      exposure:\n        include: health\n"
    )
    out = scan(CHECK, tmp_path, {"application.yml": yml})
    assert cc.ACTUATOR in out.ids()
    assert not any("Actuator" in p.title for p in out.passed)


def test_django_base_settings_debug_is_tentative(tmp_path: Path) -> None:
    out = scan(
        CHECK,
        tmp_path,
        {
            "manage.py": "",
            "proj/settings/base.py": "DEBUG = True\n",
            "proj/settings/production.py": "from .base import *\nDEBUG = False\n",
        },
    )
    debug = [f for f in out.by_id(cc.DEBUG) if "base.py" in f.asset]
    assert debug and all(f.confidence.value == "tentative" for f in debug)


def test_iis_httpcookies_without_requiressl(tmp_path: Path) -> None:
    web = '<configuration><system.web><httpCookies httpOnlyCookies="true"/></system.web></configuration>'
    assert cc.COOKIE in ids_in(CHECK, tmp_path, {"web.config": web})
