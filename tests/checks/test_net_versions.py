"""``net.versions``: regras curadas de versão (CVEs famosos e ramos sem suporte)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from typing import Any

import pytest
from fakes_net import fast_settings
from helpers import CheckOutcome, LocalServer, Route, http_fact, run_check

from eigan.checks.net import versions
from eigan.core import vulndb
from eigan.core.models import Fact, Severity

HOST = "127.0.0.1"


def tech(
    name: str, version: str | None, *, evidence: str = "", port: int = 80, host: str = HOST
) -> Fact:
    return Fact(
        "tech",
        f"{host}:{name}",
        {
            "host": host,
            "name": name,
            "version": version,
            "kind": "service",
            "evidence": evidence,
            "port": port,
            "label": f"{name} {version}",
        },
    )


def run(fact: Fact, **kw: Any) -> CheckOutcome:
    return run_check("net.versions", fact, settings=fast_settings(), **kw)


def rule(rule_id: str) -> versions.Rule:
    [found] = [r for r in versions.load_rules() if r.id == rule_id]
    return found


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(versions, "today", lambda: date(2026, 11, 2))


# -- dados ---------------------------------------------------------------------------------


def test_data_file_has_source_and_license() -> None:
    from eigan.data import load_json

    data = load_json(versions.DATA_FILE)
    assert data["fonte"] and data["licenca"] and data["url"].startswith("https://")
    assert data["atualizado"]


def test_every_rule_has_references_and_cves_are_wellformed() -> None:
    import re

    for item in versions.load_rules():
        assert item.references and all(ref.startswith("https://") for ref in item.references)
        assert all(re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in item.cves)
        assert item.ranges or item.branches


# -- intervalos: positivo e fronteiras --------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "version", "expected"),
    [
        ("apache-2.4.49", "2.4.49", True),
        ("apache-2.4.49", "2.4.48", False),
        ("apache-2.4.49", "2.4.51", False),
        ("apache-2.4.50", "2.4.50", True),
        ("apache-2.4.50", "2.4.49", False),
        ("openssl-heartbleed", "1.0.1", True),
        ("openssl-heartbleed", "1.0.1f", True),
        ("openssl-heartbleed", "1.0.1g", False),
        ("openssl-heartbleed", "1.0.2", False),
        ("openssl-heartbleed", "1.0.0s", False),
        ("openssl-heartbleed", "1.0.2-beta1", True),
        ("openssl-heartbleed", "1.0.2-beta2", False),
        ("vsftpd-2.3.4", "2.3.4", True),
        ("vsftpd-2.3.4", "2.3.5", False),
        ("vsftpd-2.3.4", "3.0.3", False),
        ("proftpd-1.3.5", "1.3.5", True),
        ("proftpd-1.3.5", "1.3.5a", False),
        ("proftpd-1.3.5", "1.3.4", False),
        ("exim-4.87-4.91", "4.87", True),
        ("exim-4.87-4.91", "4.91", True),
        ("exim-4.87-4.91", "4.86", False),
        ("exim-4.87-4.91", "4.92", False),
        ("php-cgi-windows", "8.1.28", True),
        ("php-cgi-windows", "8.1.29", False),
        ("php-cgi-windows", "8.2.19", True),
        ("php-cgi-windows", "8.2.20", False),
        ("php-cgi-windows", "8.3.7", True),
        ("php-cgi-windows", "8.3.8", False),
        ("php-cgi-windows", "5.6.40", True),
        ("php-cgi-windows", "8.4.0", False),
        ("iis-6.0-webdav", "6.0", True),
        ("iis-6.0-webdav", "7.5", False),
        ("jenkins-cli", "2.441", True),
        ("jenkins-cli", "2.442", False),
        ("jenkins-cli", "2.426.2", True),
        ("jenkins-cli", "2.426.3", False),
        ("jenkins-cli", "2.440.1", False),
        ("nginx-ramo-antigo", "1.14.2", True),
        ("nginx-ramo-antigo", "1.18.0", False),
        ("openssh-ramo-antigo", "7.3p1", True),
        ("openssh-ramo-antigo", "7.4p1", False),
    ],
)
def test_range_boundaries(rule_id: str, version: str, expected: bool) -> None:
    assert versions.matches_range(rule(rule_id), version) is expected


def test_normalize_version_strips_package_revision() -> None:
    assert versions.normalize_version("7.4.3-4ubuntu2.20") == "7.4.3"
    assert versions.normalize_version("4.90_1") == "4.90"
    assert versions.normalize_version("1.0.1e-fips", letters=True) == "1.0.1.5"
    assert versions.normalize_version("lixo") == ""


def test_canonical_product_aliases() -> None:
    assert versions.canonical_product("Microsoft-IIS") == "iis"
    assert versions.canonical_product("httpd") == "apache"
    assert versions.canonical_product(" Apache2 ") == "apache"


# -- achados ponta a ponta ------------------------------------------------------------------------


def test_apache_traversal_finding_matches_kev() -> None:
    out = run(tech("apache", "2.4.49"))
    [finding] = out.by_id("net.versao.vulneravel.apache_traversal")
    assert "CVE-2021-41773" in finding.cves
    assert finding.kev == vulndb.any_kev(finding.cves)
    if finding.kev:
        assert finding.severity is Severity.CRITICAL
    assert finding.confidence.value == "firm"


def test_apache_2450_reports_second_cve() -> None:
    out = run(tech("apache", "2.4.50"))
    [finding] = out.by_id("net.versao.vulneravel.apache_traversal")
    assert "CVE-2021-42013" in finding.cves


def test_apache_fixed_version_is_clean() -> None:
    assert run(tech("apache", "2.4.51")).ids() == set()
    assert run(tech("apache", "2.4.58")).ids() == set()


def test_distro_marker_downgrades_to_tentative() -> None:
    out = run(tech("apache", "2.4.49", evidence="Apache/2.4.49 (Ubuntu)"))
    [finding] = out.by_id("net.versao.vulneravel.apache_traversal")
    assert finding.confidence.value == "tentative"
    assert "distribuição" in finding.evidence


def test_openssl_heartbleed_is_always_tentative_and_sends_nothing() -> None:
    out = run(tech("openssl", "1.0.1f", port=443))
    [finding] = out.by_id("net.versao.vulneravel.openssl_heartbleed")
    assert finding.confidence.value == "tentative"
    assert finding.cves == ["CVE-2014-0160"]
    assert not run(tech("openssl", "1.0.1g", port=443)).ids()


def test_vsftpd_backdoor_banner_only_tentative() -> None:
    [finding] = run(tech("vsftpd", "2.3.4", port=21)).by_id("net.versao.vulneravel.vsftpd_backdoor")
    assert finding.confidence.value == "tentative"
    assert not run(tech("vsftpd", "3.0.5", port=21)).ids()


def test_proftpd_mod_copy() -> None:
    [finding] = run(tech("proftpd", "1.3.5", port=21)).by_id(
        "net.versao.vulneravel.proftpd_mod_copy"
    )
    assert finding.cves == ["CVE-2015-3306"]
    assert not run(tech("proftpd", "1.3.6", port=21)).ids()


def test_exim_range() -> None:
    [finding] = run(tech("exim", "4.89", port=25)).by_id("net.versao.vulneravel.exim_rce")
    assert finding.cves == ["CVE-2019-10149"]
    assert not run(tech("exim", "4.92", port=25)).ids()


def test_missing_version_is_ignored() -> None:
    assert run(tech("apache", None)).ids() == set()
    assert run(tech("apache", "")).ids() == set()


def test_unknown_product_does_not_match_check() -> None:
    from eigan.core.registry import get_check, load_builtin_checks

    load_builtin_checks()
    item = get_check("net.versions")
    assert item is not None and item.when is not None
    assert not item.when(tech("redis", "7.0.0"))
    assert item.when(tech("Apache2", "2.4.49"))


# -- PHP no Windows (condição) -----------------------------------------------------------------------


def test_php_cgi_needs_windows_signal() -> None:
    assert not run(tech("php", "8.1.2", evidence="X-Powered-By: PHP/8.1.2")).by_id(
        "net.versao.vulneravel.php_cgi_windows"
    )


def test_php_cgi_reported_when_windows_known_tentative() -> None:
    php = tech("php", "8.1.2", evidence="X-Powered-By: PHP/8.1.2")
    iis = tech("iis", "10.0", evidence="Microsoft-IIS/10.0")
    out = run(php, scan=_scan_with(iis))
    [finding] = out.by_id("net.versao.vulneravel.php_cgi_windows")
    assert finding.cves == ["CVE-2024-4577"]
    assert finding.confidence.value == "tentative"


def test_php_cgi_patched_version_not_reported_even_on_windows() -> None:
    iis = tech("iis", "10.0", evidence="Microsoft-IIS/10.0")
    out = run(tech("php", "8.3.8"), scan=_scan_with(iis))
    assert not out.by_id("net.versao.vulneravel.php_cgi_windows")


def _scan_with(*seed: Fact) -> Any:
    from eigan.core.context import ScanContext
    from eigan.core.target import parse_target

    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    for item in seed:
        scan.add_fact(item)
    return scan


# -- IIS 6 / WebDAV ---------------------------------------------------------------------------------------


def _options_route(headers: list[tuple[str, str]]) -> Callable[..., Route]:
    return lambda handler: Route(200, "ok", headers=headers)


def test_iis6_webdav_confirmed_by_options(serve: Callable[..., LocalServer]) -> None:
    server = serve({"/": _options_route([("DAV", "1, 2"), ("Allow", "OPTIONS, PROPFIND")])})
    port = server.port
    scan = _scan_with(http_fact(server.url))
    out = run(tech("iis", "6.0", port=port), scan=scan)
    [finding] = out.by_id("net.versao.vulneravel.iis_webdav")
    assert finding.cves == ["CVE-2017-7269"]
    assert "WebDAV" in finding.evidence


def test_iis6_without_webdav_is_not_reported(serve: Callable[..., LocalServer]) -> None:
    server = serve({"/": _options_route([("Allow", "GET, HEAD, POST")])})
    port = server.port
    scan = _scan_with(http_fact(server.url))
    out = run(tech("iis", "6.0", port=port), scan=scan)
    assert not out.by_id("net.versao.vulneravel.iis_webdav")


def test_iis6_unanswered_options_is_tentative() -> None:
    out = run(tech("iis", "6.0"))
    [finding] = out.by_id("net.versao.vulneravel.iis_webdav")
    assert finding.confidence.value == "tentative"


# -- Jenkins --------------------------------------------------------------------------------------------------


def test_jenkins_header_teaches_tech(serve: Callable[..., LocalServer]) -> None:
    server = serve({"/": Route(200, "ok", headers=[("X-Jenkins", "2.426.1")])})
    out = run_check("net.versions.jenkins", http_fact(server.url), settings=fast_settings())
    [fact] = [f for f in out.facts if f.kind == "tech"]
    assert fact.data["name"] == "jenkins" and fact.data["version"] == "2.426.1"
    assert run(fact).by_id("net.versao.vulneravel.jenkins_cli")


def test_jenkins_header_garbage_ignored(serve: Callable[..., LocalServer]) -> None:
    server = serve({"/": Route(200, "ok", headers=[("X-Jenkins", "<script>")])})
    out = run_check("net.versions.jenkins", http_fact(server.url), settings=fast_settings())
    assert not out.facts


def test_jenkins_fixed_versions_clean() -> None:
    assert not run(tech("jenkins", "2.442")).ids()
    assert not run(tech("jenkins", "2.426.3")).ids()


# -- fim de suporte ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        ("php", "7.4.33", True),
        ("php", "8.0.30", True),
        ("php", "8.1.27", False),  # ainda com suporte? depende da data fixada abaixo
        ("php", "8.4.1", False),
        ("php", "5.6.40", True),
        ("php", "7.40.1", False),
        ("apache", "2.2.34", True),
        ("apache", "2.4.58", False),
        ("iis", "7.5", True),
        ("iis", "10.0", False),
    ],
)
def test_end_of_life_branches(name: str, version: str, expected: bool) -> None:
    out = run(tech(name, version))
    eol = {i for i in out.ids() if ".fim_de_vida." in i}
    if name == "php" and version == "8.1.27":
        expected = True  # 8.1 acabou em 31/12/2025 e a data fixada é 02/11/2026
    assert bool(eol) is expected


def test_branch_still_supported_is_not_a_strength(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(versions, "today", lambda: date(2025, 6, 1))
    out = run(tech("php", "8.2.5"))
    assert not out.ids()
    assert not any(p.control == "net.versao.php" for p in out.passed)


def test_branch_boundary_day(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(versions, "today", lambda: date(2025, 12, 31))
    assert not run(tech("php", "8.1.30")).ids()
    monkeypatch.setattr(versions, "today", lambda: date(2026, 1, 1))
    assert run(tech("php", "8.1.30")).ids()


def test_every_finding_has_complete_kb() -> None:
    from eigan.core import kb

    for fid in versions.kb_versions.FINDINGS:
        entry = kb.get(fid)
        assert entry is not None and entry.steps and entry.references and entry.verify


@pytest.mark.parametrize(
    ("name", "version", "banner", "finding"),
    [
        ("proftpd", "1.3.5", "220 ProFTPD 1.3.5 Server", "net.versao.vulneravel.proftpd_mod_copy"),
        ("exim", "4.89", "220 mail ESMTP Exim 4.89", "net.versao.vulneravel.exim_rce"),
    ],
)
def test_banner_only_rules_are_tentative_and_not_critical(
    name: str, version: str, banner: str, finding: str
) -> None:
    out = run(tech(name, version, evidence=banner))
    [item] = out.by_id(finding)
    assert item.confidence.value == "tentative"
    assert item.severity is not Severity.CRITICAL


def test_tentative_vendor_mark_caps_kev_severity() -> None:
    out = run(tech("openssl", "1.0.1f", port=443, evidence="Apache (Ubuntu) OpenSSL/1.0.1f"))
    [item] = out.by_id("net.versao.vulneravel.openssl_heartbleed")
    assert item.confidence.value == "tentative"
    assert item.severity is not Severity.CRITICAL


def test_windows_text_needs_a_server_token() -> None:
    php = tech("php", "8.1.2")
    out = run(php, scan=_scan_with(tech("wordpress", "6.4", evidence="Windows Live Writer")))
    assert "net.versao.vulneravel.php_cgi_windows" not in out.ids()
