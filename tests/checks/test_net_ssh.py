"""``net.ssh``: leitura do KEXINIT, política de algoritmos, Terrapin e regreSSHion."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fakes_net import fast_settings
from fakes_net_ssh import (
    MODERN_CIPHERS,
    MODERN_KEX,
    FakeSshServer,
    ignore_packet,
    kexinit_payload,
    packet,
    service_fact,
)
from helpers import CheckOutcome, run_check

from eigan.checks.net import sshproto
from eigan.core import vulndb


@pytest.fixture
def ssh_server() -> Iterator[list[FakeSshServer]]:
    servers: list[FakeSshServer] = []
    yield servers
    for server in servers:
        server.stop()


def scan(
    servers: list[FakeSshServer],
    banner: bytes = b"SSH-2.0-OpenSSH_9.9p1\r\n",
    payload: bytes | None = None,
    **kex: Any,
) -> CheckOutcome:
    pkt = packet(payload if payload is not None else kexinit_payload(**kex))
    server = FakeSshServer(banner, [pkt])
    servers.append(server)
    return run_check("net.ssh", service_fact(server.port), settings=fast_settings())


# -- parser ---------------------------------------------------------------------------


def test_parse_kexinit_reads_all_lists() -> None:
    kex = sshproto.parse_kexinit(kexinit_payload())
    assert kex.get("kex")[0] == "mlkem768x25519-sha256"
    assert "chacha20-poly1305@openssh.com" in kex.ciphers
    assert kex.strict_kex
    assert kex.post_quantum == ["mlkem768x25519-sha256"]


@pytest.mark.parametrize("payload", [b"", b"\x15" + b"\x00" * 40, kexinit_payload()[:60]])
def test_parse_kexinit_rejects_bad_packets(payload: bytes) -> None:
    with pytest.raises(ValueError):
        sshproto.parse_kexinit(payload)


def test_parse_banner_and_openssh() -> None:
    banner = sshproto.parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    assert banner is not None and banner.comment == "Ubuntu-3ubuntu0.6"
    version = sshproto.parse_openssh(banner.software)
    assert version is not None and version.branch == (8, 9) and version.portable == 1
    assert sshproto.parse_banner("HTTP/1.1 200 OK") is None
    assert sshproto.parse_openssh("dropbear_2022.83") is None


def test_dpkg_compare() -> None:
    assert sshproto.dpkg_compare("3ubuntu0.10", "3ubuntu0.9") == 1
    assert sshproto.dpkg_compare("2+deb12u3", "2+deb12u3") == 0
    assert sshproto.dpkg_compare("2+deb12u2", "2+deb12u3") == -1
    assert sshproto.dpkg_compare("1~rc1", "1") == -1


# -- terrapin ----------------------------------------------------------------------------


def _kex(**kw: Any) -> sshproto.KexInit:
    return sshproto.parse_kexinit(kexinit_payload(**kw))


def test_terrapin_rule() -> None:
    assert sshproto.terrapin(_kex(kex=("curve25519-sha256",)))[0]  # chacha sem strict
    assert not sshproto.terrapin(_kex())[0]  # strict KEX
    assert not sshproto.terrapin(_kex(kex=("curve25519-sha256",), ciphers=("aes128-ctr",)))[0]
    etm = ("hmac-sha2-256-etm@openssh.com",)
    cbc = _kex(kex=("curve25519-sha256",), ciphers=("aes128-cbc",), macs=etm)
    assert sshproto.terrapin(cbc)[0]
    plain = _kex(kex=("curve25519-sha256",), ciphers=("aes128-cbc",), macs=("hmac-sha2-256",))
    assert not sshproto.terrapin(plain)[0]


def test_terrapin_finding_is_kev_critical(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, kex=("curve25519-sha256", "mlkem768x25519-sha256"))
    [finding] = out.by_id("net.ssh.terrapin")
    assert finding.cves == ["CVE-2023-48795"]
    assert finding.kev == vulndb.any_kev(["CVE-2023-48795"])


def test_strict_kex_passes_terrapin(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server)
    assert not out.by_id("net.ssh.terrapin")
    assert not out.by_id("net.ssh.algoritmos_fracos")
    assert not out.by_id("net.ssh.sem_pos_quantico")
    assert any(p.control == "net.ssh.pos_quantico" for p in out.passed)


# -- algoritmos ---------------------------------------------------------------------------


def test_weak_algorithms_reported(ssh_server: list[FakeSshServer]) -> None:
    out = scan(
        ssh_server,
        kex=(*MODERN_KEX, "diffie-hellman-group1-sha1"),
        ciphers=(*MODERN_CIPHERS, "3des-cbc", "arcfour"),
        macs=("hmac-md5", "hmac-sha2-256-etm@openssh.com"),
    )
    [finding] = out.by_id("net.ssh.algoritmos_fracos")
    assert "diffie-hellman-group1-sha1" in finding.evidence
    assert "hmac-md5" in finding.evidence


def test_modern_server_has_no_algorithm_findings(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server)
    assert out.ids() == set()
    assert any(p.control == "net.ssh.algoritmos" for p in out.passed)


def test_no_post_quantum_reported(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, kex=("curve25519-sha256", "kex-strict-s-v00@openssh.com"))
    assert "net.ssh.sem_pos_quantico" in out.ids()


def test_ignore_packet_before_kexinit() -> None:
    server = FakeSshServer(packets=[ignore_packet(), packet(kexinit_payload())])
    try:
        out = run_check("net.ssh", service_fact(server.port), settings=fast_settings())
    finally:
        server.stop()
    assert any(p.control == "net.ssh.algoritmos" for p in out.passed)


def test_client_sends_only_its_banner() -> None:
    server = FakeSshServer(packets=[packet(kexinit_payload())])
    try:
        run_check("net.ssh", service_fact(server.port), settings=fast_settings())
    finally:
        server.stop()
    assert server.received == [sshproto.CLIENT_BANNER]


def test_garbage_after_banner_is_not_a_finding(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, payload=b"\x14" + b"\x00" * 20)
    assert not out.by_id("net.ssh.terrapin")
    assert not out.by_id("net.ssh.algoritmos_fracos")


def test_non_ssh_banner_ignored(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, banner=b"HELLO there\r\n")
    assert out.ids() == set() and not out.passed


def test_ssh1_protocol(ssh_server: list[FakeSshServer]) -> None:
    server = FakeSshServer(b"SSH-1.5-Old_SSH\r\n")
    ssh_server.append(server)
    out = run_check("net.ssh", service_fact(server.port), settings=fast_settings())
    assert "net.ssh.protocolo_v1" in out.ids()


def test_ssh199_is_not_ssh1_only() -> None:
    assert not sshproto.only_ssh1("SSH-1.99-OpenSSH_3.9p1")
    assert sshproto.only_ssh1("SSH-1.5-X")


# -- regreSSHion ----------------------------------------------------------------------


def verdict(line: str) -> sshproto.Verdict | None:
    banner = sshproto.parse_banner(line)
    assert banner is not None
    return sshproto.regresshion(banner)


@pytest.mark.parametrize(
    ("line", "status"),
    [
        ("SSH-2.0-OpenSSH_8.4p1", sshproto.NAO_AFETADO),
        ("SSH-2.0-OpenSSH_8.5p1", sshproto.VULNERAVEL),
        ("SSH-2.0-OpenSSH_9.7p1", sshproto.VULNERAVEL),
        ("SSH-2.0-OpenSSH_9.8p1", sshproto.NAO_AFETADO),
        ("SSH-2.0-OpenSSH_4.3p2", sshproto.INDICIO),
        ("SSH-2.0-OpenSSH_4.4p1", sshproto.NAO_AFETADO),
        ("SSH-2.0-OpenSSH_9.6", sshproto.INDICIO),  # sem 'p': OpenBSD ou Red Hat
        ("SSH-2.0-OpenSSH_for_Windows_9.5", sshproto.NAO_AFETADO),
        ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", sshproto.VULNERAVEL),
        ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", sshproto.CORRIGIDO),
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.9", sshproto.VULNERAVEL),
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", sshproto.CORRIGIDO),
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.2", sshproto.VULNERAVEL),
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3", sshproto.CORRIGIDO),
        ("SSH-2.0-OpenSSH_9.4p1 Ubuntu-1ubuntu1", sshproto.INDICIO),  # revisão desconhecida
        ("SSH-2.0-OpenSSH_9.7p1 FreeBSD-20240701", sshproto.INDICIO),
    ],
)
def test_regresshion_matrix(line: str, status: str) -> None:
    result = verdict(line)
    assert result is not None and result.status == status


def test_regresshion_ignores_other_software() -> None:
    assert verdict("SSH-2.0-dropbear_2022.83") is None


def test_regresshion_finding_confidence_and_kev(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, banner=b"SSH-2.0-OpenSSH_9.3p1\r\n")
    [finding] = out.by_id("net.ssh.regresshion")
    assert finding.cves == ["CVE-2024-6387"]
    assert finding.confidence.value == "firm"
    assert finding.kev == vulndb.any_kev(["CVE-2024-6387"])


def test_regresshion_tentative_for_redhat_style(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, banner=b"SSH-2.0-OpenSSH_8.7\r\n")
    [finding] = out.by_id("net.ssh.regresshion")
    assert finding.confidence.value == "tentative"


def test_regresshion_fixed_package_not_reported(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, banner=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
    assert "net.ssh.regresshion" not in out.ids()
    assert any(p.control == "net.ssh.regresshion" for p in out.passed)


# -- regressões da revisão -----------------------------------------------------------------


def test_obsolete_algorithms_low_severity(ssh_server: list[FakeSshServer]) -> None:
    out = scan(
        ssh_server,
        hostkey=("ssh-ed25519", "ssh-rsa"),
        ciphers=(*MODERN_CIPHERS, "aes128-cbc"),
        macs=("hmac-sha1", "hmac-sha2-256-etm@openssh.com"),
    )
    [finding] = out.by_id("net.ssh.algoritmos_obsoletos")
    assert finding.severity.value == "low"
    assert "ssh-rsa" in finding.evidence


def test_critical_algorithms_raise_severity(ssh_server: list[FakeSshServer]) -> None:
    out = scan(ssh_server, hostkey=("ssh-dss", "ssh-ed25519"), ciphers=(*MODERN_CIPHERS, "none"))
    [finding] = out.by_id("net.ssh.algoritmos_fracos")
    assert finding.severity.value == "high"
    assert "ssh-dss" in finding.details["graves"]


def test_terrapin_cbc_etm_and_not_kev(ssh_server: list[FakeSshServer]) -> None:
    out = scan(
        ssh_server,
        kex=("curve25519-sha256",),
        ciphers=("aes128-cbc",),
        macs=("hmac-sha2-256-etm@openssh.com",),
    )
    [finding] = out.by_id("net.ssh.terrapin")
    assert finding.confidence.value == "firm"
    assert finding.kev is False
    assert finding.severity.value != "critical"


def test_hostile_algorithm_names_are_dropped() -> None:
    kex = sshproto.parse_kexinit(
        kexinit_payload(ciphers=("arcfour\x1b[31mEVIL", "aes128-ctr", "x" * 200))
    )
    assert kex.ciphers == ["aes128-ctr"]
    many = sshproto.parse_kexinit(kexinit_payload(kex=tuple(f"a{i}" for i in range(500))))
    assert len(many.get("kex")) == sshproto.MAX_NAMES


def test_ancient_openssh_is_only_an_indication() -> None:
    banner = sshproto.parse_banner("SSH-1.99-OpenSSH_3.9p1")
    assert banner is not None
    verdict = sshproto.regresshion(banner)
    assert verdict is not None and verdict.status == sshproto.INDICIO


def test_freebsd_is_not_labelled_linux(ssh_server: list[FakeSshServer]) -> None:
    out = scan(
        ssh_server, banner=b"SSH-2.0-OpenSSH_9.6p1 FreeBSD-20240104\r\n", kex=("curve25519-sha256",)
    )
    assert out.findings
    assert all("linux" not in f.tech for f in out.findings)
