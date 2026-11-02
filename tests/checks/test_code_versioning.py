"""Comparação de versões por ecossistema e avaliação de faixas do OSV."""

from __future__ import annotations

import itertools

import pytest

from eigan.checks.code import versioning
from eigan.checks.code.versioning import (
    VersionRange,
    compare,
    highest,
    in_range,
    is_affected,
    is_exact,
    normalize,
    smallest_fix,
    sort_versions,
)


def assert_strictly_increasing(ecosystem: str, versions: list[str]) -> None:
    """Cada par da lista precisa respeitar a ordem (nos dois sentidos da comparação)."""
    for (i, left), (j, right) in itertools.combinations(enumerate(versions), 2):
        assert i < j
        assert compare(ecosystem, left, right) == -1, f"{left} deveria vir antes de {right}"
        assert compare(ecosystem, right, left) == 1, f"{right} deveria vir depois de {left}"


# -- SemVer ---------------------------------------------------------------------------


def test_semver_ordem_da_especificacao() -> None:
    # Exemplo literal de https://semver.org/#spec-item-11
    assert_strictly_increasing(
        "npm",
        [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ],
    )


def test_semver_metadados_de_build_nao_contam() -> None:
    assert compare("npm", "1.2.3+build.5", "1.2.3") == 0
    assert compare("crates.io", "1.2.3+meta", "1.2.3+outro") == 0


@pytest.mark.parametrize("ecosystem", ["npm", "crates.io", "Go"])
def test_semver_numeros_comparam_como_numero(ecosystem: str) -> None:
    assert compare(ecosystem, "1.10.0", "1.9.0") == 1
    assert compare(ecosystem, "4.17.21", "4.17.3") == 1


def test_semver_prefixo_v_e_igual_sinal() -> None:
    assert normalize("npm", "v1.2.3") == "1.2.3"
    assert normalize("npm", "=1.2.3") == "1.2.3"
    assert compare("npm", "v1.2.3", "1.2.3") == 0


# -- Go -------------------------------------------------------------------------------


def test_go_pseudo_versoes() -> None:
    assert_strictly_increasing(
        "Go",
        [
            "v0.0.0-20210513164829-c07d793c2f9a",
            "v0.0.0-20220314234659-1baeb1ce4c0b",
            "v0.17.0",
            "v1.2.3",
            "v1.2.4-0.20220101000000-abcdefabcdef",
            "v1.2.4",
        ],
    )


def test_go_incompatible_e_ignorado() -> None:
    assert compare("Go", "v2.0.0+incompatible", "2.0.0") == 0


# -- PEP 440 --------------------------------------------------------------------------


def test_pep440_ordem_da_especificacao() -> None:
    # Exemplo literal de https://peps.python.org/pep-0440/#summary-of-permitted-suffixes-and-relative-ordering
    assert_strictly_increasing(
        "PyPI",
        [
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.0.15",
            "1.1.dev1",
        ],
    )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1.0", "1.0.0"),
        ("1.0.0", "1"),
        ("1.0a1", "1.0.a.1"),
        ("1.0a1", "1.0-alpha-1"),
        ("1.0rc1", "1.0c1"),
        ("1.0rc1", "1.0pre1"),
        ("1.0.post1", "1.0-1"),
        ("1.0.post1", "1.0-r1"),
        ("v1.0", "1.0"),
    ],
)
def test_pep440_grafias_equivalentes(left: str, right: str) -> None:
    assert compare("PyPI", left, right) == 0


def test_pep440_epoca_vence_a_versao() -> None:
    assert compare("PyPI", "1!0.1", "2024.1") == 1


def test_pep440_versoes_invalidas_caem_na_comparacao_tolerante() -> None:
    # Não pode levantar exceção: versões antigas do PyPI nem sempre seguem a PEP 440.
    assert versioning.pep440_compare("foo-bar", "1.0") is None
    assert compare("PyPI", "2.0.custom", "1.0") == 1


# -- Maven ----------------------------------------------------------------------------


def test_maven_ordem_de_qualificadores() -> None:
    # Ordem de https://maven.apache.org/pom.html#Version_Order_Specification
    assert_strictly_increasing(
        "Maven",
        [
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ],
    )


def test_maven_ordem_numerica() -> None:
    assert_strictly_increasing(
        "Maven",
        [
            "2.0",
            "2.0.a",
            "2-1",
            "2.0.2",
            "2.0.123",
            "2.1.0",
            "2.1-a",
            "2.1b",
            "2.1-c",
            "2.1-1",
            "2.1.0.1",
            "2.2",
            "2.123",
            "11.a2",
            "11.a11",
            "11.b2",
            "11.b11",
            "11.m2",
            "11.m11",
            "11",
            "11.a",
            "11b",
            "11c",
            "11m",
        ],
    )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1", "1.0"),
        ("1", "1.0.0"),
        ("1", "1-0"),
        ("1", "1.0-0"),
        ("1a", "1-a"),
        ("1a", "1.0-a"),
        ("1a", "1.0.0-a"),
        ("1x", "1-x"),
        ("1x", "1.0-x"),
        ("1", "1ga"),
        ("1", "1release"),
        ("1", "1final"),
        ("1", "1.0.0.RELEASE"),
        ("2.3.1", "2.3.1.Final"),
        ("5.3.18", "5.3.18.RELEASE"),
        ("1cr", "1rc"),
        ("1a1", "1-alpha-1"),
        ("1b2", "1-beta-2"),
        ("1m3", "1-milestone-3"),
        ("1X", "1x"),
        ("1A", "1a"),
        ("1GA", "1ga"),
        ("1RELEASE", "1release"),
        ("1SNAPSHOT", "1snapshot"),
    ],
)
def test_maven_grafias_equivalentes(left: str, right: str) -> None:
    assert compare("Maven", left, right) == 0
    assert compare("Maven", right, left) == 0


def test_maven_casos_reais_do_log4j_e_spring() -> None:
    assert compare("Maven", "2.0-beta9", "2.0") == -1
    assert compare("Maven", "2.0-beta9", "2.0-rc1") == -1
    assert compare("Maven", "2.15.0-rc1", "2.15.0") == -1
    assert compare("Maven", "2.17.1", "2.15.0") == 1
    assert compare("Maven", "5.3.17.RELEASE", "5.3.18") == -1
    assert compare("Maven", "31.1-jre", "32.0.0-android") == -1


# -- RubyGems -------------------------------------------------------------------------


def test_rubygems_letras_sao_pre_lancamento() -> None:
    # Exemplos da documentação de Gem::Version
    assert_strictly_increasing("RubyGems", ["1.0.a.2", "1.0.b1", "1.0.rc1", "1.0", "1.0.1", "1.1"])


@pytest.mark.parametrize(
    ("left", "right"),
    [("1.0", "1"), ("1.0.0", "1.0"), ("1.2.3-1", "1.2.3.pre.1"), ("0.3.0", "0.3")],
)
def test_rubygems_equivalencias(left: str, right: str) -> None:
    assert compare("RubyGems", left, right) == 0


def test_rubygems_plataforma_nao_faz_parte_da_versao() -> None:
    assert compare("RubyGems", "1.16.2-x86_64-linux", "1.16.2") == 0
    assert compare("RubyGems", "1.13.10-java", "1.14.0") == -1


# -- Packagist ------------------------------------------------------------------------


def test_composer_estabilidades() -> None:
    assert_strictly_increasing(
        "Packagist",
        [
            "1.0.0-dev",
            "1.0.0-alpha1",
            "1.0.0-alpha2",
            "1.0.0-beta",
            "1.0.0-beta2",
            "1.0.0-RC1",
            "1.0.0",
            "1.0.0-patch1",
            "1.0.1",
        ],
    )


def test_composer_quatro_numeros_e_prefixo_v() -> None:
    assert compare("Packagist", "1.0", "1.0.0.0") == 0
    assert compare("Packagist", "v7.4.5", "7.4.5") == 0
    assert compare("Packagist", "7.4.10", "7.4.5") == 1


# -- NuGet ----------------------------------------------------------------------------


def test_nuget_quatro_numeros_e_rotulos_sem_maiusculas() -> None:
    assert compare("NuGet", "13.0.1.0", "13.0.1") == 0
    assert compare("NuGet", "1.0.0-ALPHA", "1.0.0-alpha") == 0
    assert compare("NuGet", "1.0.0.1", "1.0.0") == 1
    assert compare("NuGet", "1.0.0-beta", "1.0.0") == -1


# -- versão exata ---------------------------------------------------------------------


@pytest.mark.parametrize("version", ["1.2.3", "4", "1.0.0-beta.1", "2.0.0.RELEASE", "1.2.3+build5"])
def test_versao_exata(version: str) -> None:
    assert is_exact(version)


@pytest.mark.parametrize(
    "version",
    [
        "",
        "^1.2.3",
        "~1.2",
        ">=2.0",
        "<3",
        "1.2.*",
        "1.x",
        "1.2.x",
        "1.2.X",
        "1.0.+",
        "1.+",
        "1.2.x-dev",
        "latest",
        "${versao}",
        "[1.0,2.0)",
        "1.0 - 2.0",
        "1.0 || 2.0",
    ],
)
def test_faixas_nao_sao_versao_exata(version: str) -> None:
    assert not is_exact(version)


# -- faixas do OSV --------------------------------------------------------------------


def _range(*events: tuple[str, str]) -> VersionRange:
    return VersionRange(tuple(events))


def test_faixa_introduced_fixed() -> None:
    rng = _range(("introduced", "1.0.0"), ("fixed", "1.2.0"))
    assert not in_range("npm", "0.9.9", rng)
    assert in_range("npm", "1.0.0", rng)
    assert in_range("npm", "1.1.9", rng)
    assert not in_range("npm", "1.2.0", rng)
    assert not in_range("npm", "2.0.0", rng)


def test_faixa_introduced_zero_e_sempre() -> None:
    rng = _range(("introduced", "0"), ("fixed", "2.0.0"))
    assert in_range("npm", "0.0.1", rng)
    assert in_range("npm", "1.9.9", rng)
    assert not in_range("npm", "2.0.0", rng)


def test_faixa_sem_correcao_afeta_tudo_depois_de_introduced() -> None:
    rng = _range(("introduced", "1.0.0"))
    assert in_range("Maven", "99.0", rng)
    assert not in_range("Maven", "0.9", rng)


def test_faixa_last_affected_inclui_a_ultima() -> None:
    rng = _range(("introduced", "0"), ("last_affected", "1.2.17"))
    assert in_range("Maven", "1.2.17", rng)
    assert not in_range("Maven", "1.2.18", rng)


def test_faixa_reintroducao_e_ordem_dos_eventos() -> None:
    # Eventos fora de ordem: a especificação manda ordenar antes de avaliar.
    rng = _range(
        ("fixed", "1.5.0"),
        ("introduced", "2.0.0"),
        ("fixed", "2.1.0"),
        ("introduced", "0"),
    )
    assert in_range("npm", "1.4.0", rng)
    assert not in_range("npm", "1.5.0", rng)
    assert not in_range("npm", "1.9.0", rng)
    assert in_range("npm", "2.0.5", rng)
    assert not in_range("npm", "2.1.0", rng)


def test_faixa_limit_corta_o_que_vem_depois() -> None:
    rng = _range(("introduced", "1.0.0"), ("limit", "2.0.0"))
    assert in_range("npm", "1.5.0", rng)
    assert not in_range("npm", "2.0.0", rng)
    assert in_range("npm", "9.9.9", _range(("introduced", "0"), ("limit", "*")))


def test_is_affected_faixas_e_versao_corrigida() -> None:
    ranges = (
        _range(("introduced", "2.0"), ("fixed", "2.3.1")),
        _range(("introduced", "2.4"), ("fixed", "2.12.2")),
        _range(("introduced", "2.13.0"), ("fixed", "2.15.0")),
    )
    assert is_affected("Maven", "2.14.1", ranges) == (True, "2.15.0")
    assert is_affected("Maven", "2.4.1", ranges) == (True, "2.12.2")
    assert is_affected("Maven", "2.3.1", ranges) == (False, None)
    assert is_affected("Maven", "2.12.2", ranges) == (False, None)
    assert is_affected("Maven", "2.17.1", ranges) == (False, None)


def test_is_affected_sem_versao_corrigida() -> None:
    assert is_affected("Maven", "1.2.17", (_range(("introduced", "0")),)) == (True, None)


def test_is_affected_lista_explicita_de_versoes() -> None:
    explicit = frozenset({"1.0.0", "1.0.1"})
    assert is_affected("npm", "1.0.1", (), explicit)[0] is True
    assert is_affected("npm", "v1.0.0", (), explicit)[0] is True
    assert is_affected("npm", "1.0.2", (), explicit) == (False, None)


def test_is_affected_lista_explicita_com_grafia_equivalente() -> None:
    assert is_affected("PyPI", "1.0.0", (), frozenset({"1.0"}))[0] is True


@pytest.mark.parametrize("version", ["", "latest", "dev-master", "workspace:*"])
def test_is_affected_ignora_versao_que_nao_e_numero(version: str) -> None:
    assert is_affected("npm", version, (_range(("introduced", "0")),)) == (False, None)


def test_smallest_fix_escolhe_a_menor_acima_da_instalada() -> None:
    ranges = [
        _range(("introduced", "0"), ("fixed", "1.2.0")),
        _range(("introduced", "0"), ("fixed", "1.0.5")),
        _range(("introduced", "0"), ("fixed", "2.0.0")),
    ]
    assert smallest_fix("npm", "1.1.0", ranges) == "1.2.0"
    assert smallest_fix("npm", "3.0.0", ranges) is None


def test_sort_e_highest_respeitam_o_ecossistema() -> None:
    assert sort_versions("npm", ["1.10.0", "", "1.9.0"]) == ["1.9.0", "1.10.0"]
    assert highest("Maven", ["2.15.0-rc1", "2.15.0", "2.3.1"]) == "2.15.0"
    assert highest("npm", []) is None
