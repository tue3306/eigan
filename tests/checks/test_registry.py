"""Cobertura do registro e da base de conhecimento.

Garante que o executável leva todas as checagens, que nenhuma checagem reporta um
achado sem explicação completa e que os cenários de ataque casam com achados reais.
"""

from __future__ import annotations

import re
import sys
from fnmatch import fnmatchcase

from eigan.core import facts, kb
from eigan.core.kb import CIS_V8, OWASP_2021
from eigan.core.registry import all_checks, discover_check_modules, load_builtin_checks
from eigan.intel import correlation

ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
FACT_KINDS = {
    value for name, value in vars(facts).items() if name.isupper() and isinstance(value, str)
}


def _declared_findings() -> set[str]:
    return {finding for check in all_checks() for finding in check.findings}


def test_todo_modulo_de_checagem_e_importado() -> None:
    load_builtin_checks()
    missing = [name for name in discover_check_modules() if name not in sys.modules]
    assert not missing, f"módulos fora da lista explícita de eigan.checks: {missing}"


def test_checagens_bem_formadas() -> None:
    checks = all_checks()
    assert len(checks) >= 40
    for check in checks:
        assert ID_RE.match(check.id), check.id
        assert check.name.strip() and check.description.strip(), check.id
        assert check.consumes in FACT_KINDS, (
            f"{check.id}: fato consumido desconhecido {check.consumes}"
        )
        unknown = [kind for kind in check.facts if kind not in FACT_KINDS]
        assert not unknown, f"{check.id}: fatos produzidos desconhecidos {unknown}"
        assert check.profiles, check.id


def test_todo_achado_declarado_tem_entrada_na_base() -> None:
    missing = sorted(
        f"{check.id} -> {finding}"
        for check in all_checks()
        for finding in check.findings
        if kb.get(finding) is None
    )
    assert not missing, missing


def test_toda_entrada_da_base_e_reportavel() -> None:
    declared = _declared_findings()
    orphans = [entry.id for entry in kb.all_entries() if entry.id not in declared]
    assert not orphans, f"entradas que nenhuma checagem declara: {orphans}"


def test_entradas_da_base_completas() -> None:
    problems: list[str] = []
    for entry in kb.all_entries():
        if not ID_RE.match(entry.id):
            problems.append(f"{entry.id}: id fora do padrão familia.assunto.problema")
        for name in ("title", "summary", "explanation", "risk", "verify"):
            if not str(getattr(entry, name)).strip():
                problems.append(f"{entry.id}: {name} vazio")
        if not entry.steps or any(not step.strip() for step in entry.steps):
            problems.append(f"{entry.id}: sem passos de correção")
        if not entry.fix_group:
            problems.append(f"{entry.id}: sem grupo de correção")
        if not entry.references:
            problems.append(f"{entry.id}: sem referência")
        problems += [
            f"{entry.id}: referência sem https: {ref}"
            for ref in entry.references
            if not ref.startswith("https://")
        ]
        if entry.owasp and entry.owasp not in OWASP_2021:
            problems.append(f"{entry.id}: OWASP desconhecido {entry.owasp}")
        problems += [f"{entry.id}: CIS desconhecido {c}" for c in entry.cis if c not in CIS_V8]
        if entry.cwe and not re.fullmatch(r"CWE-\d+", entry.cwe):
            problems.append(f"{entry.id}: CWE mal formado {entry.cwe}")
        problems += [
            f"{entry.id}: exemplo vazio ({fix.label})"
            for fix in entry.examples
            if not fix.code.strip() or not fix.label.strip()
        ]
    assert not problems, "\n".join(problems)


def test_padroes_dos_cenarios_casam_com_achados_reais() -> None:
    declared = _declared_findings()
    dead = [
        f"{scenario}: {pattern}"
        for scenario, pattern in correlation.all_patterns()
        if not any(fnmatchcase(finding, pattern) for finding in declared)
    ]
    assert not dead, f"padrões que não casam com nenhum achado: {dead}"
