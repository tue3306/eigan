"""Registro de checagens.

Uma checagem é uma função ``(ctx, fato) -> None`` que consome um tipo de fato
(``consumes``) e pode reportar achados e novos fatos. O motor de regras usa esse
registro para decidir o que rodar a cada fato aprendido — é o encadeamento que
faz a auditoria "pensar" sem IA.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import Category, Fact

if TYPE_CHECKING:
    from .context import CheckContext

ALL_PROFILES = frozenset({"rapido", "padrao", "completo"})
STANDARD_UP = frozenset({"padrao", "completo"})
DEEP_ONLY = frozenset({"completo"})

CheckFunc = Callable[["CheckContext", Fact], None]


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    category: Category
    consumes: str
    func: CheckFunc
    description: str
    findings: tuple[str, ...]
    facts: tuple[str, ...] = ()
    profiles: frozenset[str] = ALL_PROFILES
    when: Callable[[Fact], bool] | None = None
    platforms: frozenset[str] | None = None
    timeout: float = 180.0
    active: bool = False
    order: int = 50

    def applies(self, fact: Fact, profile: str, platform: str) -> bool:
        if fact.kind != self.consumes or profile not in self.profiles:
            return False
        if self.platforms is not None and platform not in self.platforms:
            return False
        if self.when is not None:
            try:
                return bool(self.when(fact))
            except Exception:  # noqa: BLE001 — predicado defeituoso não derruba o motor
                return False
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "category_label": self.category.label,
            "consumes": self.consumes,
            "description": self.description,
            "findings": list(self.findings),
            "facts": list(self.facts),
            "profiles": sorted(self.profiles),
            "platforms": sorted(self.platforms) if self.platforms else [],
            "active": self.active,
        }


_REGISTRY: dict[str, Check] = {}
_loaded = False


def register(item: Check) -> None:
    if item.id in _REGISTRY and _REGISTRY[item.id].func is not item.func:
        raise ValueError(f"checagem duplicada: {item.id}")
    _REGISTRY[item.id] = item


def check(
    *,
    id: str,
    name: str,
    category: Category,
    consumes: str,
    description: str,
    findings: tuple[str, ...] = (),
    facts: tuple[str, ...] = (),
    profiles: frozenset[str] = ALL_PROFILES,
    when: Callable[[Fact], bool] | None = None,
    platforms: frozenset[str] | None = None,
    timeout: float = 180.0,
    active: bool = False,
    order: int = 50,
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorador que registra uma checagem."""

    def decorator(func: CheckFunc) -> CheckFunc:
        register(
            Check(
                id=id,
                name=name,
                category=category,
                consumes=consumes,
                func=func,
                description=description,
                findings=findings,
                facts=facts,
                profiles=profiles,
                when=when,
                platforms=platforms,
                timeout=timeout,
                active=active,
                order=order,
            )
        )
        return func

    return decorator


def load_builtin_checks() -> None:
    """Importa ``eigan.checks``, que importa explicitamente cada módulo de checagem.

    A lista explícita (em vez de descoberta dinâmica) garante que o executável
    empacotado inclua todos os módulos; um teste confere que nenhum ficou de fora.
    """
    global _loaded
    if _loaded:
        return
    importlib.import_module("eigan.checks")
    _loaded = True


def discover_check_modules() -> list[str]:
    """Todos os módulos sob ``eigan.checks`` (usado pelo teste de cobertura do registro)."""
    import eigan.checks as package

    return sorted(
        info.name
        for info in pkgutil.walk_packages(package.__path__, prefix=f"{package.__name__}.")
        if not info.ispkg
    )


def all_checks() -> list[Check]:
    load_builtin_checks()
    return sorted(_REGISTRY.values(), key=lambda c: (c.category.value, c.order, c.id))


def get_check(check_id: str) -> Check | None:
    load_builtin_checks()
    return _REGISTRY.get(check_id)


def checks_for(fact: Fact, profile: str, platform: str) -> list[Check]:
    load_builtin_checks()
    matches = [c for c in _REGISTRY.values() if c.applies(fact, profile, platform)]
    return sorted(matches, key=lambda c: (c.order, c.id))
