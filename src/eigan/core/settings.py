"""Configurações da auditoria e perfis (rápida, padrão, completa)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from .. import __version__

PROFILES = ("rapido", "padrao", "completo")
PROFILE_LABEL = {"rapido": "Rápida", "padrao": "Padrão", "completo": "Completa"}
PROFILE_HELP = {
    "rapido": "O essencial em poucos minutos: principais portas e verificações de maior impacto.",
    "padrao": "Equilíbrio entre cobertura e tempo. Recomendado para a maioria dos casos.",
    "completo": "Cobertura máxima: mais portas, mais caminhos sensíveis e checagens extras.",
}


@dataclass
class Settings:
    profile: str = "padrao"
    # HTTP
    http_timeout: float = 10.0
    http_max_bytes: int = 2_000_000
    http_per_host: int = 6
    http_delay: float = 0.0
    user_agent: str = f"EIGAN/{__version__} (auditoria de seguranca autorizada)"
    max_http_services: int = 25
    # Rede
    port_timeout: float = 1.2
    port_workers: int = 200
    ports: str = "auto"  # auto (pelo perfil) | top100 | top300 | todas | lista "22,80,443"
    include_ports_for_url: bool = False
    max_network_hosts: int = 1024
    # Projeto e logs
    max_files: int = 25_000
    max_file_bytes: int = 2_000_000
    skip_dirs: str = ".git,node_modules,.venv,venv,__pycache__,dist,build,.tox,.mypy_cache,vendor"
    max_log_lines: int = 2_000_000
    # Motor
    workers: int = 8
    scan_timeout: float = 3600.0

    @property
    def ports_profile(self) -> str:
        if self.ports != "auto":
            return self.ports
        return {"rapido": "top100", "padrao": "top300", "completo": "todas"}.get(
            self.profile, "top300"
        )

    @property
    def deep(self) -> bool:
        return self.profile == "completo"

    @property
    def quick(self) -> bool:
        return self.profile == "rapido"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Settings:
        known = {f.name: f for f in fields(cls)}
        values: dict[str, Any] = {}
        for key, value in (raw or {}).items():
            spec = known.get(key)
            if spec is None:
                continue
            default = getattr(cls(), key)
            if isinstance(default, bool):
                values[key] = str(value).strip().lower() in ("1", "true", "sim", "yes", "on")
                continue
            try:
                values[key] = type(default)(value)
            except (TypeError, ValueError):
                continue
        settings = cls(**values)
        if settings.profile not in PROFILES:
            settings.profile = "padrao"
        settings.workers = max(1, min(settings.workers, 32))
        settings.port_workers = max(1, min(settings.port_workers, 1000))
        settings.http_per_host = max(1, min(settings.http_per_host, 32))
        return settings

    def with_profile(self, profile: str) -> Settings:
        clone = Settings.from_dict(self.to_dict())
        clone.profile = profile if profile in PROFILES else "padrao"
        return clone


def load_settings(path: Path | None = None) -> Settings:
    from .paths import settings_path

    target = path or settings_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Settings()
    return Settings.from_dict(raw if isinstance(raw, dict) else {})


def save_settings(settings: Settings, path: Path | None = None) -> None:
    from .paths import settings_path

    target = path or settings_path()
    target.write_text(json.dumps(settings.to_dict(), indent=2, ensure_ascii=False), "utf-8")
