"""Inventário e varredura de projetos: limites, pastas ignoradas, links e arquivos grandes."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fakes_code import project_fact, write_tree
from helpers import run_check

from eigan.checks.code import files
from eigan.checks.code.files import (
    SourceFile,
    context_adjust,
    lower_severity,
    path_context,
    project_files,
    raise_severity,
    read_text,
    tech_of,
    walk,
)
from eigan.core.context import Cancelled, CheckContext, ScanContext
from eigan.core.models import Confidence, Fact, Severity
from eigan.core.registry import get_check, load_builtin_checks
from eigan.core.settings import Settings
from eigan.core.target import parse_target

SKIP = {"node_modules", "vendor", ".venv", "venv", "dist", "build"}


def rels(root: Path, **kwargs: object) -> list[str]:
    params: dict = {"skip_dirs": SKIP, "max_files": 1000, **kwargs}
    return [f.rel for f in walk(root, **params).files]


def try_symlink(link: Path, target: Path, *, is_dir: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("este sistema não permite criar links simbólicos (Windows sem modo dev)")


# -- varredura ------------------------------------------------------------------------


def test_walk_lista_arquivos_com_caminho_relativo(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "x", "src/b.js": "y", "src/sub/c.go": "z"})
    assert rels(tmp_path) == ["a.py", "src/b.js", "src/sub/c.go"]


@pytest.mark.parametrize(
    "folder",
    [
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".gradle",
        ".terraform",
        ".next",
        "bower_components",
        "site-packages",
    ],
)
def test_walk_sempre_ignora_vcs_e_caches(tmp_path: Path, folder: str) -> None:
    write_tree(tmp_path, {f"{folder}/segredo.py": "x", "app.py": "y"})
    # Mesmo com a lista de pastas do usuário vazia.
    assert rels(tmp_path, skip_dirs=set()) == ["app.py"]


@pytest.mark.parametrize("folder", ["node_modules", "vendor", "venv", ".venv", "dist", "build"])
def test_walk_ignora_pastas_configuradas(tmp_path: Path, folder: str) -> None:
    write_tree(tmp_path, {f"{folder}/lib/x.js": "x", f"src/{folder}/y.js": "y", "app.py": "z"})
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=1000)
    assert [f.rel for f in listing.files] == ["app.py"]
    assert listing.skipped_dirs == 2


def test_walk_ignora_nome_de_pasta_sem_diferenciar_maiusculas(tmp_path: Path) -> None:
    write_tree(tmp_path, {"Node_Modules/x.js": "x", "app.py": "y"})
    assert rels(tmp_path) == ["app.py"]


def test_walk_pasta_com_nome_parecido_nao_e_ignorada(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"vendors/x.py": "x", "build-tools/y.py": "y", "my_node_modules/z.py": "z"}
    )
    assert len(rels(tmp_path)) == 3


@pytest.mark.parametrize("marker", ["pyvenv.cfg", "conda-meta/history"])
def test_walk_ignora_ambiente_virtual_com_qualquer_nome(tmp_path: Path, marker: str) -> None:
    write_tree(
        tmp_path, {f"meu_ambiente/{marker}": "x", "meu_ambiente/lib/a.py": "y", "app.py": "z"}
    )
    assert rels(tmp_path) == ["app.py"]


def test_walk_para_no_limite_de_arquivos(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"f{i:02}.txt": "x" for i in range(10)})
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=4)
    assert len(listing.files) == 4
    assert listing.truncated is True


def test_walk_no_limite_exato_nao_marca_truncado(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"f{i}.txt": "x" for i in range(3)})
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=3)
    assert len(listing.files) == 3
    assert listing.truncated is False


def test_walk_para_no_limite_de_profundidade(tmp_path: Path) -> None:
    deep = "/".join(f"n{i}" for i in range(6))
    write_tree(tmp_path, {f"{deep}/fundo.txt": "x", "n0/raso.txt": "y"})
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=100, max_depth=3)
    assert [f.rel for f in listing.files] == ["n0/raso.txt"]
    assert listing.too_deep == 1


def test_walk_nao_lista_arquivos_em_pasta_ilegivel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path, {"a/x.txt": "x", "b/y.txt": "y"})
    real = os.scandir

    def fake(path: object):  # noqa: ANN202
        if str(path).endswith("a"):
            raise PermissionError("negado")
        return real(path)  # type: ignore[arg-type]

    monkeypatch.setattr(files.os, "scandir", fake)
    assert rels(tmp_path) == ["b/y.txt"]


def test_walk_respeita_cancelamento(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/x.txt": "x"})

    def cancel() -> None:
        raise Cancelled()

    with pytest.raises(Cancelled):
        walk(tmp_path, skip_dirs=SKIP, max_files=10, check=cancel)


def test_walk_nao_segue_link_de_arquivo(tmp_path: Path) -> None:
    write_tree(tmp_path, {"real.txt": "x"})
    outside = tmp_path.parent / f"{tmp_path.name}-fora.txt"
    outside.write_text("segredo", encoding="utf-8")
    try:
        try_symlink(tmp_path / "link.txt", outside, is_dir=False)
        listing = walk(tmp_path, skip_dirs=SKIP, max_files=10)
        assert [f.rel for f in listing.files] == ["real.txt"]
        assert listing.links == 1
    finally:
        outside.unlink(missing_ok=True)


def test_walk_nao_segue_ciclo_de_links(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/b/x.txt": "x"})
    try_symlink(tmp_path / "a" / "b" / "volta", tmp_path, is_dir=True)
    try_symlink(tmp_path / "a" / "laco", tmp_path / "a", is_dir=True)
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=100)
    assert [f.rel for f in listing.files] == ["a/b/x.txt"]
    assert listing.links == 2


def test_walk_nao_visita_a_mesma_pasta_duas_vezes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Montagens podem expor a mesma pasta por dois caminhos: mesma identidade = uma visita só.
    write_tree(tmp_path, {"a/x.txt": "x", "b/y.txt": "y"})
    monkeypatch.setattr(
        files,
        "_identity",
        lambda folder: (1, 1) if folder.name in ("a", "b") else (1, 2),
    )
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=10)
    assert [f.rel for f in listing.files] == ["a/x.txt"]
    assert listing.skipped_dirs == 1


@pytest.mark.skipif(sys.platform != "win32", reason="junções existem só no Windows")
def test_walk_nao_segue_juncao_do_windows(tmp_path: Path) -> None:
    import _winapi

    write_tree(tmp_path, {"real/x.txt": "x"})
    try:
        _winapi.CreateJunction(str(tmp_path / "real"), str(tmp_path / "juncao"))
    except OSError:
        pytest.skip("não foi possível criar a junção")
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=10)
    assert [f.rel for f in listing.files] == ["real/x.txt"]
    assert listing.links == 1


def test_project_files_e_calculado_uma_vez_por_auditoria(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "x"})
    load_builtin_checks()
    item = get_check("code.inventory")
    assert item is not None
    fact = project_fact(tmp_path)
    scan = ScanContext(parse_target("https://127.0.0.1/"), Settings())
    ctx = CheckContext(scan, item, fact)
    first = project_files(ctx, tmp_path)
    write_tree(tmp_path, {"b.py": "y"})
    assert project_files(ctx, tmp_path) is first


def test_project_files_usa_as_configuracoes(tmp_path: Path) -> None:
    write_tree(tmp_path, {"minha_pasta/a.py": "x", "b.py": "y", "c.py": "z"})
    load_builtin_checks()
    item = get_check("code.inventory")
    assert item is not None
    settings = Settings(skip_dirs="minha_pasta, outra ", max_files=1)
    scan = ScanContext(parse_target("https://127.0.0.1/"), settings)
    listing = project_files(CheckContext(scan, item, project_fact(tmp_path)), tmp_path)
    assert [f.rel for f in listing.files] == ["b.py"]
    assert listing.truncated


# -- leitura de arquivos --------------------------------------------------------------


def test_read_text_decodifica_utf8_e_bom(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes("﻿olá".encode())
    assert read_text(tmp_path / "a.txt", 100) == "olá"


def test_read_text_utf16_com_bom(tmp_path: Path) -> None:
    # "pip freeze > requirements.txt" no PowerShell grava UTF-16.
    (tmp_path / "a.txt").write_bytes("django==1.0".encode("utf-16"))
    assert read_text(tmp_path / "a.txt", 100) == "django==1.0"


def test_read_text_bytes_invalidos_nao_quebram(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"ok \xff\xfe fim")
    text = read_text(tmp_path / "a.txt", 100)
    assert text is not None
    assert text.startswith("ok ")


def test_read_text_ignora_binario(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"MZ\x00\x01\x02" + b"x" * 100)
    assert read_text(tmp_path / "a.bin", 1000) is None


def test_read_text_ignora_arquivo_grande(tmp_path: Path) -> None:
    (tmp_path / "grande.txt").write_bytes(b"x" * 2000)
    assert read_text(tmp_path / "grande.txt", 1000) is None
    assert read_text(tmp_path / "grande.txt", 2000) == "x" * 2000


def test_read_text_arquivo_inexistente(tmp_path: Path) -> None:
    assert read_text(tmp_path / "nao-existe.txt", 1000) is None


def test_readable_filtra_por_tamanho(tmp_path: Path) -> None:
    write_tree(tmp_path, {"pequeno.txt": "x", "grande.txt": "y" * 500})
    listing = walk(tmp_path, skip_dirs=SKIP, max_files=10)
    assert [f.rel for f in listing.readable(100)] == ["pequeno.txt"]


# -- contexto do caminho --------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("tests/fixtures/tls/localhost.key", "teste"),
        ("src/__tests__/a.js", "teste"),
        ("spec/models/user_spec.rb", "teste"),
        ("app/testdata/x.json", "teste"),
        ("test_app.py", "teste"),
        ("conftest.py", "teste"),
        ("pkg/server_test.go", "teste"),
        ("web/app.test.ts", "teste"),
        ("web/app.spec.tsx", "teste"),
        ("src/UserServiceTest.java", "teste"),
        ("src/UserServiceTests.cs", "teste"),
        ("src/foo_test.php", "teste"),
        ("test.php", "teste"),
        ("examples/config.py", "exemplo"),
        ("docs/guia.txt", "exemplo"),
        ("sample_settings.py", "exemplo"),
        ("config.example.json", "exemplo"),
        ("demo-app.yml", "exemplo"),
        (".env.template", "exemplo"),
        ("phpunit.xml.dist", "exemplo"),
        ("README.md", "exemplo"),
        ("guia.rst", "exemplo"),
        ("src/app.py", ""),
        ("config/settings.py", ""),
        (".env", ""),
        # "test" no meio de uma palavra não é teste.
        ("src/latest.php", ""),
        ("src/Latest.java", ""),
        ("src/contest.cs", ""),
        ("attest_service.py", ""),
        ("src/fastest.go", ""),
        ("exemplary.py", ""),
    ],
)
def test_path_context(rel: str, expected: str) -> None:
    assert path_context(rel) == expected


def test_context_adjust_teste_fica_baixa_e_indicio() -> None:
    severity, confidence, where = context_adjust(
        "tests/x.py", Severity.CRITICAL, Confidence.CONFIRMED
    )
    assert (severity, confidence, where) == (Severity.LOW, Confidence.TENTATIVE, "teste")


def test_context_adjust_exemplo_perde_um_nivel() -> None:
    severity, confidence, where = context_adjust(
        "examples/x.py", Severity.HIGH, Confidence.CONFIRMED
    )
    assert (severity, confidence, where) == (Severity.MEDIUM, Confidence.TENTATIVE, "exemplo")


def test_context_adjust_codigo_normal_nao_muda() -> None:
    assert context_adjust("src/x.py", Severity.HIGH, Confidence.FIRM) == (
        Severity.HIGH,
        Confidence.FIRM,
        "",
    )


def test_ajuste_de_severidade_nos_limites() -> None:
    assert lower_severity(Severity.CRITICAL) is Severity.HIGH
    assert lower_severity(Severity.LOW) is Severity.LOW
    assert lower_severity(Severity.INFO) is Severity.INFO
    assert raise_severity(Severity.HIGH) is Severity.CRITICAL
    assert raise_severity(Severity.CRITICAL) is Severity.CRITICAL


@pytest.mark.parametrize(
    ("name", "tech"),
    [
        ("app.py", ["python"]),
        ("Dockerfile", ["dockerfile"]),
        ("api.dockerfile", ["dockerfile"]),
        ("web.config", ["csharp"]),
        ("appsettings.Production.json", ["csharp"]),
        ("Main.java", ["java"]),
        ("dados.csv", []),
    ],
)
def test_tech_of(name: str, tech: list[str]) -> None:
    assert tech_of(SourceFile(Path(name), name, 0)) == tech


# -- checagem de inventário -----------------------------------------------------------


def _inventory(root: Path, **settings: object):  # noqa: ANN202
    return run_check("code.inventory", project_fact(root), settings=Settings(**settings))


def test_inventario_linguagens_e_manifestos(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "app.py": "x",
            "lib/util.py": "x",
            "web/index.ts": "x",
            "web/package.json": "{}",
            "web/package-lock.json": "{}",
            "requirements.txt": "",
            "go.mod": "module x",
            "node_modules/lodash/package.json": "{}",
            "README.md": "x",
        },
    )
    out = _inventory(tmp_path)
    assert out.findings == []
    manifests = {f.data["rel"]: f.data for f in out.facts if f.kind == "code.manifest"}
    assert set(manifests) == {
        "web/package.json",
        "web/package-lock.json",
        "requirements.txt",
        "go.mod",
    }
    lock = manifests["web/package-lock.json"]
    assert lock["ecosystem"] == "npm"
    assert lock["kind"] == "package-lock"
    assert lock["lockfile"] is True
    assert lock["project"] == str(tmp_path)
    assert Path(lock["path"]).is_file()

    [inventory] = [f for f in out.facts if f.kind == "code.inventory"]
    assert inventory.data["files"] == 8
    assert inventory.data["languages"] == {"Python": 2, "TypeScript": 1}
    assert inventory.data["ecosystems"] == ["Go", "PyPI", "npm"]
    assert inventory.data["truncated"] is False
    assert set(inventory.data["manifests"]) == set(manifests)


def test_inventario_avisa_quando_trunca(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"f{i}.py": "x" for i in range(5)})
    out = _inventory(tmp_path, max_files=2)
    [inventory] = [f for f in out.facts if f.kind == "code.inventory"]
    assert inventory.data["files"] == 2
    assert inventory.data["truncated"] is True
    assert any("max_files" in line for line in out.logs)


def test_inventario_limita_numero_de_manifestos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from eigan.checks.code import inventory

    monkeypatch.setattr(inventory, "MAX_MANIFESTS", 2)
    write_tree(tmp_path, {f"p{i}/go.mod": "module x" for i in range(5)})
    out = _inventory(tmp_path)
    assert len(out.fact_keys("code.manifest")) == 2
    assert any("manifestos encontrados" in line for line in out.logs)


def test_inventario_pasta_vazia(tmp_path: Path) -> None:
    out = _inventory(tmp_path)
    assert out.findings == []
    assert out.fact_keys("code.manifest") == set()
    [inventory] = [f for f in out.facts if f.kind == "code.inventory"]
    assert inventory.data["files"] == 0


def test_inventario_alvo_que_nao_e_pasta(tmp_path: Path) -> None:
    arquivo = tmp_path / "arquivo.txt"
    arquivo.write_text("x", encoding="utf-8")
    fact = Fact("project", str(arquivo), {"path": str(arquivo)})
    out = run_check("code.inventory", fact)
    assert out.facts == []
    assert any("não é uma pasta" in line for line in out.logs)


def test_inventario_nao_publica_manifesto_de_pasta_ignorada(tmp_path: Path) -> None:
    write_tree(tmp_path, {"vendor/lib/composer.lock": "{}", "dist/package.json": "{}"})
    assert _inventory(tmp_path).fact_keys("code.manifest") == set()


def test_inventario_registra_links_nao_seguidos(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "x"})
    try_symlink(tmp_path / "laco", tmp_path, is_dir=True)
    out = _inventory(tmp_path)
    assert any("links" in line for line in out.logs)
