"""Leitores de manifestos e lockfiles: cada formato, com casos que não podem virar dependência."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eigan.checks.code import manifests
from eigan.checks.code.files import SourceFile
from eigan.checks.code.parsers_js import (
    parse_package_json,
    parse_package_lock,
    parse_pnpm_lock,
    parse_yarn_lock,
)
from eigan.checks.code.parsers_jvm import parse_gradle_build, parse_gradle_lock, parse_pom
from eigan.checks.code.parsers_misc import (
    parse_cargo_lock,
    parse_composer_lock,
    parse_csproj,
    parse_gemfile_lock,
    parse_go_mod,
    parse_go_sum,
    parse_nuget_lock,
    parse_nuget_props,
    parse_packages_config,
)
from eigan.checks.code.parsers_py import (
    parse_pipfile_lock,
    parse_requirements,
    parse_toml_lock,
)


def pairs(deps: list[manifests.Dependency]) -> set[tuple[str, str]]:
    return {(d.name, d.version) for d in deps}


def lines(deps: list[manifests.Dependency]) -> dict[str, int]:
    return {d.name: d.line for d in deps}


# -- requirements -----------------------------------------------------------------------


def test_requirements_so_versoes_fixadas() -> None:
    text = """\
# comentário
Django==3.2.1
requests == 2.25.0  # fixado
uvicorn[standard]==0.20.0 ; python_version >= "3.8"
PyYAML===5.3.1
hashed==1.0.0 \\
    --hash=sha256:abc
flask>=2.0
jinja2~=3.0
werkzeug!=2.0.0
pillow==9.*
numpy==1.2.*,<2
-r outros.txt
-e git+https://github.com/org/pacote.git#egg=pacote
pacote-url @ https://example.com/pacote-1.0.tar.gz
git+https://github.com/org/outro.git
--index-url https://pypi.org/simple
./pasta/local
"""
    deps = parse_requirements(text)
    assert pairs(deps) == {
        ("Django", "3.2.1"),
        ("requests", "2.25.0"),
        ("uvicorn", "0.20.0"),
        ("PyYAML", "5.3.1"),
        ("hashed", "1.0.0"),
    }
    assert lines(deps)["Django"] == 2


def test_requirements_vazio_e_so_comentarios() -> None:
    assert parse_requirements("") == []
    assert parse_requirements("# nada aqui\n\n   \n") == []


def test_pipfile_lock_default_e_develop() -> None:
    text = json.dumps(
        {
            "_meta": {"hash": {"sha256": "x"}},
            "default": {
                "django": {"version": "==3.2.1", "hashes": []},
                "pacote-git": {"git": "https://github.com/org/p.git", "ref": "abc"},
            },
            "develop": {"pytest": {"version": "==7.0.0"}},
        },
        indent=4,
    )
    deps = parse_pipfile_lock(text)
    assert pairs(deps) == {("django", "3.2.1"), ("pytest", "7.0.0")}
    assert lines(deps)["django"] > 0


def test_pipfile_lock_invalido_levanta_valueerror() -> None:
    with pytest.raises(ValueError):
        parse_pipfile_lock("{ isso não é json")


def test_poetry_lock_ignora_fontes_locais() -> None:
    text = """\
[[package]]
name = "requests"
version = "2.25.0"
description = "x"

[[package]]
name = "interno"
version = "1.0.0"

[package.source]
type = "directory"
url = "../interno"

[[package]]
name = "fork-git"
version = "2.0.0"

[package.source]
type = "git"
url = "https://github.com/org/fork.git"

[[package]]
name = "mirror"
version = "3.0.0"

[package.source]
type = "legacy"
url = "https://pypi.internal/simple"
reference = "interno"
"""
    deps = parse_toml_lock(text)
    assert pairs(deps) == {("requests", "2.25.0"), ("mirror", "3.0.0")}
    assert lines(deps)["requests"] == 2


def test_uv_lock_ignora_o_proprio_projeto() -> None:
    text = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "meu-projeto"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "urllib3"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pacote-git"
version = "1.0.0"
source = { git = "https://github.com/org/p.git" }
"""
    assert pairs(parse_toml_lock(text)) == {("urllib3", "1.26.4")}


# -- npm --------------------------------------------------------------------------------


def _lock_v3() -> str:
    return json.dumps(
        {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                },
                "node_modules/@babel/core": {"version": "7.0.0"},
                "node_modules/a/node_modules/minimist": {"version": "0.0.8"},
                "node_modules/apelido": {"name": "qs", "version": "6.5.2"},
                "packages/local": {"name": "local", "version": "9.9.9"},
                "node_modules/local": {"resolved": "packages/local", "link": True},
                "node_modules/pasta": {"version": "1.0.0", "resolved": "file:../pasta"},
                "node_modules/do-git": {
                    "version": "1.2.3",
                    "resolved": "git+ssh://git@github.com/org/do-git.git#abc",
                },
                "node_modules/tarball": {
                    "version": "1.2.3",
                    "resolved": "https://codeload.github.com/org/tarball/tar.gz/abc",
                },
            },
        },
        indent=2,
    )


def test_package_lock_v3() -> None:
    deps = parse_package_lock(_lock_v3())
    assert pairs(deps) == {
        ("lodash", "4.17.20"),
        ("@babel/core", "7.0.0"),
        ("minimist", "0.0.8"),
        ("qs", "6.5.2"),
    }
    assert lines(deps)["lodash"] > 0


def test_package_lock_v2_prefere_packages() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "app"},
                "node_modules/axios": {"version": "0.21.0"},
            },
            "dependencies": {"axios": {"version": "0.21.0"}},
        }
    )
    assert pairs(parse_package_lock(text)) == {("axios", "0.21.0")}


def test_package_lock_v1_aninhado_e_apelido() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                    "dependencies": {"qs": {"version": "6.7.0"}},
                },
                "apelido": {"version": "npm:lodash@4.17.15"},
                "de-pasta": {"version": "file:../pasta"},
                "do-github": {"version": "github:org/repo#abc"},
            },
        },
        indent=2,
    )
    assert pairs(parse_package_lock(text)) == {
        ("express", "4.17.1"),
        ("qs", "6.7.0"),
        ("lodash", "4.17.15"),
    }


def test_package_lock_que_nao_e_objeto() -> None:
    assert parse_package_lock("[]") == []


def test_yarn_lock_v1() -> None:
    text = """\
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.12.13":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#abc"
  integrity sha512-abc
  dependencies:
    "@babel/highlight" "^7.12.13"

lodash@^4.17.15, lodash@^4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#abc"

apelido@npm:minimist@^1.2.0:
  version "1.2.0"

"do-git@git+https://github.com/org/do-git.git#abc":
  version "1.0.0"

"do-github@github:org/repo":
  version "1.0.0"

"de-url@https://example.com/x.tgz":
  version "1.0.0"

"de-pasta@file:../pasta":
  version "1.0.0"
"""
    deps = parse_yarn_lock(text)
    assert pairs(deps) == {
        ("@babel/code-frame", "7.12.13"),
        ("lodash", "4.17.20"),
        ("minimist", "1.2.0"),
    }
    assert lines(deps)["lodash"] == 11


def test_yarn_lock_berry() -> None:
    text = """\
__metadata:
  version: 6
  cacheKey: 8

"@babel/core@npm:^7.0.0":
  version: 7.0.0
  resolution: "@babel/core@npm:7.0.0"
  languageName: node

"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"

"apelido@npm:minimist@^1.2.0":
  version: 1.2.0
  resolution: "minimist@npm:1.2.0"

"meu-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "meu-app@workspace:."

"sub@workspace:packages/sub":
  version: 1.0.0
  resolution: "sub@workspace:packages/sub"

"pasta@portal:../pasta::locator=x":
  version: 1.0.0
"""
    assert pairs(parse_yarn_lock(text)) == {
        ("@babel/core", "7.0.0"),
        ("lodash", "4.17.20"),
        ("minimist", "1.2.0"),
    }


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("  /lodash/4.17.20:", ("lodash", "4.17.20")),  # formato 5
        ("  /@babel/core/7.0.0_react@17.0.0:", ("@babel/core", "7.0.0")),
        ("  /qs@6.5.2:", ("qs", "6.5.2")),  # formato 6
        ("  /foo@1.0.0(bar@2.0.0):", ("foo", "1.0.0")),
        ("  lodash@4.17.20:", ("lodash", "4.17.20")),  # formato 9
        ("  '@babel/core@7.0.0':", ("@babel/core", "7.0.0")),
        ("  '@babel/core@7.0.0(react@17.0.0)':", ("@babel/core", "7.0.0")),
    ],
)
def test_pnpm_lock_formatos(line: str, expected: tuple[str, str]) -> None:
    text = f"lockfileVersion: '9.0'\n\npackages:\n\n{line}\n    resolution: {{integrity: x}}\n"
    deps = parse_pnpm_lock(text)
    assert pairs(deps) == {expected}
    assert deps[0].line == 5


def test_pnpm_lock_outras_secoes_nao_contam() -> None:
    text = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.20

packages:

  qs@6.5.2:
    resolution: {integrity: x}
    dependencies:
      lodash: 4.17.20

  meu-link@file:../pasta:
    resolution: {directory: ../pasta}

snapshots:

  qs@6.5.2:
    dependencies:
      lodash: 4.17.20
"""
    assert pairs(parse_pnpm_lock(text)) == {("qs", "6.5.2")}


def test_package_json_so_versoes_exatas() -> None:
    text = json.dumps(
        {
            "name": "app",
            "dependencies": {
                "lodash": "4.17.20",
                "axios": "^0.21.0",
                "qs": "~6.5.0",
                "de-git": "github:org/repo",
                "apelido": "npm:minimist@1.2.0",
                "curinga": "*",
                "tag": "latest",
                "faixa": ">=1.0.0 <2.0.0",
                "com-v": "v1.2.3",
                "com-igual": "=2.0.0",
            },
            "devDependencies": {"jest": "26.0.0"},
            "optionalDependencies": {"fsevents": "2.3.2"},
            "peerDependencies": {"react": "17.0.0"},
        },
        indent=2,
    )
    deps = parse_package_json(text)
    assert pairs(deps) == {
        ("lodash", "4.17.20"),
        ("minimist", "1.2.0"),
        ("com-v", "1.2.3"),
        ("com-igual", "2.0.0"),
        ("jest", "26.0.0"),
        ("fsevents", "2.3.2"),
    }
    assert lines(deps)["lodash"] == 4


# -- PHP, Ruby, Go, Rust, .NET ------------------------------------------------------------


def test_composer_lock() -> None:
    text = json.dumps(
        {
            "packages": [
                {"name": "guzzlehttp/guzzle", "version": "7.4.4"},
                {"name": "phpmailer/phpmailer", "version": "v5.2.18"},
                {"name": "org/branch", "version": "dev-main"},
                {"name": "org/alias", "version": "2.x-dev"},
                {"name": "org/alias2", "version": "2.1.x-dev"},
                {"name": "org/local", "version": "1.0.0", "dist": {"type": "path"}},
            ],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}],
        },
        indent=4,
    )
    deps = parse_composer_lock(text)
    assert pairs(deps) == {
        ("guzzlehttp/guzzle", "7.4.4"),
        ("phpmailer/phpmailer", "5.2.18"),
        ("phpunit/phpunit", "9.5.0"),
    }
    assert lines(deps)["guzzlehttp/guzzle"] > 0


def test_gemfile_lock() -> None:
    text = """\
GIT
  remote: https://github.com/org/gem-git.git
  revision: abc
  specs:
    gem-git (1.0.0)

PATH
  remote: .
  specs:
    meu-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (5.2.0)
      activesupport (= 5.2.0)
    nokogiri (1.13.0-x86_64-linux)
      racc (~> 1.4)
    rake (13.0.1)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack (= 5.2.0)
  rake (>= 12)

BUNDLED WITH
   2.3.7
"""
    deps = parse_gemfile_lock(text)
    assert pairs(deps) == {("actionpack", "5.2.0"), ("nokogiri", "1.13.0"), ("rake", "13.0.1")}
    assert lines(deps)["actionpack"] == 15


def test_go_mod_require_e_replace() -> None:
    text = """\
module example.com/app

go 1.21

toolchain go1.21.3

require github.com/unico/pacote v1.2.3

require (
\tgolang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
\tgolang.org/x/net v0.7.0 // indirect
\tgithub.com/trocado/a v1.0.0
\tgithub.com/local/b v1.0.0
\tgithub.com/so-versao/c v1.0.0
\tgithub.com/outra-versao/d v2.0.0
)

replace github.com/trocado/a => github.com/fork/a v1.5.0

replace (
\tgithub.com/local/b => ../pasta-local
\tgithub.com/so-versao/c v1.0.0 => github.com/fork/c v1.1.0
\tgithub.com/outra-versao/d v1.0.0 => github.com/fork/d v1.1.0
)

exclude github.com/excluido/e v1.0.0

retract v1.0.0
"""
    deps = parse_go_mod(text)
    assert pairs(deps) == {
        ("github.com/unico/pacote", "v1.2.3"),
        ("golang.org/x/crypto", "v0.0.0-20210513164829-c07d793c2f9a"),
        ("golang.org/x/net", "v0.7.0"),
        ("github.com/fork/a", "v1.5.0"),
        ("github.com/fork/c", "v1.1.0"),
        ("github.com/outra-versao/d", "v2.0.0"),
    }


def test_go_sum_ignora_linhas_de_go_mod() -> None:
    text = (
        "golang.org/x/net v0.7.0 h1:abc=\n"
        "golang.org/x/net v0.7.0/go.mod h1:def=\n"
        "golang.org/x/text v0.3.0/go.mod h1:ghi=\n"
    )
    assert pairs(parse_go_sum(text)) == {("golang.org/x/net", "v0.7.0")}


def test_cargo_lock_so_crates_io() -> None:
    text = """\
version = 3

[[package]]
name = "meu-crate"
version = "0.1.0"

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "esparso"
version = "2.0.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "do-git"
version = "1.0.0"
source = "git+https://github.com/org/do-git#abc"

[[package]]
name = "privado"
version = "1.0.0"
source = "registry+https://crates.empresa.local/index"
"""
    deps = parse_cargo_lock(text)
    assert pairs(deps) == {("smallvec", "1.6.0"), ("esparso", "2.0.0")}
    assert lines(deps)["smallvec"] == 8


def test_nuget_lock() -> None:
    text = json.dumps(
        {
            "version": 1,
            "dependencies": {
                "net6.0": {
                    "Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.3"},
                    "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"},
                    "Meu.Projeto": {"type": "Project"},
                },
                "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}},
            },
        },
        indent=2,
    )
    assert pairs(parse_nuget_lock(text)) == {
        ("Newtonsoft.Json", "12.0.3"),
        ("Newtonsoft.Json", "13.0.3"),
        ("System.Text.Json", "6.0.0"),
    }


def test_csproj_package_reference() -> None:
    text = """\
<Project Sdk="Microsoft.NET.Sdk">
  <!-- <PackageReference Include="Comentado" Version="1.0.0" /> -->
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
    <PackageReference Include="Dentro">
      <Version>2.0.0</Version>
    </PackageReference>
    <PackageReference Include="Fixada" Version="[3.1.0]" />
    <PackageReference Include="Faixa" Version="[1.0,2.0)" />
    <PackageReference Include="Curinga" Version="1.*" />
    <PackageReference Include="Variavel" Version="$(MinhaVersao)" />
    <PackageReference Include="SemVersao" />
    <PackageReference Update="Atualizada" Version="4.0.0" />
  </ItemGroup>
</Project>
"""
    deps = parse_csproj(text)
    assert pairs(deps) == {
        ("Newtonsoft.Json", "12.0.3"),
        ("Dentro", "2.0.0"),
        ("Fixada", "3.1.0"),
        ("Atualizada", "4.0.0"),
    }
    assert lines(deps)["Newtonsoft.Json"] == 4


def test_packages_config() -> None:
    text = """\
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <!-- <package id="Comentado" version="1.0.0" /> -->
  <package id="Newtonsoft.Json" version="9.0.1" targetFramework="net45" />
  <package id="Faixa" version="[1.0,2.0)" />
</packages>
"""
    assert pairs(parse_packages_config(text)) == {("Newtonsoft.Json", "9.0.1")}


def test_directory_packages_props() -> None:
    text = """\
<Project>
  <ItemGroup>
    <!-- <PackageVersion Include="Comentado" Version="1.0.0" /> -->
    <PackageVersion Include="Serilog" Version="2.10.0" />
    <PackageVersion Include="Faixa" Version="[1.0,)" />
  </ItemGroup>
</Project>
"""
    assert pairs(parse_nuget_props(text)) == {("Serilog", "2.10.0")}


# -- JVM ----------------------------------------------------------------------------------


def test_pom_versoes_literais_propriedades_e_parent() -> None:
    text = """\
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.6.5</version>
  </parent>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <encadeada>${log4j.version}</encadeada>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>${encadeada}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.8</version>
      <exclusions>
        <exclusion>
          <groupId>org.excluido</groupId>
          <artifactId>nao-conta</artifactId>
          <version>1.0.0</version>
        </exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>sem.versao</groupId>
      <artifactId>gerida-por-bom</artifactId>
    </dependency>
    <dependency>
      <groupId>variavel.desconhecida</groupId>
      <artifactId>x</artifactId>
      <version>${nao.existe}</version>
    </dependency>
    <dependency>
      <groupId>faixa</groupId>
      <artifactId>y</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
    <!-- <dependency>
      <groupId>comentado</groupId>
      <artifactId>z</artifactId>
      <version>1.0.0</version>
    </dependency> -->
  </dependencies>
</project>
"""
    deps = parse_pom(text)
    assert pairs(deps) == {
        ("org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("org.apache.logging.log4j:log4j-api", "2.14.1"),
        ("org.springframework.boot:spring-boot-starter-web", "2.6.5"),
        ("com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
    }
    by_name = {d.name: d for d in deps}
    assert by_name["org.springframework.boot:spring-boot-starter-web"].note.startswith(
        "versão herdada"
    )
    assert by_name["org.apache.logging.log4j:log4j-core"].line == 14


def test_pom_sem_versao_nem_parent_nao_vira_dependencia() -> None:
    text = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId></dependency></dependencies></project>"
    assert parse_pom(text) == []


def test_gradle_lockfile() -> None:
    text = """\
# This is a Gradle generated file for dependency locking.
com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath
empty=annotationProcessor
"""
    deps = parse_gradle_lock(text)
    assert pairs(deps) == {
        ("com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
        ("org.apache.logging.log4j:log4j-core", "2.14.1"),
    }
    assert lines(deps)["org.apache.logging.log4j:log4j-core"] == 3


def test_gradle_build_literais() -> None:
    text = """\
dependencies {
    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    api("com.google.guava:guava:30.0-jre")
    testImplementation group: 'junit', name: 'junit', version: '4.12'
    implementation 'com.exemplo:faixa:1.+'
    implementation 'com.exemplo:faixa2:1.0.+'
    implementation "com.exemplo:variavel:$versao"
    // implementation 'comentado:x:1.0.0'
}
"""
    assert pairs(parse_gradle_build(text)) == {
        ("org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("com.google.guava:guava", "30.0-jre"),
        ("junit:junit", "4.12"),
    }


# -- identificação e limites ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "kind", "ecosystem", "lockfile"),
    [
        ("package-lock.json", "package-lock", "npm", True),
        ("sub/npm-shrinkwrap.json", "package-lock", "npm", True),
        ("yarn.lock", "yarn-lock", "npm", True),
        ("pnpm-lock.yaml", "pnpm-lock", "npm", True),
        ("package.json", "package-json", "npm", False),
        ("Pipfile.lock", "pipfile-lock", "PyPI", True),
        ("poetry.lock", "poetry-lock", "PyPI", True),
        ("uv.lock", "uv-lock", "PyPI", True),
        ("requirements.txt", "requirements", "PyPI", False),
        ("requirements-dev.txt", "requirements", "PyPI", False),
        ("dev-requirements.txt", "requirements", "PyPI", False),
        ("constraints.txt", "requirements", "PyPI", False),
        ("requirements/base.txt", "requirements", "PyPI", False),
        ("composer.lock", "composer-lock", "Packagist", True),
        ("Gemfile.lock", "gemfile-lock", "RubyGems", True),
        ("go.mod", "go-mod", "Go", False),
        ("go.sum", "go-sum", "Go", True),
        ("Cargo.lock", "cargo-lock", "crates.io", True),
        ("packages.lock.json", "nuget-lock", "NuGet", True),
        ("packages.config", "packages-config", "NuGet", False),
        ("Directory.Packages.props", "nuget-props", "NuGet", False),
        ("src/App.csproj", "csproj", "NuGet", False),
        ("src/App.fsproj", "csproj", "NuGet", False),
        ("pom.xml", "pom", "Maven", False),
        ("gradle.lockfile", "gradle-lock", "Maven", True),
        ("gradle/dependency-locks/x.lockfile", "gradle-lock", "Maven", True),
        ("build.gradle", "gradle-build", "Maven", False),
        ("build.gradle.kts", "gradle-build", "Maven", False),
    ],
)
def test_identifica_manifesto(rel: str, kind: str, ecosystem: str, lockfile: bool) -> None:
    spec = manifests.identify(SourceFile(Path(rel), rel, 0))
    assert spec is not None
    assert (spec.kind, spec.ecosystem, spec.lockfile) == (kind, ecosystem, lockfile)
    assert manifests.parser_for(spec.kind) is not None


@pytest.mark.parametrize(
    "rel",
    ["README.md", "notes.txt", "src/main.py", "my-requirements-notes.md", "package.json.bak"],
)
def test_outros_arquivos_nao_sao_manifesto(rel: str) -> None:
    assert manifests.identify(SourceFile(Path(rel), rel, 0)) is None


def test_unique_remove_repeticoes_e_valores_absurdos() -> None:
    deps = [
        manifests.Dependency("a", "1.0.0", 1),
        manifests.Dependency("a", "1.0.0", 2),
        manifests.Dependency("a", "1.0.1", 3),
        manifests.Dependency("", "1.0.0"),
        manifests.Dependency("b", ""),
        manifests.Dependency("longa", "1." * 200),
        manifests.Dependency("n" * 1000, "1.0.0"),
    ]
    assert [(d.name, d.version, d.line) for d in manifests.unique(deps)] == [
        ("a", "1.0.0", 1),
        ("a", "1.0.1", 3),
    ]


def test_superseded_lockfile_torna_package_json_redundante(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    manifest = tmp_path / "pkg" / "package.json"
    manifest.write_text("{}", encoding="utf-8")
    assert manifests.superseded_by(manifest, "package-json", tmp_path) is None
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    assert manifests.superseded_by(manifest, "package-json", tmp_path) == "yarn.lock"


def test_superseded_outros_formatos(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module x", encoding="utf-8")
    (tmp_path / "packages.lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "gradle.lockfile").write_text("", encoding="utf-8")
    assert manifests.superseded_by(tmp_path / "go.sum", "go-sum", tmp_path) == "go.mod"
    assert (
        manifests.superseded_by(tmp_path / "A.csproj", "csproj", tmp_path) == "packages.lock.json"
    )
    assert (
        manifests.superseded_by(tmp_path / "build.gradle", "gradle-build", tmp_path)
        == "gradle.lockfile"
    )
    assert manifests.superseded_by(tmp_path / "pom.xml", "pom", tmp_path) is None


# -- entradas hostis: tempo linear ---------------------------------------------------


@pytest.mark.parametrize("repeat", ['<PackageReference Include="a">', "<!--"])
def test_csproj_com_tags_sem_fechamento_e_linear(repeat: str) -> None:
    import time

    from eigan.checks.code.parsers_misc import parse_csproj

    start = time.monotonic()
    parse_csproj(repeat * 40_000)
    assert time.monotonic() - start < 5


def test_pom_com_tags_sem_fechamento_e_linear() -> None:
    import time

    start = time.monotonic()
    for tag in ("<dependency>", "<parent>", "<properties>", "<exclusions>"):
        parse_pom(tag * 40_000)
    assert time.monotonic() - start < 5


def test_requirements_com_espacos_longos_e_comentario_colado() -> None:
    import time

    from eigan.checks.code.parsers_py import parse_requirements

    start = time.monotonic()
    parse_requirements("a" + " " * 100_000 + "x\n")
    assert time.monotonic() - start < 2
    assert pairs(parse_requirements("color==1.0#nota\n")) == {("color", "1.0")}
