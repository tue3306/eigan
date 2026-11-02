"""Leitor mínimo de YAML: o subconjunto de compose/Kubernetes, com a linha de cada nó."""

from __future__ import annotations

import pytest

from eigan.checks.code.yamlish import (
    Node,
    blank_template_actions,
    parse_documents,
    parse_inline,
    split_documents,
    strip_comment,
    to_python,
    unquote,
)


def _one(text: str) -> Node:
    documents = parse_documents(text)
    assert len(documents) == 1
    return documents[0]


def test_mapa_lista_e_escalares_com_linha() -> None:
    node = _one(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27  # comentário\n"
        "    ports:\n"
        '      - "80:80"\n'
        "      - 443:443\n"
    )
    assert to_python(node) == {
        "services": {"web": {"image": "nginx:1.27", "ports": ["80:80", "443:443"]}}
    }
    web = node.get("services", "web")
    assert web is not None
    assert web.line_of("image") == 3
    assert [item.line for item in web.seq("ports")] == [5, 6]
    assert web.text("image") == "nginx:1.27"
    assert web.text("nada") == ""
    assert web.has("ports") and not web.has("nada")


def test_lista_no_mesmo_recuo_da_chave() -> None:
    node = _one("volumes:\n- a:/a\n- b:/b\nimage: x\n")
    assert to_python(node) == {"volumes": ["a:/a", "b:/b"], "image": "x"}


def test_itens_de_lista_com_mapa_e_lista_aninhados() -> None:
    node = _one(
        "containers:\n"
        "- name: a\n"
        "  args:\n"
        "  - x\n"
        "  securityContext:\n"
        "    privileged: true\n"
        "- name: b\n"
        "  image: z\n"
    )
    first, second = node.seq("containers")
    assert first.flag("securityContext", "privileged") is True
    assert first.seq("args")[0].text() == "x"
    assert second.text("image") == "z"
    assert second.line == 7


def test_lista_dentro_de_lista() -> None:
    assert to_python(_one("- - a\n  - b\n- c\n")) == [["a", "b"], "c"]


def test_booleanos_do_yaml() -> None:
    node = _one("a: yes\nb: 'off'\nc: TRUE\nd: talvez\n")
    assert node.flag("a") is True
    assert node.flag("b") is False
    assert node.flag("c") is True
    assert node.flag("d") is None
    assert node.flag("ausente") is None


def test_listas_e_mapas_em_linha_inclusive_quebrados() -> None:
    node = _one(
        "cap_add: [SYS_ADMIN, 'NET_ADMIN']\nm: {a: b, c: [1, 2]}\nlonga: [a,\n  b,\n  'c,d']\nfim: 1\n"
    )
    assert to_python(node) == {
        "cap_add": ["SYS_ADMIN", "NET_ADMIN"],
        "m": {"a": "b", "c": ["1", "2"]},
        "longa": ["a", "b", "c,d"],
        "fim": "1",
    }
    assert node.seq("cap_add")[0].line == 1


def test_lista_em_linha_sem_fechar_nao_engole_o_restante() -> None:
    node = _one("a: [b,\nc: d\n")
    assert node.text("c") == "d"


def test_blocos_de_texto() -> None:
    node = _one(
        "script: |\n  linha 1\n  linha 2\nargs:\n  - |\n    echo a\n    echo b\n  - >-\n    junta\nfim: x\n"
    )
    assert node.text("script") == "linha 1\nlinha 2"
    assert [item.text() for item in node.seq("args")] == ["echo a\necho b", "junta"]
    assert node.text("fim") == "x"


def test_escalar_em_varias_linhas_nao_vira_chave() -> None:
    node = _one("descricao: texto longo\n  continua: aqui\nimage: x\n")
    assert node.text("descricao") == "texto longo"
    assert node.text("image") == "x"
    assert not node.has("continua")


def test_varios_documentos_e_linhas_globais() -> None:
    documents = parse_documents(
        "---\nkind: Pod\n--- # segundo\nkind: Service\n...\n---\n# só comentário\n---\nkind: Job\n"
    )
    assert [doc.text("kind") for doc in documents] == ["Pod", "Service", "Job"]
    assert documents[1].line_of("kind") == 4
    assert documents[2].line_of("kind") == 9


def test_documento_na_mesma_linha_do_separador() -> None:
    [lines] = split_documents("--- kind: Pod\n")
    assert lines[0].content == "kind: Pod"


def test_ancoras_alias_e_mescla() -> None:
    node = _one(
        "x-base: &base\n"
        "  privileged: true\n"
        "  restart: always\n"
        "x-outro: &outro\n"
        "  user: root\n"
        "services:\n"
        "  a:\n"
        "    <<: *base\n"
        "    restart: never\n"
        "  b:\n"
        "    <<: [*base, *outro]\n"
        "  c: *base\n"
        "  d:\n"
        "    lista: [*base]\n"
    )
    a = node.get("services", "a")
    assert a is not None
    assert a.flag("privileged") is True
    assert a.text("restart") == "never"
    assert a.line_of("restart") == 9
    assert a.line_of("privileged") == 2
    assert node.text("services", "b", "user") == "root"
    assert node.flag("services", "c", "privileged") is True
    assert node.seq("services", "d", "lista")[0].flag("privileged") is True


def test_tags_sao_descartadas() -> None:
    node = _one("a: !!str 123\nb: !custom\n  c: 1\n")
    assert node.text("a") == "123"
    assert node.text("b", "c") == "1"


def test_alias_desconhecido_vira_vazio() -> None:
    assert _one("a: *nada\n").text("a") == ""


def test_nulos_viram_vazio() -> None:
    node = _one("a: ~\nb: null\nc:\nd: ''\n")
    assert [node.text(key) for key in "abcd"] == ["", "", "", ""]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("a: b # c", "a: b"),
        ("a: 'b # c' # d", "a: 'b # c'"),
        ('a: "b # c"', 'a: "b # c"'),
        (r'a: "b\" # c" # d', r'a: "b\" # c"'),
        ("a: 'it''s # c' # d", "a: 'it''s # c'"),
        ("a: don't # comentário", "a: don't"),
        ("url: http://x/#ancora", "url: http://x/#ancora"),
        ("# tudo", ""),
    ],
)
def test_comentarios(line: str, expected: str) -> None:
    assert strip_comment(line) == expected


def test_aspas_e_escapes() -> None:
    assert unquote('"a\\"b"') == 'a"b'
    assert unquote("'it''s'") == "it's"
    assert unquote("sem aspas") == "sem aspas"
    assert parse_inline("~") is None


def test_chaves_entre_aspas_e_com_dois_pontos() -> None:
    node = _one("\"a:b\": 1\n'c d': 2\nhttp://x: 3\nkey: valor: com dois pontos\n")
    assert to_python(node) == {
        "a:b": "1",
        "c d": "2",
        "http://x": "3",
        "key": "valor: com dois pontos",
    }


def test_template_de_helm_nao_interrompe_a_leitura() -> None:
    text = (
        "apiVersion: apps/v1\n"
        "{{- if .Values.x }}\n"
        "kind: Deployment\n"
        "{{- end }}\n"
        "metadata:\n"
        "  name: {{ .Chart.Name }}\n"
        '  image: "{{ .Values.repo }}:{{ .Values.tag }}"\n'
    )
    node = _one(blank_template_actions(text))
    assert node.text("kind") == "Deployment"
    assert node.line_of("kind") == 3
    assert node.text("metadata", "name") == "{{ .Chart.Name }}"
    assert "{{ .Values.tag }}" in node.text("metadata", "image")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n# nada\n",
        "- - - \n",
        "a: [\n",
        "{{{{{{",
        ": sem chave\n",
        "\t\ta: b\n\t- c\n",
        "a:\n  - b\n c: d\n    e: f\n",
        "- a: 1\n b: 2\n",
    ],
)
def test_texto_malformado_nunca_quebra(text: str) -> None:
    for node in parse_documents(text):
        assert isinstance(node, Node)
        to_python(node)


def test_aninhamento_absurdo_nao_estoura_a_pilha() -> None:
    deep = "".join(" " * i + f"k{i}:\n" for i in range(5000))
    assert len(parse_documents(deep)) == 1
    flow = "a: " + "[" * 5000 + "]" * 5000 + "\n"
    assert len(parse_documents(flow)) == 1


def test_lista_em_linha_gigante_tem_custo_linear() -> None:
    text = "a: [\n" + "  b,\n" * 200_000
    assert parse_documents(text)[0].has("a")


def test_linha_com_corrida_enorme_de_espacos_nao_trava() -> None:
    import time

    inicio = time.monotonic()
    parse_documents("a" + " " * 100_000 + "b\n")
    parse_documents("a" + " " * 100_000 + "b: 1\n")
    assert time.monotonic() - inicio < 3
