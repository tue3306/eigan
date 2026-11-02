"""Relatório PDF: conteúdo, acentos, marcação hostil, textos longos e centenas de achados."""

from __future__ import annotations

import re
from typing import Any

import pytest
from fakes_reports import (
    IMG,
    PAYLOADS,
    SCRIPT,
    SECRET,
    analyzed,
    clean_result,
    make,
    many_findings,
    not_evaluated,
    pdf_pages,
    pdf_text_of,
    sample_result,
    sample_with_diff,
    scan,
)
from reportlab.platypus import Paragraph

from eigan.core import kb
from eigan.core.kb import Fix, KBEntry
from eigan.core.models import (
    Category,
    CheckRun,
    Decision,
    PassedControl,
    ScanResult,
    Severity,
    TriageStatus,
)
from eigan.reports import render_pdf
from eigan.reports.pdf_blocks import MAX_CODE_ROWS, Kit, code_rows, wrap_line
from eigan.reports.pdf_canvas import _fit
from eigan.reports.pdf_styles import styles
from eigan.reports.pdf_text import escape, markup, pdf_text


def squeeze(text: str) -> str:
    """Sem espaços: a extração de texto do teste separa os pedaços do desenho."""
    return re.sub(r"\s+", "", text)


def has(pdf: bytes, text: str) -> bool:
    return squeeze(text) in squeeze(pdf_text_of(pdf))


def valid(pdf: bytes) -> bytes:
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2000
    return pdf


# -- conteúdo --------------------------------------------------------------------------------


def test_pdf_completo_tem_as_partes_do_relatorio() -> None:
    result = sample_with_diff()
    pdf = valid(render_pdf(result))
    assert pdf_pages(pdf) >= 2
    posture = result.analysis["posture"]
    for text in (
        "Relatório de auditoria de segurança",
        "https://exemplo.com.br",
        "Site ou aplicação web",
        "Padrão",
        "4 min 12 s",
        "0.0.0",
        posture["grade"],
        posture["label"],
        result.analysis["narrative"]["headline"],
        "Resumo",
        "Plano de correção",
        "Principais achados",
        "Exploração conhecida (CISA KEV)",
        "CVE-2021-44228",
        "Comparação com a auditoria anterior",
        "Pontos fortes",
        "Só aceita TLS 1.2 e TLS 1.3",
        "Conformidade: OWASP Top 10 (2021)",
        "Sem achados nas verificações do EIGAN",
        "Verificações que não terminaram",
        "Sem resposta em 30 s",
        "Gerado pelo EIGAN 0.0.0",
        "análise local por regras, sem IA e sem envio de dados",
        "Use somente em sistemas que você tem autorização para avaliar.",
    ):
        assert has(pdf, text), text
    assert has(pdf, f"{posture['score']}/100")


def test_rodape_com_numero_de_paginas_e_versao() -> None:
    pdf = render_pdf(sample_result())
    pages = pdf_pages(pdf)
    assert has(pdf, f"Página 1 de {pages}")
    assert has(pdf, f"Página {pages} de {pages}")
    assert has(pdf, "EIGAN 0.0.0")


def test_plano_tem_passos_verificacao_e_codigo() -> None:
    result = analyzed(scan([make("web.hsts.ausente", tech=["nginx"])]))
    pdf = render_pdf(result)
    entry = kb.require("web.hsts.ausente")
    for step in entry.steps:
        assert has(pdf, pdf_text(step)), step
    assert has(pdf, pdf_text(entry.verify))
    assert has(pdf, "Exemplo de correção")
    assert b"/Courier" in pdf


def test_acentos_do_portugues_saem_corretos() -> None:
    title = "Ação de correção: coração, São João, àéíóú ãõ ç ÀÉÍÓÚ ÃÕ Ç ª º — “aspas” ‘simples’ …"
    pdf = render_pdf(analyzed(scan([make(title=title)])))
    assert has(pdf, title)
    assert "?" not in pdf_text(title)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("≥ 1", ">= 1"),
        ("≤ 2", "<= 2"),
        ("a → b", "a -> b"),
        ("✓ ok", "OK ok"),
        ("− 5", "- 5"),
        ("≠", "!="),
        ("漢字", "??"),
        ("😀", "?"),
        ("ő", "o"),
        ("a\u200bb", "ab"),
        ("a\u00adb", "ab"),
        ("a\x00b\x1bc", "abc"),
        ("a\tb", "a    b"),
        ("a\r\nb\rc", "a\nb\nc"),
        ("\ud83d", "?"),
        ("\u202ex", "?x"),
    ],
)
def test_caracteres_fora_da_fonte_padrao(text: str, expected: str) -> None:
    assert pdf_text(text) == expected
    pdf_text(text).encode("cp1252")


def test_titulo_com_caracteres_fora_do_cp1252_renderiza() -> None:
    pdf = valid(render_pdf(analyzed(scan([make(title="≥ ✓ 漢 😀 \u202e fim")]))))
    # Controles invisíveis ficam à mostra; o que a fonte padrão não desenha vira "?".
    assert has(pdf, ">= OK ? ? <U+202E> fim")


# -- marcação hostil --------------------------------------------------------------------------


def test_escape_do_minimo_de_marcacao() -> None:
    assert escape("<b>&amp;</b>") == "&lt;b&gt;&amp;amp;&lt;/b&gt;"
    assert markup("<a>\nb") == "&lt;a&gt;<br/>b"
    assert markup("a" * 10, 5) == "aaaa…"
    assert markup("a\n\n  b\r\nc", 20) == "a b c"


REPORTLAB_MARKUP = (
    "<b>sem fechar",
    "</b></para>",
    "<para><font color='red' size='99'>grande</font></para>",
    '<img src="file:///etc/passwd" width="10" height="10"/>',
    '<a href="javascript:alert(1)">clique</a>',
    '<a href="http://mal.example" color="blue">link</a>',
    "<link href='http://mal.example'>x</link>",
    "<seq id='a'/>",
    "<br/><br/><nobr>",
    "&bogus; &#xZZ; & &amp",
    "<![CDATA[x]]>",
    "<?xml version='1.0'?>",
    "<!-- comentário -->",
    "<onDraw name='x'/>",
    "<greek>a</greek><sub>1</sub><super>2</super>",
)


@pytest.mark.parametrize("payload", [*REPORTLAB_MARKUP, *PAYLOADS])
def test_marcacao_vinda_do_alvo_nunca_e_interpretada(payload: str) -> None:
    finding = make(
        title=payload,
        asset=payload,
        evidence=payload,
        details={payload: payload},
        status=TriageStatus.OPEN,
        cves=[payload],
        kev=True,
    )
    result = analyzed(
        scan(
            [finding],
            target=payload,
            id=payload,
            profile=payload,
            status=payload,
            app_version=payload,
            passed=[PassedControl("c", payload, payload)],
            decisions=[Decision("2026-11-01T10:00:00+00:00", payload)],
            runs=[CheckRun("x", payload, payload, payload, 0.1, payload)],
            errors=[payload],
        )
    )
    pdf = valid(render_pdf(result))
    # Nenhum link, ação ou imagem criados a partir do texto do alvo.
    assert b"/URI" not in pdf
    assert b"/Annot" not in pdf
    assert b"/JavaScript" not in pdf
    assert b"/Subtype /Image" not in pdf
    assert b"/Launch" not in pdf
    assert has(pdf, pdf_text(payload))


def test_marcacao_em_todos_os_campos_da_analise() -> None:
    result = analyzed(scan([make()]))
    action = result.analysis["plan"][0]
    hostile = "<b>x</i>&<img src=x/>"
    action["title"] = action["area"] = action["band_text"] = hostile
    action["assets"] = [hostile]
    action["fixes"] = [{"tech": hostile, "label": hostile, "lang": hostile, "code": hostile}]
    problem = action["problems"][0]
    problem["title"] = problem["summary"] = problem["verify"] = hostile
    problem["steps"] = [hostile]
    result.analysis["narrative"]["headline"] = hostile
    result.analysis["narrative"]["paragraphs"] = [hostile]
    result.analysis["posture"]["label"] = hostile
    result.analysis["posture"]["cap_reason"] = hostile
    result.analysis["scenarios"] = [
        {
            "id": hostile,
            "title": hostile,
            "severity": "high",
            "narrative": hostile,
            "breaker": hostile,
            "host": hostile,
        }
    ]
    result.analysis["kev"] = [
        {
            "cve": hostile,
            "name": hostile,
            "vendor": hostile,
            "product": hostile,
            "date_added": hostile,
            "ransomware": True,
            "finding": hostile,
            "title": hostile,
            "asset": hostile,
        }
    ]
    result.analysis["kev_catalog"] = {"versao": hostile, "publicado": hostile}
    result.analysis["compliance"] = {
        "owasp": [{"id": "A01:2021", "label": hostile, "count": 1, "worst": "high"}],
        "lgpd": {"count": 1, "worst": "high", "titles": [hostile], "text": hostile},
    }
    result.analysis["diff"] = {
        "previous_date": hostile,
        "previous_profile": hostile,
        "grade_before": hostile,
        "new": [{"title": hostile, "asset": hostile, "severity": "high"}],
        "fixed": [{"title": hostile, "asset": hostile, "severity": hostile}],
    }
    pdf = valid(render_pdf(result))
    assert b"/Subtype /Image" not in pdf
    assert has(pdf, pdf_text(hostile))


def test_metadados_do_arquivo_com_alvo_hostil() -> None:
    pdf = valid(render_pdf(analyzed(scan([make()], target="a(b)\\c\n<x>" + "y" * 300))))
    assert b"/Title" in pdf
    assert b"/Producer" in pdf


def test_segredos_nao_aparecem_inteiros() -> None:
    finding = make(asset="ativo", evidence=f"chave {SECRET}")
    result = analyzed(
        scan(
            [finding],
            runs=[CheckRun("x", "Nome", "alvo", "erro", 0.1, f"erro {SECRET}")],
            errors=[f"falha {SECRET}"],
        )
    )
    assert not has(render_pdf(result), SECRET)


# -- textos longos e volume -----------------------------------------------------------------------


LONG_URL = "https://exemplo.com.br/" + "caminho-muito-longo/" * 300
WIDE = "W" * 8000
SPACED = "palavra " * 4000


@pytest.mark.parametrize(
    "text",
    [LONG_URL, WIDE, SPACED, "<" * 3000, "&" * 3000, "\n" * 3000, "a\n" * 3000],
    ids=["url", "largo", "palavras", "menor-que", "e-comercial", "quebras", "linhas"],
)
def test_textos_longos_nunca_derrubam_o_pdf(text: str) -> None:
    finding = make(
        title=text,
        asset=text,
        evidence=text,
        details={"d": text},
        cves=["CVE-2021-44228"],
        kev=True,
        status_note=text,
    )
    result = analyzed(
        scan(
            [finding],
            target=text,
            passed=[PassedControl("c", text, text)],
            decisions=[Decision("2026-11-01T10:00:00+00:00", text)],
            runs=[CheckRun("x", text, text, "erro", 0.1, text)],
            errors=[text],
        )
    )
    valid(render_pdf(result))


def _entry(**fields: Any) -> KBEntry:
    base: dict[str, Any] = {
        "id": "teste.pdf.longo",
        "title": "Entrada",
        "category": Category.WEB,
        "severity": Severity.HIGH,
        "summary": "Resumo",
        "explanation": "Explicação",
        "risk": "Risco",
        "steps": ("Passo",),
        "verify": "Verifique",
        "fix_group": "configuracao",
    }
    base.update(fields)
    return KBEntry(**base)


def _pdf_with(entry: KBEntry, **extra: Any) -> bytes:
    previous = dict(kb._KB)
    kb._KB[entry.id] = entry
    try:
        return valid(render_pdf(analyzed(scan([make(entry.id, title="T", **extra)]))))
    finally:
        kb._KB.clear()
        kb._KB.update(previous)


@pytest.mark.parametrize(
    "code",
    [
        "\n".join(f"linha {n}" for n in range(2000)),
        "x" * 20_000,
        "\n".join("y" * 300 for _ in range(300)),
        "<b>&amp;</b>\t\x00" * 500,
    ],
    ids=["muitas-linhas", "uma-linha", "linhas-longas", "marcacao"],
)
def test_codigo_longo_cabe_na_pagina_com_aviso_de_corte(code: str) -> None:
    pdf = _pdf_with(_entry(examples=(Fix("generico", "Exemplo", code, "text"),)), tech=["generico"])
    assert has(pdf, "no relatório HTML") or "\n" not in code


def test_nota_e_bandas_cabem_com_textos_longos_na_analise() -> None:
    result = analyzed(scan([make()]))
    result.analysis["narrative"]["headline"] = "W" * 5000
    result.analysis["posture"]["cap_reason"] = "W" * 5000
    result.analysis["what_if"] = {"actions": 1, "score": 100, "grade": "W" * 5000}
    valid(render_pdf(result))


def test_textos_da_base_muito_longos() -> None:
    long = "Texto da base com muitas palavras e ação. " * 400
    entry = _entry(
        title=long,
        summary=long,
        explanation=long,
        risk=long,
        steps=(long, long, long),
        verify=long,
    )
    assert pdf_pages(_pdf_with(entry)) >= 2


def test_centenas_de_achados_tem_tamanho_de_resumo_executivo() -> None:
    result = many_findings(800)
    pdf = valid(render_pdf(result))
    assert pdf_pages(pdf) < 40
    assert has(pdf, "A lista completa está no relatório HTML e no CSV.")
    assert has(pdf, "Os 30 achados abertos de maior prioridade")


def test_lista_de_pontos_fortes_e_comparacao_longas_tem_limite() -> None:
    passed = [
        PassedControl(f"c{n}", f"Controle aprovado número {n}", f"ativo{n}") for n in range(90)
    ]
    previous = analyzed(
        scan([make(asset=f"https://antigo{n}.exemplo/") for n in range(30)], id="anterior")
    )
    result = analyzed(
        scan([make(asset=f"https://novo{n}.exemplo/") for n in range(30)], passed=passed), previous
    )
    pdf = valid(render_pdf(result))
    assert has(pdf, "E mais 50 controles aprovados no relatório HTML.")
    assert has(pdf, "E mais 20 problemas no relatório HTML.")


def test_muitas_execucoes_com_problema_tem_limite() -> None:
    runs = [CheckRun(f"c{n}", f"Verificação {n}", "alvo", "erro", 0.1, "falhou") for n in range(40)]
    errors = [f"Erro número {n}" for n in range(40)]
    pdf = valid(render_pdf(analyzed(scan([make()], runs=runs, errors=errors))))
    assert has(pdf, "E mais 25 verificações no relatório HTML.")
    assert has(pdf, "E mais 25 erros no relatório HTML.")


# -- estados --------------------------------------------------------------------------------------


def test_nao_avaliado_mostra_estado_sem_nota() -> None:
    pdf = valid(render_pdf(not_evaluated()))
    assert has(pdf, "Não foi possível avaliar este alvo")
    assert has(pdf, "Não avaliado")
    assert has(pdf, "—")
    assert not has(pdf, "/100")
    assert not has(pdf, "Plano de correção")
    assert not has(pdf, "Conformidade")
    assert has(pdf, "Conexão recusada")


def test_sem_problemas_mostra_nota_maxima() -> None:
    pdf = valid(render_pdf(clean_result()))
    assert has(pdf, "A+")
    assert has(pdf, "100/100")
    assert has(pdf, "Só aceita TLS 1.2+")
    assert not has(pdf, "Plano de correção")
    assert not has(pdf, "Principais achados")
    assert has(pdf, "Conformidade")


def test_resultado_vazio_sem_analise() -> None:
    result: ScanResult = scan()
    pdf = valid(render_pdf(result))
    assert result.analysis["evaluated"] is False
    assert has(pdf, "Não avaliado")


@pytest.mark.parametrize(
    ("status", "text"),
    [
        ("cancelada", "A auditoria foi cancelada antes do fim"),
        ("erro", "A auditoria terminou com erro"),
    ],
)
def test_resultado_parcial_avisa_na_capa(status: str, text: str) -> None:
    pdf = render_pdf(analyzed(scan([make()], status=status)))
    assert has(pdf, text)


def test_analise_incompleta_nao_quebra() -> None:
    result = scan([make()])
    result.analysis = {"evaluated": True, "posture": {"score": 80, "grade": "B"}}
    pdf = valid(render_pdf(result))
    assert has(pdf, "80/100")


def test_analise_com_tipos_inesperados_nao_quebra() -> None:
    result = scan([make()])
    result.analysis = {
        "evaluated": True,
        "posture": "x",
        "plan": [1, {"problems": "x", "fixes": [None]}],
        "kev": "x",
        "scenarios": [None],
        "compliance": {"owasp": [None], "cis": [1], "cwe": "x", "lgpd": []},
        "inventory": {"sections": [None, {"rows": [None]}]},
        "diff": {"new": [None]},
        "narrative": {"paragraphs": "x", "top_risks": [None]},
    }
    valid(render_pdf(result))


def test_achados_so_triados_nao_aparecem_como_principais() -> None:
    finding = make(status=TriageStatus.ACCEPTED, status_note="Aceito pela diretoria")
    pdf = render_pdf(analyzed(scan([finding])))
    assert not has(pdf, "Principais achados")


# -- blocos ---------------------------------------------------------------------------------------


def test_quebra_de_linha_de_codigo_marca_a_continuacao() -> None:
    assert wrap_line("abc", 10) == ["abc"]
    pieces = wrap_line("a" * 25, 10)
    assert pieces[0] == "a" * 10
    assert all(piece.startswith("» ") for piece in pieces[1:])
    assert all(len(piece) <= 10 for piece in pieces)
    assert "".join(p.removeprefix("» ") for p in pieces) == "a" * 25


def test_codigo_tem_limite_de_linhas_e_aviso() -> None:
    rows = code_rows("\n".join(str(n) for n in range(100)), 40)
    assert rows[0] == "0"
    assert rows[24] == "24"
    assert rows[-1] == "... mais 75 linhas no relatório HTML"
    assert len(rows) == 26
    rows = code_rows("\n".join("x" * 200 for _ in range(30)), 40)
    assert len(rows) <= MAX_CODE_ROWS + 1
    assert "no relatório HTML" in rows[-1]
    assert code_rows("a\nb", 40) == ["a", "b"]


def test_rodape_corta_o_que_nao_cabe() -> None:
    assert _fit("curto", 400, "Helvetica", 7.5) == "curto"
    cut = _fit("W" * 500, 100, "Helvetica", 7.5)
    assert cut.endswith("...")
    assert len(cut) < 30
    assert _fit("W" * 500, 1, "Helvetica", 7.5) == "..."


def test_paragrafo_de_kit_escapa_o_texto_dinamico() -> None:
    paragraph = Kit(400).text("<b>x</b>")
    assert isinstance(paragraph, Paragraph)
    # um <b> de verdade viraria um fragmento em negrito com o texto "x"
    assert not any(getattr(frag, "bold", 0) for frag in paragraph.frags)
    assert "".join(frag.text for frag in paragraph.frags) == "<b>x</b>"


def test_estilos_usam_so_fontes_padrao() -> None:
    fonts = {style.fontName for style in styles().values()}
    assert fonts <= {"Helvetica", "Helvetica-Bold", "Courier"}


def test_imagem_e_svg_do_alvo_nao_entram_no_arquivo() -> None:
    pdf = render_pdf(analyzed(scan([make(title=IMG, evidence=SCRIPT)])))
    assert b"/Subtype /Image" not in pdf
