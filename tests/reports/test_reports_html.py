"""Relatório HTML: conteúdo, seções, escape de tudo que vem do alvo, sem JavaScript nem rede."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from importlib import resources
from pathlib import PurePosixPath
from typing import Any

import pytest
from fakes_reports import (
    IMG,
    JS_URL,
    PAYLOADS,
    SCRIPT,
    SECRET,
    SITE,
    analyzed,
    clean_result,
    make,
    many_findings,
    not_evaluated,
    parse_html,
    previous_result,
    sample_result,
    sample_with_diff,
    scan,
)

from eigan.core import kb
from eigan.core.kb import Fix, KBEntry
from eigan.core.models import (
    Category,
    CheckRun,
    Decision,
    Fact,
    Finding,
    PassedControl,
    ScanResult,
    Severity,
    TriageStatus,
)
from eigan.intel.analysis import analyze
from eigan.reports import html as html_module
from eigan.reports import render_html
from eigan.reports.common import cve_url, cwe_url, is_web_url, visible, web_link

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
    "form-action 'none'"
)
#: elementos que nunca podem existir no relatório
FORBIDDEN_TAGS = {
    "script",
    "iframe",
    "object",
    "embed",
    "img",
    "link",
    "base",
    "form",
    "input",
    "button",
    "video",
    "audio",
    "source",
    "applet",
    "frame",
    "frameset",
    "math",
}


def assert_safe(document: str) -> Any:
    """Nenhum elemento ativo, atributo de evento ou recurso externo (como o navegador lê)."""
    parsed = parse_html(document)
    assert not FORBIDDEN_TAGS & set(parsed.tags), FORBIDDEN_TAGS & set(parsed.tags)
    assert parsed.tags.count("svg") == 1, "só o emblema pode ser SVG"
    for tag, name, value in parsed.attrs:
        assert not name.startswith("on"), (tag, name, value)
        assert name not in ("src", "srcset", "action", "formaction", "background", "style")
        if name in ("href", "xlink:href"):
            assert tag == "a", (tag, name, value)
            assert value.startswith("#") or re.match(r"https?://[^\s]+$", value), value
    assert "url(" not in parsed.style
    assert "@import" not in parsed.style
    assert "@font-face" not in parsed.style
    assert "expression(" not in parsed.style
    return parsed


# -- estrutura geral -------------------------------------------------------------------------


def test_documento_autocontido_sem_javascript_nem_recursos_externos() -> None:
    document = render_html(sample_with_diff())
    assert document.startswith("<!doctype html>")
    assert '<html lang="pt-BR">' in document
    parsed = assert_safe(document)
    csp = [
        value
        for tag, name, value in parsed.attrs
        if tag == "meta" and name == "content" and "default-src" in value
    ]
    assert csp == [CSP]
    assert '<meta name="referrer" content="no-referrer">' in document
    assert "<script" not in document.lower()
    assert "javascript:" not in document.lower()


def test_secoes_na_ordem_do_relatorio() -> None:
    result = sample_with_diff()
    result.analysis["scenarios"] = [
        {
            "id": "c1",
            "title": "Roubo de sessão",
            "severity": "high",
            "narrative": "Sem HTTPS e sem HSTS, a sessão é capturada.",
            "breaker": "Ative o HSTS.",
            "host": "exemplo.com.br",
            "titles": ["HSTS ausente"],
            "assets": [SITE],
            "findings": [],
        }
    ]
    document = render_html(result)
    order = [
        'class="cover"',
        'id="veredito"',
        'id="resumo"',
        'id="cenarios"',
        'id="plano"',
        'id="achados"',
        'id="kev"',
        'id="pontos-fortes"',
        'id="conformidade"',
        'id="comparacao"',
        'id="inventario"',
        'id="linha-do-tempo"',
        'class="footer"',
    ]
    positions = [document.index(marker) for marker in order]
    assert positions == sorted(positions)


def test_capa_com_os_dados_da_auditoria() -> None:
    plain = parse_html(render_html(sample_result())).plain()
    for text in (
        "Relatório de auditoria de segurança",
        "https://exemplo.com.br",
        "Site ou aplicação web",
        "Padrão",
        "0.0.0",
        "4 min 12 s",
    ):
        assert text in plain, text


def test_veredito_com_nota_pontuacao_e_contagens() -> None:
    result = sample_result()
    document = render_html(result)
    plain = parse_html(document).plain()
    posture = result.analysis["posture"]
    assert f">{posture['grade']}</span>" in document
    assert f"{posture['score']}/100" in plain
    assert posture["label"] in plain
    assert posture["cap_reason"] in plain
    assert result.analysis["narrative"]["headline"] in plain
    for label in ("Críticas", "Altas", "Médias", "Baixas", "Informativos"):
        assert label in plain
    for band in ("P1", "P2", "P3", "P4"):
        assert f">{band}</span>" in document


def test_kev_na_tabela_com_link_para_o_achado() -> None:
    result = sample_result()
    document = render_html(result)
    parsed = parse_html(document)
    plain = parsed.plain()
    assert "Exploração conhecida (CISA KEV)" in plain
    assert "CVE-2021-44228" in plain
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in parsed.hrefs()
    fingerprint = next(f.fingerprint for f in result.findings if f.kev)
    assert f"#f-{fingerprint}" in parsed.hrefs()


def test_achados_agrupados_por_tipo_com_explicacao_uma_vez() -> None:
    result = sample_result()
    document = render_html(result)
    entry = kb.require("web.hsts.fraco")
    assert document.count('id="tipo-web.hsts.fraco"') == 1
    assert document.count(_esc(entry.explanation)) == 1
    block = document.split('id="tipo-web.hsts.fraco"')[1].split("</article>")[0]
    assert block.count('class="occ"') == 3
    assert "Subdomínio legado, desligamento previsto para dezembro." in block
    assert "Risco aceito" in block or "Aceito" in block
    assert "Falso positivo" in block


def test_detalhes_viram_pares_chave_valor_legiveis() -> None:
    document = render_html(sample_result())
    assert "<dt>max_age</dt><dd>86400</dd>" in document
    assert "<dt>inclui_subdominios</dt><dd>não</dd>" in document
    assert "<dt>nada</dt><dd>—</dd>" in document
    assert "<dt>corrigida</dt><dd>2.17.1</dd>" in document


def test_plano_mostra_passos_verificacao_e_exemplo_de_correcao() -> None:
    result = analyzed(scan([make("web.hsts.ausente", tech=["nginx"])]))
    document = render_html(result)
    entry = kb.require("web.hsts.ausente")
    plan = document.split('id="plano"')[1].split('id="achados"')[0]
    assert '<ol class="steps">' in plan
    for step in entry.steps:
        assert _esc(step) in plan
    assert _esc(entry.verify) in plan
    assert "Exemplo de correção" in plan
    assert '<pre class="code"><code>' in plan
    assert 'id="acao-1"' in plan


def test_comparacao_com_a_auditoria_anterior() -> None:
    document = render_html(sample_with_diff())
    parsed = parse_html(document)
    plain = parsed.plain()
    assert "Comparação com a auditoria anterior" in plain
    for title in ("Corrigidos", "Novos", "Ainda abertos", "Não verificados"):
        assert title in plain
    assert 'id="comparacao"' in document


def test_sem_comparacao_quando_nao_ha_auditoria_anterior() -> None:
    document = render_html(sample_result())
    assert 'id="comparacao"' not in document
    assert 'href="#comparacao"' not in document


def test_conformidade_tem_as_dez_categorias_owasp() -> None:
    document = render_html(sample_result())
    section = document.split('id="conformidade"')[1].split("</section>")[0]
    owasp = section.split("<h3>CIS Controls v8</h3>")[0]
    assert owasp.count("<tr>") == 11  # cabeçalho + 10 categorias
    assert "Sem achados nas verificações do EIGAN" in owasp
    assert "Nenhum problema encontrado" not in owasp
    assert "LGPD" in section


def test_linha_do_tempo_com_decisoes_problemas_e_erros() -> None:
    document = render_html(sample_result())
    section = document.split('id="linha-do-tempo"')[1].split("</section>")[0]
    assert "<details" in section
    assert "Iniciar pelas verificações de HTTPS." in section
    assert "Tempo esgotado" in section
    assert "Sem resposta em 30 s" in section
    assert "Conexão recusada" in section
    assert "tempo esgotado após 30 s" in section
    assert "web.transport" not in section  # execuções que terminaram bem não entram


def test_inventario_em_tabelas() -> None:
    document = render_html(sample_result())
    section = document.split('id="inventario"')[1].split("</section>")[0]
    assert "<table" in section
    assert "nginx" in section


def test_pontos_fortes_agrupam_os_ativos_do_mesmo_controle() -> None:
    document = render_html(sample_result())
    section = document.split('id="pontos-fortes"')[1].split("</section>")[0]
    assert section.count("Só aceita TLS 1.2 e TLS 1.3") == 1
    assert "exemplo.com.br:443" in section
    assert "api.exemplo.com.br:443" in section


def test_rodape_com_autoria_e_aviso_de_autorizacao() -> None:
    plain = parse_html(render_html(sample_result())).plain()
    assert "Gerado pelo EIGAN 0.0.0" in plain
    assert "análise local por regras, sem IA e sem envio de dados" in plain
    assert "Use somente em sistemas que você tem autorização para avaliar." in plain
    assert "Identificador da auditoria" in plain


def test_todos_os_links_internos_tem_destino_e_ids_sao_unicos() -> None:
    parsed = parse_html(render_html(sample_with_diff()))
    ids = parsed.ids()
    assert len(ids) == len(set(ids)), "ids repetidos"
    for href in parsed.hrefs():
        if href.startswith("#"):
            assert href[1:] in ids, href


def test_links_externos_nao_vazam_a_origem() -> None:
    document = render_html(sample_result())
    for tag in re.findall(r'<a href="https?://[^>]+>', document):
        assert 'rel="noopener noreferrer"' in tag


# -- estados --------------------------------------------------------------------------------


def test_nao_avaliado_nao_mostra_nota() -> None:
    document = render_html(not_evaluated())
    parsed = assert_safe(document)
    plain = parsed.plain()
    assert "Não foi possível avaliar este alvo" in plain
    assert "Não avaliado" in plain
    assert "/100" not in plain
    assert "A+" not in plain
    assert 'id="conformidade"' not in document
    assert 'id="plano"' not in document
    assert "Conexão recusada" in plain  # a linha do tempo mostra o que foi tentado


def test_sem_problemas_mostra_nota_maxima_e_sem_plano() -> None:
    document = render_html(clean_result())
    parsed = assert_safe(document)
    assert ">A+</span>" in document
    assert "100/100" in parsed.plain()
    assert 'id="plano"' not in document
    assert 'id="achados"' not in document
    assert 'id="kev"' not in document
    assert "Só aceita TLS 1.2+" in parsed.plain()


@pytest.mark.parametrize(
    ("status", "text"),
    [
        ("cancelada", "A auditoria foi cancelada antes do fim"),
        ("erro", "A auditoria terminou com erro"),
        ("em_andamento", "A auditoria ainda estava em andamento"),
    ],
)
def test_resultado_parcial_avisa_na_capa(status: str, text: str) -> None:
    result = analyzed(scan([make()], status=status))
    cover = render_html(result).split('id="veredito"')[0]
    assert text in cover


def test_concluida_nao_tem_aviso_de_resultado_parcial() -> None:
    cover = render_html(sample_result()).split('id="veredito"')[0]
    assert 'class="notice"' not in cover


def test_analise_antiga_sem_chaves_nao_quebra() -> None:
    result = scan([make()])
    result.analysis = {"evaluated": True, "posture": {"score": 80, "grade": "B"}}
    document = render_html(result)
    assert_safe(document)
    assert ">B</span>" in document


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
    assert_safe(render_html(result))


def test_analise_com_tipos_errados_em_severidade_e_faixa_nao_quebra() -> None:
    result = scan([make()])
    result.analysis = {
        "evaluated": True,
        "compliance": {"owasp": [{"id": "A01:2021", "count": 1, "worst": ["alta"]}]},
        "plan": [{"band": ["P1"], "worst": {"x": 1}, "group": "g", "effort": "baixo"}],
        "narrative": {"top_risks": [{"severity": 3, "band": {}, "fingerprint": "x"}]},
    }
    assert_safe(render_html(result))


# -- texto hostil ---------------------------------------------------------------------------


def _esc(text: str) -> str:
    """O texto como o autoescape do Jinja escreve no HTML."""
    return (
        text.replace("&", "&amp;")
        .replace(">", "&gt;")
        .replace("<", "&lt;")
        .replace("'", "&#39;")
        .replace('"', "&#34;")
    )


def _hostile_title(p: str) -> ScanResult:
    return scan([make("web.hsts.ausente", title=p)])


def _hostile_asset(p: str) -> ScanResult:
    return scan([make(asset=p)])


def _hostile_evidence(p: str) -> ScanResult:
    return scan([make(evidence=p)])


def _hostile_detail_value(p: str) -> ScanResult:
    return scan([make(details={"campo": p})])


def _hostile_detail_key(p: str) -> ScanResult:
    return scan([make(details={p: "valor"})])


def _hostile_detail_list(p: str) -> ScanResult:
    return scan([make(details={"lista": [p, {"sub": p}]})])


def _hostile_note(p: str) -> ScanResult:
    return scan([make(status=TriageStatus.ACCEPTED, status_note=p)])


def _hostile_tech(p: str) -> ScanResult:
    return scan([make(tech=[p])])


def _hostile_cve(p: str) -> ScanResult:
    return scan([make(cves=[p])])


def _hostile_unknown_id(p: str) -> ScanResult:
    return scan([make(check_id=p, title="Título", severity=Severity.HIGH)])


def _hostile_target(p: str) -> ScanResult:
    return scan([make()], target=p)


def _hostile_id(p: str) -> ScanResult:
    return scan([make()], id=p)


def _hostile_profile(p: str) -> ScanResult:
    return scan([make()], profile=p)


def _hostile_status(p: str) -> ScanResult:
    return scan([make()], status=p)


def _hostile_version(p: str) -> ScanResult:
    return scan([make()], app_version=p)


def _hostile_error(p: str) -> ScanResult:
    return scan([make()], errors=[p])


def _hostile_passed_text(p: str) -> ScanResult:
    return scan(passed=[PassedControl("c", p, "ativo")])


def _hostile_passed_asset(p: str) -> ScanResult:
    return scan(passed=[PassedControl("c", "Texto", p)])


def _hostile_decision(p: str) -> ScanResult:
    return scan([make()], decisions=[Decision("2026-11-01T10:00:00+00:00", p)])


def _hostile_run_name(p: str) -> ScanResult:
    return scan([make()], runs=[CheckRun("x", p, "alvo", "erro", 0.1, "m")])


def _hostile_run_message(p: str) -> ScanResult:
    return scan([make()], runs=[CheckRun("x", "Nome", "alvo", "erro", 0.1, p)])


def _hostile_run_key(p: str) -> ScanResult:
    return scan([make()], runs=[CheckRun("x", "Nome", p, "tempo_esgotado", 0.1, "m")])


def _hostile_run_status(p: str) -> ScanResult:
    return scan([make()], runs=[CheckRun("x", "Nome", "alvo", p, 0.1, "m")])


def _hostile_fact_value(p: str) -> ScanResult:
    return scan(
        [make()],
        facts=[Fact("http.service", SITE, {"url": p, "host": p, "port": 443}, source="web")],
    )


def _hostile_fact_key(p: str) -> ScanResult:
    return scan(
        [make()],
        facts=[Fact("tech", p, {"name": p, "version": p, "evidence": p}, source="web")],
    )


HOSTILE_FIELDS: dict[str, Callable[[str], ScanResult]] = {
    name.removeprefix("_hostile_"): value
    for name, value in list(globals().items())
    if name.startswith("_hostile_")
}


@pytest.mark.parametrize("field", sorted(HOSTILE_FIELDS))
@pytest.mark.parametrize("payload", PAYLOADS)
def test_texto_hostil_nunca_vira_marcacao(field: str, payload: str) -> None:
    document = render_html(analyzed(HOSTILE_FIELDS[field](payload)))
    assert_safe(document)
    lowered = document.lower()
    assert "<script" not in lowered
    assert "<img" not in lowered
    assert "<iframe" not in lowered
    assert "<svg/onload" not in lowered
    assert "<a href=javascript" not in lowered
    assert "</style><script" not in lowered


@pytest.mark.parametrize(
    "field",
    [
        "title",
        "asset",
        "evidence",
        "detail_value",
        "detail_key",
        "note",
        "target",
        "error",
        "passed_text",
        "passed_asset",
        "decision",
        "run_name",
        "run_message",
        "fact_value",
    ],
)
def test_texto_hostil_continua_visivel_para_o_leitor(field: str) -> None:
    payload = IMG
    plain = parse_html(render_html(analyzed(HOSTILE_FIELDS[field](payload)))).plain()
    assert payload in plain


def test_evidencia_hostil_aparece_literal_num_pre() -> None:
    document = render_html(analyzed(scan([make(evidence=SCRIPT)])))
    assert f'<pre class="evidence">{_esc(SCRIPT)}</pre>' in document


def test_marcas_de_template_no_alvo_nao_sao_interpretadas() -> None:
    plain = parse_html(render_html(analyzed(scan([make(evidence="{{ 7*7 }}")])))).plain()
    assert "{{ 7*7 }}" in plain
    assert "49" not in plain.split("Evidência")[1].split("\n")[0]


def _with_entry(entry: KBEntry, finding: Finding) -> str:
    previous = dict(kb._KB)
    kb._KB[entry.id] = entry
    try:
        return render_html(analyzed(scan([finding])))
    finally:
        kb._KB.clear()
        kb._KB.update(previous)


def _hostile_entry(entry_id: str = "teste.relatorio.hostil", **fields: Any) -> KBEntry:
    base: dict[str, Any] = {
        "id": entry_id,
        "title": "Entrada de teste",
        "category": Category.WEB,
        "severity": Severity.HIGH,
        "summary": "Resumo",
        "explanation": "Explicação",
        "risk": "Risco",
        "steps": ("Passo 1",),
        "verify": "Verifique",
        "fix_group": "configuracao",
        "references": ("https://exemplo.org/referencia",),
    }
    base.update(fields)
    return KBEntry(**base)


@pytest.mark.parametrize(
    "reference",
    [
        JS_URL,
        "JaVaScRiPt:alert(1)",
        " javascript:alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "//mal.example/x",
        "/caminho/relativo",
        "http://",
        "https:///sem-host",
        "http://exemplo.org/com espaço",
    ],
)
def test_referencia_que_nao_e_http_vira_texto(reference: str) -> None:
    entry = _hostile_entry(references=(reference,))
    document = _with_entry(entry, make(entry.id, title="Teste"))
    parsed = assert_safe(document)
    bad_start = ("javascript", "data", "vbscript", "file", "//")
    assert not [href for href in parsed.hrefs() if href.lower().startswith(bad_start)]
    assert reference not in parsed.hrefs()
    assert "Referências (1)" in parsed.plain()


def test_referencia_http_vira_link_escapado() -> None:
    url = 'https://exemplo.org/a?b=1&c="><script>alert(1)</script>'
    entry = _hostile_entry(references=(url, "http://exemplo.org/ok"))
    document = _with_entry(entry, make(entry.id, title="Teste"))
    parsed = assert_safe(document)
    assert url in parsed.hrefs()
    assert "http://exemplo.org/ok" in parsed.hrefs()
    assert "<script" not in document.lower()


def test_exemplo_de_correcao_e_texto_da_base_tambem_sao_escapados() -> None:
    entry = _hostile_entry(
        title=SCRIPT,
        summary=IMG,
        explanation=SCRIPT,
        risk=IMG,
        steps=(SCRIPT, IMG),
        verify=IMG,
        examples=(Fix("generico", SCRIPT, f"<html>{SCRIPT}</html>", "html"),),
        cwe='CWE-79"><script>',
    )
    document = _with_entry(entry, make(entry.id, title="Teste", tech=["generico"]))
    assert_safe(document)
    assert "<script" not in document.lower()


def test_ativo_com_url_javascript_nao_vira_link() -> None:
    document = render_html(analyzed(scan([make(asset=JS_URL)])))
    parsed = assert_safe(document)
    assert JS_URL in parsed.plain()
    assert JS_URL not in parsed.hrefs()


def test_cve_com_formato_invalido_nao_vira_link() -> None:
    bad = 'CVE-2021-1"><script>alert(1)</script>'
    document = render_html(analyzed(scan([make(cves=[bad, "CVE-2021-44228"])])))
    parsed = assert_safe(document)
    assert bad in parsed.plain()
    links = [h for h in parsed.hrefs() if "nvd.nist.gov" in h]
    assert links == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://exemplo.com/a?b=c#d", True),
        ("http://127.0.0.1:8080/", True),
        ("HTTPS://EXEMPLO.COM/", True),
        ("http://[::1]:8080/", True),
        ("javascript:alert(1)", False),
        ("https://exemplo.com/a b", False),
        ("https://exemplo.com/\x01", False),
        ("http://[inválido", False),
        ("https://exemplo.com/\u202eexe.pdf", False),
        ("ftp://exemplo.com/", False),
        ("", False),
    ],
)
def test_so_http_com_host_vira_link(url: str, expected: bool) -> None:
    assert is_web_url(url) is expected
    assert web_link(url) == {"url": url if expected else "", "text": url}


def test_urls_de_cve_e_cwe_so_para_identificadores_validos() -> None:
    assert cve_url("cve-2021-44228") == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert cve_url("CVE-2021-1") == ""
    assert cve_url("CVE-2021-44228/../../x") == ""
    assert cwe_url("CWE-79") == "https://cwe.mitre.org/data/definitions/79.html"
    assert cwe_url('CWE-79"') == ""
    assert cwe_url("") == ""


# -- caracteres invisíveis e segredos ----------------------------------------------------------


@pytest.mark.parametrize(
    ("char", "shown"),
    [
        ("\u202e", "<U+202E>"),  # inverte a direção do texto (Trojan Source)
        ("\u2066", "<U+2066>"),
        ("\u200b", "<U+200B>"),
        ("\x00", "<U+0000>"),
        ("\x1b", "<U+001B>"),
        ("\x7f", "<U+007F>"),
        ("\ufeff", "<U+FEFF>"),
        ("\udce9", "<U+DCE9>"),
    ],
)
def test_caracteres_invisiveis_ficam_a_mostra(char: str, shown: str) -> None:
    assert visible(f"a{char}b") == f"a{shown}b"
    document = render_html(analyzed(scan([make(title=f"a{char}b", evidence=f"e{char}f")])))
    assert char not in document
    assert _esc(f"a{shown}b") in document
    assert _esc(f"e{shown}f") in document


def test_quebras_de_linha_e_tabulacao_sao_preservadas_na_evidencia() -> None:
    assert visible("a\tb\nc\r\nd") == "a\tb\nc\r\nd"
    document = render_html(analyzed(scan([make(evidence="linha 1\nlinha 2\tfim")])))
    assert "linha 1\nlinha 2\tfim" in document


def test_segredos_nao_aparecem_inteiros() -> None:
    finding = make(
        evidence=f"chave {SECRET}",
        details={"valor": f"aws={SECRET}", "lista": [SECRET], "senha": "password=hunter2hunter2"},
    )
    result = scan(
        [finding],
        errors=[f"falha usando {SECRET}"],
        decisions=[Decision("2026-11-01T10:00:00+00:00", f"usando {SECRET}")],
        runs=[CheckRun("x", "Nome", "alvo", "erro", 0.1, f"erro com {SECRET}")],
        facts=[Fact("tech", "t", {"name": "n", "evidence": f"banner {SECRET}"}, source="web")],
    )
    document = render_html(analyzed(result))
    assert SECRET not in document
    assert "hunter2hunter2" not in document
    assert "AKIA…(20 caracteres)" in document


# -- volume e texto longo -----------------------------------------------------------------------


def test_centenas_de_achados_tem_limite_por_bloco_e_links_validos() -> None:
    result = many_findings(800)
    document = render_html(result)
    parsed = assert_safe(document)
    assert document.count('class="occ"') <= 600
    assert "no CSV e no JSON" in parsed.plain()
    ids = set(parsed.ids())
    for href in parsed.hrefs():
        if href.startswith("#"):
            assert href[1:] in ids, href


def test_comparacao_com_ocorrencias_alem_do_limite_nao_gera_link_quebrado() -> None:
    previous = many_findings(10)
    previous.id = "anterior"
    result = many_findings(800)
    analyze(result, previous)
    parsed = parse_html(render_html(result))
    ids = set(parsed.ids())
    for href in parsed.hrefs():
        if href.startswith("#"):
            assert href[1:] in ids, href


def test_textos_longos_nao_quebram_e_a_evidencia_tem_limite() -> None:
    url = "https://exemplo.com.br/" + "a" * 5000
    finding = make(asset=url, title="T" * 5000, evidence="E" * 50_000, details={"d": "D" * 5000})
    document = render_html(analyzed(scan([finding], target=url)))
    assert_safe(document)
    assert "E" * 3900 in document
    assert "E" * 4100 not in document
    assert "cortada; o JSON tem o texto completo" in document
    assert "D" * 1100 not in document


def test_estilo_sem_gradientes_caixa_alta_nem_sombras() -> None:
    css = parse_html(render_html(sample_result())).style.lower()
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)  # só as regras, sem os comentários
    assert "gradient" not in css
    assert "uppercase" not in css
    assert "box-shadow" not in css
    assert "overflow-wrap: anywhere" in css
    assert "tabular-nums" in css
    assert "@media print" in css
    assert "@page" in css
    assert "#1f4fd1" in css


@pytest.mark.parametrize(
    "token",
    [
        "--crit-fg: #b42318",
        "--crit-bg: #fef3f2",
        "--high-fg: #c4320a",
        "--high-bg: #fff4ed",
        "--med-fg: #b54708",
        "--med-bg: #fffaeb",
        "--low-fg: #175cd3",
        "--low-bg: #eff8ff",
        "--info-fg: #475467",
        "--info-bg: #f2f4f7",
        "--grade-a: #067647",
        "--grade-b: #3b7c0f",
        "--grade-c: #b54708",
        "--grade-d: #c4320a",
        "--grade-f: #b42318",
        "--brand: #1f4fd1",
        "--brand-ink: #1a3fa8",
    ],
)
def test_tokens_de_cor_iguais_aos_do_painel(token: str) -> None:
    assert token in parse_html(render_html(clean_result())).style


def test_textos_fixos_do_modelo_sem_setas_nem_caixa_alta() -> None:
    source = resources.files("eigan.reports").joinpath("templates/report.html.j2")
    fixed = re.sub(r"\{[{%#].*?[}%#]\}", " ", source.read_text(encoding="utf-8"), flags=re.S)
    fixed = re.sub(r"<[^>]*>", " ", fixed)
    assert "→" not in fixed
    assert "\u2192" not in parse_html(render_html(sample_with_diff())).plain()
    allowed = {"EIGAN", "OWASP", "LGPD", "CISA", "JSON"}
    assert not {w for w in re.findall(r"[^\W\d_]{4,}", fixed) if w.isupper()} - allowed


# -- empacotamento ------------------------------------------------------------------------------


def test_modelo_com_escape_automatico_ligado() -> None:
    assert html_module._environment().autoescape is True


def test_modelos_carregam_sem_pasta_no_disco(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instalação compactada: ``importlib.resources`` não devolve um ``Path``."""

    real = resources.files("eigan.reports").joinpath("templates")

    @dataclasses.dataclass
    class FakeNode:
        name: str

        def is_file(self) -> bool:
            return real.joinpath(self.name).is_file()

        def read_text(self, encoding: str = "utf-8") -> str:
            return real.joinpath(self.name).read_text(encoding=encoding)

    class FakeRoot:
        def joinpath(self, name: str) -> Any:
            return self if name == "templates" else FakeNode(str(PurePosixPath(name)))

    monkeypatch.setattr(html_module.resources, "files", lambda _pkg: FakeRoot())
    html_module._environment.cache_clear()
    try:
        document = render_html(sample_result())
    finally:
        html_module._environment.cache_clear()
    assert "Relatório de auditoria de segurança" in document
    assert "<svg" in document


def test_emblema_embutido_vem_do_pacote() -> None:
    document = render_html(sample_result())
    svg = document.split("<svg", 1)[1].split("</svg>", 1)[0]
    assert "#1f4fd1" in svg
    assert "script" not in svg.lower()
    assert 'aria-hidden="true"' in svg


def test_nao_altera_o_resultado_recebido() -> None:
    result = sample_result()
    before = result.to_dict()
    render_html(result)
    assert result.to_dict() == before


def test_previous_result_de_apoio_tem_analise() -> None:
    assert previous_result().analysis["evaluated"] is True


def test_categoria_sem_verificacao_aparece_como_nao_avaliada(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    only_a05 = [e for e in kb.all_entries() if e.owasp == "A05:2021"]
    monkeypatch.setattr(kb, "all_entries", lambda: only_a05)
    document = render_html(sample_result())
    owasp = document.split('id="conformidade"')[1].split("<h3>CIS Controls v8</h3>")[0]
    assert "Não avaliado: o EIGAN não tem verificação para esta categoria" in owasp


def test_chave_longa_dos_detalhes_nao_estoura_a_largura() -> None:
    css = resources.files("eigan.reports").joinpath("templates/report.css").read_text("utf-8")
    kv = re.search(r"\.kv \{[^}]*\}", css)
    assert kv is not None
    assert "grid-template-columns: minmax(0, max-content) minmax(0, 1fr)" in kv.group(0)
    assert "overflow-wrap: anywhere" in css.split(".kv dt {")[1].split("}")[0]
