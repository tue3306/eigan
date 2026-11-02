"""Segunda parte do PDF: principais achados, KEV, comparação, pontos fortes e conformidade.

Também escreve as verificações que não terminaram e o fecho do relatório. As listas
longas têm limite (o PDF é o resumo executivo); o relatório HTML e o CSV trazem tudo.
"""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, ListFlowable, Paragraph, Spacer, Table
from reportlab.platypus.flowables import HRFlowable

from ..core import fmt
from .pdf_blocks import Kit, band_markup, colored, severity_markup
from .pdf_styles import GRADE_COLOR, INK_HEX, KEV_HEX, LINE, MUTED_HEX, SEVERITY_FG, grid_style
from .pdf_text import markup

TOP_FINDINGS = 30
MAX_CELL = 300
MAX_ASSET = 200
MAX_STRENGTHS = 40
MAX_STRENGTH_ASSETS = 6
MAX_DIFF_ITEMS = 10
MAX_LGPD_TITLES = 12
MAX_PROBLEM_ROWS = 15


def _head(kit: Kit, *titles: str) -> list[Paragraph]:
    return [kit.para(title, "cell_head") for title in titles]


def _more(hidden: int, singular: str, plural: str) -> str:
    return f"E mais {fmt.plural(hidden, singular, plural)} no relatório HTML."


# -- principais achados e KEV -------------------------------------------------------------------


def top_findings(view: dict[str, Any], kit: Kit) -> None:
    """Tabela dos achados abertos mais urgentes (prioridade, severidade, título e ativo)."""
    findings = view["top_findings"]
    if not findings:
        return
    kit.section("Principais achados")
    shown = findings[:TOP_FINDINGS]
    if len(findings) > len(shown):
        kit.add(
            kit.text(
                f"Os {len(shown)} achados abertos de maior prioridade, de {len(findings)}. "
                "A lista completa está no relatório HTML e no CSV.",
                "small",
            )
        )
    rows: list[list[Any]] = [_head(kit, "Prioridade", "Severidade", "Título", "Ativo")]
    for item in shown:
        title = markup(item["title"], MAX_CELL)
        if item["kev"]:
            title += " " + colored("· CISA KEV", KEV_HEX, bold=True)
        rows.append(
            [
                kit.para(
                    f"{band_markup(item['band'])} {colored(markup(item['priority']), MUTED_HEX)}",
                    "cell",
                ),
                kit.para(severity_markup(item["severity"]), "cell"),
                kit.para(title, "cell"),
                kit.text(item["asset"], "cell", MAX_CELL),
            ]
        )
    rest = kit.width - 40 * mm
    table = Table(rows, colWidths=[20 * mm, 20 * mm, rest * 0.52, rest * 0.48], repeatRows=1)
    table.setStyle(grid_style())
    kit.add(table)


def kev(view: dict[str, Any], kit: Kit) -> None:
    """Vulnerabilidades do catálogo CISA KEV encontradas e onde aparecem."""
    items = view["kev"]
    if not items:
        return
    kit.section("Exploração conhecida (CISA KEV)")
    kit.add(
        kit.para(
            "Vulnerabilidades do catálogo da CISA de falhas já exploradas por atacantes reais. "
            "Trate como prioridade máxima.",
            "small",
        )
    )
    rows: list[list[Any]] = [_head(kit, "CVE", "Vulnerabilidade", "Onde")]
    for item in items:
        name = markup(item["name"] or "—", MAX_CELL)
        product = " · ".join(part for part in (item["vendor"], item["product"]) if part)
        if product:
            name += "<br/>" + colored(markup(product, MAX_ASSET), MUTED_HEX)
        notes = []
        if item["date_added"]:
            notes.append(colored(f"no catálogo desde {markup(item['date_added'])}", MUTED_HEX))
        if item["ransomware"]:
            notes.append(colored("usada em ransomware", SEVERITY_FG["high"], bold=True))
        if notes:
            name += "<br/>" + " · ".join(notes)
        where = markup(item["title"] or "—", MAX_CELL)
        if item["asset"]:
            where += "<br/>" + colored(markup(item["asset"], MAX_CELL), MUTED_HEX)
        rows.append(
            [kit.text(item["cve"], "cell", 40), kit.para(name, "cell"), kit.para(where, "cell")]
        )
    table = Table(rows, colWidths=[30 * mm, 70 * mm, kit.width - 100 * mm], repeatRows=1)
    table.setStyle(grid_style())
    kit.add(table)


# -- comparação ---------------------------------------------------------------------------------


def comparison(view: dict[str, Any], kit: Kit) -> None:
    """O que mudou desde a auditoria anterior do mesmo alvo."""
    data = view["diff"]
    if not data:
        return
    kit.section("Comparação com a auditoria anterior")
    intro = "Auditoria anterior do mesmo alvo"
    if data["previous_date"]:
        intro += f" em {data['previous_date']}"
    if data["previous_profile"]:
        intro += f" (perfil {data['previous_profile']})"
    kit.add(kit.text(intro + ".", "small"))
    grade = f" ({markup(data['grade_before'], 10)})" if data["grade_before"] else ""
    kit.add(
        kit.para(
            f"Nota: <b>{markup(data['score_before'])}</b>{grade} antes e "
            f"<b>{markup(data['score_after'])}</b> agora, {markup(data['delta_text'])}."
        ),
        Spacer(1, 3 * mm),
    )
    kit.add(
        kit.count_row(
            [
                (
                    len(data["fixed"]),
                    "Corrigidos",
                    GRADE_COLOR["a"] if data["fixed"] else MUTED_HEX,
                ),
                (len(data["new"]), "Novos", SEVERITY_FG["high"] if data["new"] else MUTED_HEX),
                (
                    len(data["persisting"]),
                    "Ainda abertos",
                    INK_HEX if data["persisting"] else MUTED_HEX,
                ),
                (
                    len(data["unverified"]),
                    "Não verificados",
                    INK_HEX if data["unverified"] else MUTED_HEX,
                ),
            ]
        )
    )
    for key, title in (("new", "Problemas novos"), ("fixed", "Problemas corrigidos")):
        _diff_list(data[key], title, kit)
    if data["unverified"]:
        kit.add(
            Spacer(1, 2 * mm),
            kit.para(
                "A checagem que encontrou os problemas não verificados não rodou desta vez "
                "(perfil mais leve ou erro). Não dá para afirmar que foram corrigidos.",
                "small",
            ),
        )


def _diff_list(items: list[dict[str, Any]], title: str, kit: Kit) -> None:
    if not items:
        return
    kit.add(kit.para(title, "h3_flush"))
    for item in items[:MAX_DIFF_ITEMS]:
        line = f"{severity_markup(item['severity'])} · {markup(item['title'], MAX_CELL)}"
        if item["asset"]:
            line += " " + colored(f"em {markup(item['asset'], MAX_ASSET)}", MUTED_HEX)
        kit.add(kit.para(line, "cell"))
    hidden = len(items) - MAX_DIFF_ITEMS
    if hidden > 0:
        kit.add(kit.text(_more(hidden, "problema", "problemas"), "small"))


# -- pontos fortes e conformidade -----------------------------------------------------------------


def strengths(view: dict[str, Any], kit: Kit) -> None:
    """Controles aprovados, com os ativos em que foram verificados."""
    items = view["strengths"]
    kit.section("Pontos fortes")
    if not items:
        kit.add(kit.para("Nenhum controle aprovado foi registrado nesta auditoria."))
        return
    paragraphs = []
    for item in items[:MAX_STRENGTHS]:
        text = markup(item["text"], MAX_CELL)
        assets = item["assets"][:MAX_STRENGTH_ASSETS]
        if assets:
            where = ", ".join(markup(asset, MAX_ASSET) for asset in assets)
            more = len(item["assets"]) - len(assets) + item["more"]
            if more > 0:
                where += f" e mais {more}"
            text += " " + colored(f"em {where}", MUTED_HEX)
        paragraphs.append(kit.para(text))
    # Sinal de visto da ZapfDingbats (uma das 14 fontes padrão do PDF): o reportlab converte
    # o caractere Unicode do visto para o código da fonte.
    kit.add(
        ListFlowable(
            paragraphs,
            bulletType="bullet",
            start="\N{CHECK MARK}",
            leftIndent=6 * mm,
            bulletDedent=6 * mm,
            bulletFontName="ZapfDingbats",
            bulletFontSize=8,
            bulletColor=colors.HexColor(GRADE_COLOR["a"]),
        )
    )
    hidden = len(items) - MAX_STRENGTHS
    if hidden > 0:
        kit.add(kit.text(_more(hidden, "controle aprovado", "controles aprovados"), "small"))


def compliance(view: dict[str, Any], kit: Kit) -> None:
    """OWASP Top 10 (2021) com as dez categorias e o quadro da LGPD."""
    data = view["compliance"]
    kit.section("Conformidade: OWASP Top 10 (2021)")
    rows: list[list[Any]] = [_head(kit, "Categoria", "Achados", "Pior severidade")]
    for item in data["owasp"]:
        label = kit.text(item["label"], "cell", MAX_CELL)
        if item["count"]:
            worst = kit.para(severity_markup(item["worst"]), "cell") if item["worst"] else ""
            rows.append([label, kit.text(item["count"], "cell"), worst])
        else:
            rows.append(
                [
                    label,
                    kit.para("0", "cell_muted"),
                    kit.para(
                        "Sem achados nas verificações do EIGAN"
                        if item.get("assessed", True)
                        else "Não avaliado pelo EIGAN",
                        "cell_muted",
                    ),
                ]
            )
    table = Table(rows, colWidths=[kit.width - 85 * mm, 20 * mm, 65 * mm], repeatRows=1)
    table.setStyle(grid_style())
    kit.add(table)
    kit.add(
        kit.text(
            "Sem achados vale só para o que o EIGAN verifica, sem intrusão: não garante "
            "que a categoria esteja livre de problemas.",
            "small",
        )
    )
    lgpd = data["lgpd"]
    if not lgpd["count"]:
        return
    titles = "; ".join(markup(title, MAX_ASSET) for title in lgpd["titles"][:MAX_LGPD_TITLES])
    hidden = len(lgpd["titles"]) - MAX_LGPD_TITLES
    if hidden > 0:
        titles += f"; e mais {hidden}"
    exposed = fmt.plural(lgpd["count"], "achado aberto pode", "achados abertos podem")
    kit.add(
        Spacer(1, 4 * mm),
        kit.para("LGPD", "h2"),
        kit.text(lgpd["text"]),
        kit.para(f"<b>{markup(exposed)} expor dados pessoais:</b> {titles}"),
    )


# -- verificações incompletas e fecho ----------------------------------------------------------


def unfinished(view: dict[str, Any], kit: Kit) -> None:
    """Verificações com erro, tempo esgotado ou canceladas, e os erros da auditoria."""
    timeline = view["timeline"]
    problems = timeline["problems"]
    errors = timeline["errors"]
    if not problems and not errors:
        return
    kit.section("Verificações que não terminaram")
    kit.add(
        kit.para(
            "O resultado pode estar incompleto nos pontos abaixo. A linha do tempo completa "
            "está no relatório HTML.",
            "small",
        )
    )
    for problem in problems[:MAX_PROBLEM_ROWS]:
        line = f"<b>{markup(problem['name'], 120)}</b> · {markup(problem['status'])}"
        if problem["asset"]:
            line += f" · {markup(problem['asset'], MAX_ASSET)}"
        if problem["message"]:
            line += f" ({markup(problem['message'], MAX_ASSET)})"
        kit.add(kit.para(line))
    if len(problems) > MAX_PROBLEM_ROWS:
        hidden = len(problems) - MAX_PROBLEM_ROWS
        kit.add(kit.text(_more(hidden, "verificação", "verificações"), "small"))
    for error in errors[:MAX_PROBLEM_ROWS]:
        kit.add(kit.text(error, limit=MAX_CELL))
    if len(errors) > MAX_PROBLEM_ROWS:
        kit.add(kit.text(_more(len(errors) - MAX_PROBLEM_ROWS, "erro", "erros"), "small"))


def closing(view: dict[str, Any], kit: Kit) -> None:
    """Fecho: versão, catálogo KEV, identificador da auditoria e o aviso de autorização."""
    footer = view["footer"]
    meta = view["meta"]
    lines = [
        f"Gerado pelo EIGAN {footer['generator']} em {meta['generated']} — análise local por "
        "regras, sem IA e sem envio de dados.",
    ]
    if footer["kev_version"]:
        line = f"Catálogo CISA KEV embarcado: versão {footer['kev_version']}"
        if footer["kev_date"]:
            line += f", publicada em {footer['kev_date']}"
        lines.append(line + ".")
    if footer["catalogs_line"]:
        lines.append(footer["catalogs_line"])
    lines.append(f"Identificador da auditoria: {meta['scan_id']}.")
    kit.add(
        CondPageBreak(30 * mm),
        Spacer(1, 8 * mm),
        HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=5),
    )
    for line in lines:
        kit.add(kit.text(line, "footnote", limit=MAX_CELL))
    for notice in footer["catalog_notices"]:
        kit.add(kit.para(f"<b>Atenção:</b> {markup(notice, MAX_CELL)}", "footnote_strong"))
    kit.add(
        kit.para(
            "<b>Use somente em sistemas que você tem autorização para avaliar.</b>",
            "footnote_strong",
        )
    )
