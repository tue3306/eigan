"""Primeira parte do PDF: capa, veredito, resumo, cenários de risco e plano de correção."""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Spacer, Table, TableStyle

from ..core import fmt
from .pdf_blocks import Kit, band_cell, band_markup, colored, severity_markup
from .pdf_canvas import Emblem
from .pdf_styles import (
    GRADE_BG,
    GRADE_COLOR,
    KEV_HEX,
    LINE,
    MUTED_HEX,
    QUICK_HEX,
    SEVERITY_FG,
    plain_style,
)
from .pdf_text import markup

MAX_CELL = 300
MAX_TITLE = 300
MAX_HEADLINE = 300
MAX_VERDICT_TEXT = 400
MAX_PLAN_ASSETS = 8
MAX_PARAGRAPH = 3000


# -- capa -------------------------------------------------------------------------------------


def cover(view: dict[str, Any], kit: Kit) -> None:
    """Marca, título, alvo e os dados da auditoria em três colunas."""
    meta = view["meta"]
    brand = Table(
        [
            [
                Emblem(12 * mm),
                [
                    kit.para("EIGAN", "brand"),
                    kit.para("Auditoria de segurança local, por regras", "small"),
                ],
            ]
        ],
        colWidths=[15 * mm, kit.width - 15 * mm],
    )
    brand.setStyle(plain_style())
    brand.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    kit.add(
        brand,
        Spacer(1, 7 * mm),
        kit.para("Relatório de auditoria de segurança", "title"),
        kit.text(meta["target"], "target", limit=500),
        Spacer(1, 5 * mm),
    )
    pairs = [
        ("Tipo de alvo", meta["kind"]),
        ("Perfil", meta["profile"]),
        ("Início", meta["started"] or "—"),
        ("Duração", meta["duration"] or "—"),
        ("Verificações", meta["checks_text"]),
        ("Versão do EIGAN", meta["version"]),
    ]
    if meta["status"] != "concluida":
        pairs.append(("Situação", meta["status_label"]))
    cells: list[Any] = [
        [kit.text(label, "count_label"), kit.text(value, "cell", limit=MAX_CELL)]
        for label, value in pairs
    ]
    columns = 3
    rows = []
    for start in range(0, len(cells), columns):
        chunk = cells[start : start + columns]
        chunk = chunk + [""] * (columns - len(chunk))
        rows.append(chunk)
    table = Table(rows, colWidths=[kit.width / columns] * columns)
    table.setStyle(plain_style(right=6, top=5, bottom=5))
    table.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 0.6, LINE)]))
    kit.add(table)
    if meta["status_note"]:
        kit.add(kit.notice(meta["status_note"]))


# -- veredito ---------------------------------------------------------------------------------


def verdict(view: dict[str, Any], kit: Kit) -> None:
    """Nota grande, pontuação, manchete e contagens (ou o estado "não avaliado")."""
    data = view["verdict"]
    css = data["grade_css"]
    color = GRADE_COLOR.get(css, GRADE_COLOR["none"])
    if data["evaluated"]:
        grade_cell: list[Any] = [
            kit.para(colored(markup(data["grade"]), color), "grade"),
            kit.para(
                f'<b>{markup(data["score"])}</b><font color="{MUTED_HEX}" size="9">/100</font>',
                "score",
            ),
            kit.para(colored(markup(data["label"]), color), "grade_label"),
        ]
        # Célula de tabela não quebra entre páginas: os textos têm limite de tamanho.
        text_cell: list[Any] = [kit.text(data["headline"], "headline", limit=MAX_HEADLINE)]
        for extra in (data["cap_reason"], data["what_if"]):
            if extra:
                text_cell += [Spacer(1, 3), kit.text(extra, limit=MAX_VERDICT_TEXT)]
    else:
        grade_cell = [
            kit.para(colored("—", color), "grade"),
            kit.para(colored("Não avaliado", color), "grade_label"),
        ]
        text_cell = [
            kit.para("Não foi possível avaliar este alvo", "headline"),
            Spacer(1, 3),
            kit.text(data["headline"], limit=MAX_VERDICT_TEXT),
            Spacer(1, 3),
            kit.para(
                "Sem respostas, o EIGAN não atribui nota: uma nota alta aqui daria uma falsa "
                "sensação de segurança."
            ),
        ]
    grade_width = 40 * mm
    # A nota fica num bloco próprio com cantos arredondados e o fundo tingido da nota,
    # como no painel; o texto ao lado fica sem fundo.
    tile = Table([[grade_cell]], colWidths=[grade_width])
    tile.setStyle(plain_style(left=4, right=4, top=10, bottom=10))
    tile.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(GRADE_BG.get(css, GRADE_BG["none"])),
                ),
                ("ROUNDEDCORNERS", [6, 6, 6, 6]),
            ]
        )
    )
    table = Table([[tile, text_cell]], colWidths=[grade_width, kit.width - grade_width])
    table.setStyle(plain_style())
    table.setStyle(
        TableStyle([("LEFTPADDING", (1, 0), (1, 0), 14), ("TOPPADDING", (1, 0), (1, 0), 4)])
    )
    kit.add(Spacer(1, 8 * mm), KeepTogether([table]))
    if data["evaluated"]:
        kit.add(Spacer(1, 6 * mm), _counts(data, kit), Spacer(1, 4 * mm), _bands(data, kit))


def _counts(data: dict[str, Any], kit: Kit) -> Table:
    return kit.count_row(
        [
            (
                item["n"],
                item["label"],
                SEVERITY_FG.get(item["key"], MUTED_HEX) if item["n"] else MUTED_HEX,
            )
            for item in data["counts"]
        ]
    )


def _bands(data: dict[str, Any], kit: Kit) -> Table:
    rows = []
    commands: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (1, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (-1, 0), (-1, -1), 0),
    ]
    for index, item in enumerate(data["priorities"]):
        chip, background = band_cell(item["band"], kit.s["chip"])
        rows.append(
            [
                chip,
                kit.text(item["band"]["text"], "cell"),
                kit.text(fmt.plural(item["n"], "achado", "achados"), "cell_right"),
            ]
        )
        commands.append(("BACKGROUND", (0, index), (0, index), background))
    table = Table(rows, colWidths=[12 * mm, kit.width - 42 * mm, 30 * mm])
    table.setStyle(TableStyle(commands))
    return table


# -- resumo e cenários --------------------------------------------------------------------------


def summary(view: dict[str, Any], kit: Kit) -> None:
    paragraphs = view["summary"]["paragraphs"]
    if not paragraphs:
        return
    kit.section("Resumo")
    for paragraph in paragraphs:
        kit.add(kit.text(paragraph, limit=MAX_PARAGRAPH), Spacer(1, 4))


def scenarios(view: dict[str, Any], kit: Kit) -> None:
    items = view["scenarios"]
    if not items:
        return
    kit.section("Cenários de risco")
    kit.add(
        kit.para(
            "Problemas que, juntos, abrem um caminho de ataque mais grave do que cada um isolado.",
            "small",
        )
    )
    for scenario in items:
        kit.add(
            kit.para(
                f"{markup(scenario['title'], MAX_TITLE)} {_dot(severity_markup(scenario['severity']))}",
                "h2",
            ),
            kit.text(scenario["narrative"], limit=MAX_PARAGRAPH),
            kit.para(f"<b>Como quebrar a cadeia:</b> {markup(scenario['breaker'], MAX_PARAGRAPH)}"),
            kit.para(f"Onde: {markup(scenario['where'], MAX_CELL)}", "small"),
        )


# -- plano de correção --------------------------------------------------------------------------


def plan(view: dict[str, Any], kit: Kit) -> None:
    actions = view["plan"]
    if not actions:
        return
    kit.section("Plano de correção")
    quick = view["quick_wins"]
    intro = (
        f"{fmt.plural(len(actions), 'ação', 'ações')}, na ordem recomendada. Cada ação resolve "
        "um grupo de problemas com a mesma correção"
    )
    intro += f"; {quick} de esforço baixo." if quick else "."
    kit.add(kit.text(intro, "small"))
    for action in actions:
        _action(action, kit)


def _action(action: dict[str, Any], kit: Kit) -> None:
    band = action["band"]
    kit.add(
        kit.para(f"{action['index']}. {markup(action['title'], MAX_TITLE)}", "h2"),
        kit.para(f"{band_markup(band)} {markup(band['text'])}", "band"),
    )
    meta = []
    if action["area"]:
        meta.append(f"Área: {markup(action['area'])}")
    meta.append(f"Esforço: {markup(action['effort'])}")
    if action["gain_text"]:
        meta.append(f"Efeito na nota: <b>{markup(action['gain_text'])}</b>")
    if action["quick_win"]:
        meta.append(colored("Ganho rápido", QUICK_HEX, bold=True))
    if action["kev"]:
        meta.append(colored("Exploração ativa (CISA KEV)", KEV_HEX, bold=True))
    kit.add(kit.para(" · ".join(meta), "indent_small"))
    if action["assets"]:
        shown = action["assets"][:MAX_PLAN_ASSETS]
        assets = ", ".join(markup(a, 200) for a in shown)
        more = len(action["assets"]) - len(shown) + action["more_assets"]
        if more > 0:
            assets += f" e mais {more}"
        kit.add(kit.para(f"Ativos afetados: {assets}", "indent_small"))
    for problem in action["problems"]:
        _problem(problem, kit)
    for fix in action["fixes"]:
        kit.add(
            kit.para(f"Exemplo de correção: {markup(fix['label'])}", "fix_label"),
            kit.code(fix["code"]),
        )


def _problem(problem: dict[str, Any], kit: Kit) -> None:
    count = fmt.plural(problem["count"], "ocorrência", "ocorrências")
    kit.add(
        kit.para(
            f"{markup(problem['title'], MAX_TITLE)} {_dot(severity_markup(problem['severity']))}"
            f"{colored(' · ' + markup(count), MUTED_HEX)}",
            "h3",
        )
    )
    if problem["summary"] and problem["summary"] != problem["title"]:
        kit.add(kit.text(problem["summary"], "indent"))
    if problem["steps"]:
        kit.add(kit.steps(problem["steps"]))
    if problem["verify"]:
        kit.add(kit.para(f"<b>Como verificar:</b> {markup(problem['verify'])}", "indent"))


def _dot(text: str) -> str:
    """Separador " · " antes de um rótulo colorido."""
    return f"· {text}"
