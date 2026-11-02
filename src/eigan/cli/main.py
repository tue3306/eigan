"""Linha de comando do EIGAN.

Sem argumentos (ou com dois cliques no executável) abre o painel no navegador.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .. import APP_NAME, APP_TAGLINE, __version__
from ..core import fmt, kb
from ..core.models import ScanResult, Severity, TargetKind
from ..core.registry import all_checks, load_builtin_checks
from ..core.settings import PROFILE_LABEL, PROFILES, load_settings
from ..core.target import TargetError, parse_target
from .console import Console, prepare_streams

EXIT_OK, EXIT_FAIL_ON, EXIT_ERROR, EXIT_CANCELLED = 0, 1, 2, 130
FAIL_ON = {
    "critica": Severity.CRITICAL,
    "alta": Severity.HIGH,
    "media": Severity.MEDIUM,
    "baixa": Severity.LOW,
}
DEFAULT_FORMATS = ("html", "pdf", "json")


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage: Any, actions: Any, groups: Any, prefix: str | None = None) -> None:
        super().add_usage(usage, actions, groups, prefix or "uso: ")


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _Formatter)
        kwargs.setdefault("add_help", False)
        super().__init__(*args, **kwargs)
        self._positionals.title = "argumentos"
        self._optionals.title = "opções"
        self.add_argument("-h", "--ajuda", "--help", action="help", help="mostra esta ajuda e sai")

    def error(self, message: str) -> Any:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: erro: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="eigan",
        description=(
            f"{APP_NAME} {__version__} — auditor de segurança blue team.\n"
            "Encontra vulnerabilidades e explica como corrigir. Sem IA, sem chaves de API, offline.\n"
            "Use somente em sistemas que você tem autorização para avaliar.\n\n"
            "Sem comando, abre o painel no navegador."
        ),
    )
    parser.add_argument(
        "--versao",
        "--version",
        action="version",
        version=f"EIGAN {__version__}",
        help="mostra a versão",
    )
    sub = parser.add_subparsers(dest="comando", metavar="comando", parser_class=_Parser)

    p = sub.add_parser("painel", aliases=["serve", "panel"], help="abre o painel no navegador")
    p.add_argument("--porta", type=int, default=8765, help="porta local (padrão 8765)")
    p.add_argument("--sem-navegador", action="store_true", help="não abre o navegador")

    p = sub.add_parser(
        "auditar",
        aliases=["scan", "audit"],
        help="audita um alvo e gera os relatórios",
        description=(
            "Alvos aceitos: URL (https://site.com.br), host ou IP (servidor.local, 10.0.0.5), "
            "rede CIDR (10.0.0.0/24), 'local' (esta máquina), uma pasta de projeto ou um "
            "arquivo/pasta de logs."
        ),
    )
    p.add_argument("alvo", help="o que auditar")
    p.add_argument("--tipo", choices=[k.value for k in TargetKind], help="força o tipo do alvo")
    p.add_argument("--perfil", choices=PROFILES, help="rapido, padrao ou completo")
    p.add_argument("--portas", help="auto, top100, top1000, todas ou lista (22,80,8000-8100)")
    p.add_argument(
        "--com-portas", action="store_true", help="em alvos URL, também varre as portas do host"
    )
    p.add_argument(
        "--formatos", help="relatórios a gerar: html,pdf,json,sarif,csv (padrão html,pdf,json)"
    )
    p.add_argument("--saida", type=Path, help="pasta dos relatórios")
    p.add_argument("--sem-relatorio", action="store_true", help="não grava relatórios")
    p.add_argument(
        "--falhar-em",
        "--fail-on",
        choices=list(FAIL_ON),
        help="sai com código 1 se houver achado aberto com esta severidade ou maior (para CI)",
    )
    p.add_argument("--json", action="store_true", help="imprime o resultado completo em JSON")
    p.add_argument(
        "-s", "--sim", "--yes", action="store_true", help="confirma que você tem autorização"
    )
    p.add_argument("-q", "--silencioso", action="store_true", help="não mostra o andamento")

    p = sub.add_parser("checagens", aliases=["checks"], help="lista as verificações disponíveis")
    p.add_argument(
        "--categoria", help="filtra pela categoria (web, tls, dns, rede, host, codigo, logs)"
    )

    p = sub.add_parser("explicar", aliases=["explain"], help="explica um achado e como corrigir")
    p.add_argument("id", help="identificador do achado (ex.: web.hsts.ausente)")

    p = sub.add_parser("historico", aliases=["history"], help="lista as auditorias salvas")
    p.add_argument("--limite", type=int, default=30)

    p = sub.add_parser(
        "relatorio", aliases=["report"], help="gera relatórios de uma auditoria salva"
    )
    p.add_argument("id", help="id da auditoria (veja 'eigan historico')")
    p.add_argument("--formatos", help="html,pdf,json,sarif,csv (padrão: todos)")
    p.add_argument("--saida", type=Path, help="pasta dos relatórios")

    p = sub.add_parser("comparar", aliases=["diff"], help="compara duas auditorias do mesmo alvo")
    p.add_argument("anterior")
    p.add_argument("atual")

    sub.add_parser("versao", aliases=["version"], help="mostra a versão")
    return parser


# -- comandos -----------------------------------------------------------------------------


def cmd_panel(args: argparse.Namespace) -> int:
    from ..panel.server import serve

    return serve(port=args.porta, open_browser=not args.sem_navegador)


def _parse_formats(text: str | None, default: Sequence[str]) -> list[str]:
    from ..reports import FORMATS

    if not text:
        return list(default)
    formats = [f.strip().lower() for f in text.split(",") if f.strip()]
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ValueError(f"Formato desconhecido: {', '.join(unknown)}. Use {', '.join(FORMATS)}.")
    return formats


class _Progress:
    """Mostra decisões e achados à medida que o motor trabalha."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.lock = threading.Lock()

    def __call__(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        with self.lock:
            if kind == "decision":
                self.console.wrap(
                    str(event.get("text", "")), indent="    ", first=self.console.dim("  · ")
                )
            elif kind == "finding":
                f = event.get("finding", {})
                severity = str(f.get("severity", "info"))
                label = Severity(severity).label
                self.console.line(
                    f"  {self.console.severity('●', severity)} {self.console.severity(label, severity)}: "
                    f"{f.get('title', '')} — {f.get('asset', '')}"
                )


def cmd_audit(args: argparse.Namespace) -> int:
    from ..service import run_audit

    console = Console(sys.stderr if args.json else sys.stdout)
    try:
        target = parse_target(args.alvo, args.tipo)
        formats = [] if args.sem_relatorio else _parse_formats(args.formatos, DEFAULT_FORMATS)
    except (TargetError, ValueError) as exc:
        console.line(f"Erro: {exc}")
        return EXIT_ERROR

    if target.kind in (TargetKind.URL, TargetKind.HOST) and not args.sim:
        if not sys.stdin.isatty():
            console.line(
                "Confirme a autorização com --sim (necessário fora de um terminal interativo)."
            )
            return EXIT_ERROR
        answer = input(f"Você tem autorização para avaliar {target.display}? [s/N] ")
        if answer.strip().lower() not in ("s", "sim", "y", "yes"):
            console.line("Auditoria não iniciada.")
            return EXIT_ERROR

    settings = load_settings()
    if args.perfil:
        settings = settings.with_profile(args.perfil)
    if args.portas:
        settings.ports = args.portas
    if args.com_portas:
        settings.include_ports_for_url = True

    quiet = args.silencioso or args.json
    if not quiet:
        console.line(
            f"{console.bold('EIGAN')} {__version__} · auditando {console.bold(target.display)} "
            f"({target.kind.label.lower()}, perfil {PROFILE_LABEL[settings.profile].lower()})"
        )
        console.line(console.dim("Ctrl+C cancela e mantém o resultado parcial."))

    cancel = threading.Event()
    outcome: dict[str, Any] = {}

    def work() -> None:
        try:
            outcome["result"] = run_audit(
                target.raw,
                kind=target.kind.value,
                settings=settings,
                emit=None if quiet else _Progress(console),
                cancel=cancel,
            )
        except Exception as exc:  # noqa: BLE001 — erro vira mensagem e código de saída
            outcome["error"] = exc

    worker = threading.Thread(target=work, name="eigan-auditoria", daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.3)
    except KeyboardInterrupt:
        console.line("\nCancelando… aguarde as verificações em curso.")
        cancel.set()
        worker.join()

    if "error" in outcome:
        console.line(f"Erro na auditoria: {outcome['error']}")
        return EXIT_ERROR
    result: ScanResult = outcome["result"]

    written: dict[str, Path] = {}
    if formats:
        from ..reports import write_reports

        written = write_reports(result, formats, args.saida)

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print_summary(console, result, written)

    if result.status == "cancelada":
        return EXIT_CANCELLED
    if args.falhar_em:
        floor = FAIL_ON[args.falhar_em]
        from ..intel.scoring import counts_toward_score

        if any(counts_toward_score(f) and f.severity.rank >= floor.rank for f in result.findings):
            return EXIT_FAIL_ON
    return EXIT_OK


def print_summary(
    console: Console, result: ScanResult, written: dict[str, Path] | None = None
) -> None:
    analysis = result.analysis
    posture = analysis.get("posture", {})
    narrative = analysis.get("narrative", {})
    counts = analysis.get("counts", {})
    console.line()
    console.rule(f"Resultado · {result.target}")
    grade = str(posture.get("grade", "—"))
    if analysis.get("evaluated"):
        line = f"Nota {console.grade(grade, grade)} · {posture.get('score')}/100 ({posture.get('label', '')})"
        console.line(line)
        if posture.get("cap_reason"):
            console.wrap(str(posture["cap_reason"]), indent="  ")
    console.wrap(str(narrative.get("headline", "")))
    parts = [
        console.severity(f"{s.label} {counts.get(s.value, 0)}", s.value)
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts.get(s.value)
    ]
    if parts:
        console.line("Achados abertos: " + " · ".join(parts))

    plan = analysis.get("plan", [])
    if plan:
        console.line()
        console.rule("Plano de correção")
        for index, action in enumerate(plan[:5], 1):
            extra = f"esforço {str(action['effort_label']).split(' ')[0].lower()}"
            if action.get("score_gain"):
                extra += f", +{action['score_gain']} pontos"
            console.line(f"{index}. [{action['band']}] {console.bold(action['title'])} — {extra}")
            for problem in action["problems"][:3]:
                console.wrap(problem["title"], indent="     ", first="   • ")
                for step in problem["steps"][:3]:
                    console.wrap(step, indent="       ", first=console.dim("     - "))
        if len(plan) > 5:
            console.line(console.dim(f"   … mais {len(plan) - 5} ações no relatório."))
        what_if = analysis.get("what_if")
        if what_if:
            console.line(
                f"Fazendo as {what_if['actions']} primeiras ações, a nota estimada vai para "
                f"{what_if['score']} ({what_if['grade']})."
            )
    if written:
        console.line()
        console.rule("Relatórios")
        for path in written.values():
            console.line(f"  {path}")
    console.line(
        console.dim(
            f"Auditoria {result.id} · {fmt.duration(result.duration)} · eigan explicar <id> detalha cada achado"
        )
    )


def cmd_checks(args: argparse.Namespace) -> int:
    console = Console()
    load_builtin_checks()
    checks = all_checks()
    if args.categoria:
        checks = [c for c in checks if c.category.value == args.categoria.lower()]
    current = ""
    for check in sorted(checks, key=lambda c: (c.category.value, c.order, c.id)):
        if check.category.value != current:
            current = check.category.value
            console.line()
            console.rule(check.category.label)
        profiles = ", ".join(PROFILE_LABEL[p].lower() for p in check.profiles)
        console.line(
            f"  {console.bold(check.id)} — {check.name} {console.dim('(' + profiles + ')')}"
        )
        console.wrap(check.description, indent="      ")
    stats = kb.stats()
    console.line()
    console.line(
        f"{len(checks)} verificações · {stats.total} tipos de achado na base de conhecimento."
    )
    return EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    console = Console()
    load_builtin_checks()
    entry = kb.get(args.id)
    if entry is None:
        close = difflib.get_close_matches(
            args.id, [e.id for e in kb.all_entries()], n=5, cutoff=0.5
        )
        console.line(f"'{args.id}' não está na base de conhecimento.")
        if close:
            console.line("Você quis dizer: " + ", ".join(close))
        return EXIT_ERROR
    console.rule(f"{entry.title}  ({entry.id})")
    console.line(
        f"Severidade padrão: {console.severity(entry.severity.label, entry.severity.value)} · categoria {entry.category.label}"
    )
    console.line()
    console.wrap(entry.summary)
    console.line()
    console.rule("O que é")
    console.wrap(entry.explanation)
    console.line()
    console.rule("Risco")
    console.wrap(entry.risk)
    console.line()
    console.rule("Como corrigir")
    for index, step in enumerate(entry.steps, 1):
        console.wrap(step, indent="   ", first=f"{index}. ")
    for fix in entry.examples:
        console.line()
        console.line(console.bold(f"Exemplo — {fix.label}"))
        for code_line in fix.code.splitlines():
            console.line("    " + code_line)
    console.line()
    console.rule("Como verificar")
    console.wrap(entry.verify)
    tags = [t for t in (entry.cwe, entry.owasp) if t] + [f"CIS {c}" for c in entry.cis]
    if entry.lgpd:
        tags.append("LGPD")
    if tags:
        console.line()
        console.line(console.dim("Referências de conformidade: " + ", ".join(tags)))
    for ref in entry.references:
        console.line(console.dim(f"  {ref}"))
    return EXIT_OK


def cmd_history(args: argparse.Namespace) -> int:
    from ..storage import Store

    console = Console()
    scans = Store().scans(limit=args.limite)
    if not scans:
        console.line("Nenhuma auditoria salva ainda. Comece com: eigan auditar <alvo>")
        return EXIT_OK
    for row in scans:
        grade = row.get("grade") or "—"
        score = row.get("score")
        score_text = f"{score:>3}" if isinstance(score, int) else "  —"
        console.line(
            f"{row['id']}  {fmt.date_time(row['started_at'])}  {console.grade(f'{grade:<2}', grade)} {score_text}  "
            f"{row['target']}  {console.dim(PROFILE_LABEL.get(row['profile'], row['profile']).lower())}"
        )
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    from ..reports import FORMATS, write_reports
    from ..storage import Store

    console = Console()
    result = Store().get(args.id)
    if result is None:
        console.line(f"Auditoria '{args.id}' não encontrada. Veja os ids com: eigan historico")
        return EXIT_ERROR
    try:
        formats = _parse_formats(args.formatos, FORMATS)
    except ValueError as exc:
        console.line(f"Erro: {exc}")
        return EXIT_ERROR
    for path in write_reports(result, formats, args.saida).values():
        console.line(str(path))
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    from ..intel.diff import compare
    from ..storage import Store, target_key

    console = Console()
    store = Store()
    old, new = store.get(args.anterior), store.get(args.atual)
    if old is None or new is None:
        console.line("Auditoria não encontrada. Veja os ids com: eigan historico")
        return EXIT_ERROR
    if target_key(old.kind.value, old.target) != target_key(new.kind.value, new.target):
        console.line("Só é possível comparar auditorias do mesmo alvo.")
        return EXIT_ERROR
    if old.started_at > new.started_at:
        old, new = new, old
    data = compare(new, old)
    console.rule(f"{new.target}: {fmt.date_time(old.started_at)} → {fmt.date_time(new.started_at)}")
    console.line(f"Nota: {data['score_before']} → {data['score_after']} ({data['delta']:+d})")
    for key, title in (
        ("fixed", "Corrigidos"),
        ("new", "Novos"),
        ("persisting", "Ainda abertos"),
        ("unverified", "Não verificados nesta auditoria"),
    ):
        items = data[key]
        if not items:
            continue
        console.line()
        console.line(console.bold(f"{title} ({len(items)})"))
        for item in items:
            console.line(
                f"  {console.severity('●', item['severity'])} {item['title']} — {item['asset']}"
            )
    return EXIT_OK


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"EIGAN {__version__} — {APP_TAGLINE}")
    print("Blue team, por regras: sem IA, sem chaves de API, sem envio de dados.")
    return EXIT_OK


COMMANDS = {
    "painel": cmd_panel,
    "serve": cmd_panel,
    "panel": cmd_panel,
    "auditar": cmd_audit,
    "scan": cmd_audit,
    "audit": cmd_audit,
    "checagens": cmd_checks,
    "checks": cmd_checks,
    "explicar": cmd_explain,
    "explain": cmd_explain,
    "historico": cmd_history,
    "history": cmd_history,
    "relatorio": cmd_report,
    "report": cmd_report,
    "comparar": cmd_compare,
    "diff": cmd_compare,
    "versao": cmd_version,
    "version": cmd_version,
}


def main(argv: Sequence[str] | None = None) -> int:
    prepare_streams()
    from ..core.logs import setup_logging

    setup_logging()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.comando:
        args = parser.parse_args(["painel"])
    return COMMANDS[args.comando](args)
