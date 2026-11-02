"""Resumo em português gerado por modelos de texto (sem IA).

Cada frase vem de um modelo fixo preenchido com números e nomes da auditoria. Assim o
texto é previsível, verificável e igual para o mesmo resultado.
"""

from __future__ import annotations

from typing import Any

from ..core import facts, fmt
from ..core.models import Finding, ScanResult, Severity, TargetKind
from ..core.settings import PROFILE_LABEL
from . import scoring
from .correlation import ScenarioMatch
from .remediation import Action, entry_for

NOT_EVALUATED = {
    TargetKind.URL: (
        "Não foi possível avaliar o alvo: nenhuma verificação obteve resposta. Confira o "
        "endereço, a conexão e se o site está no ar."
    ),
    TargetKind.HOST: (
        "Não foi possível avaliar o alvo: nenhum serviço respondeu. Confira o endereço, a "
        "conexão e se um firewall bloqueia o acesso."
    ),
    TargetKind.LOCAL: "Não foi possível avaliar esta máquina: nenhuma verificação se aplicou.",
    TargetKind.PROJECT: (
        "Nenhum arquivo analisável foi encontrado nesta pasta. Confira o caminho do projeto."
    ),
    TargetKind.LOGS: (
        "Nenhum registro de log reconhecido foi encontrado. Confira o caminho e o formato do log."
    ),
}

#: plataformas e CDNs que entregam HTTPS, HSTS e cabeçalhos por conta própria
HOSTING_PLATFORMS = {
    "cloudflare": "Cloudflare",
    "render": "Render",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "github-pages": "GitHub Pages",
    "fastly": "Fastly",
    "cloudfront": "CloudFront",
    "akamai": "Akamai",
    "azure-front-door": "Azure Front Door",
    "azure-cdn": "Azure CDN",
}
GOOD_GRADES = ("A+", "A", "B")
_BACKEND_KINDS = ("language", "framework", "cms")
#: servidores de aplicação e PaaS: rodam código do site mesmo sem cookie nem formulário na home
_APP_SERVERS = frozenset(
    {
        "gunicorn",
        "uvicorn",
        "hypercorn",
        "waitress",
        "tomcat",
        "jetty",
        "kestrel",
        "werkzeug",
        "passenger",
        "cowboy",
        "puma",
        "unicorn",
        "thin",
        "heroku",
        "express",
        "wildfly",
        "weblogic",
        "websphere",
        "glassfish",
    }
)

RISK_WORD = {
    Severity.CRITICAL: "crítico",
    Severity.HIGH: "alto",
    Severity.MEDIUM: "médio",
    Severity.LOW: "baixo",
}


def severity_phrase(findings: list[Finding]) -> str:
    """``"1 de risco crítico, 2 de risco alto e 3 de risco médio"``."""
    parts = []
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = sum(1 for f in findings if f.severity is severity)
        if n:
            parts.append(f"{n} de risco {RISK_WORD[severity]}")
    return fmt.join_pt(parts)


def _headline(
    result: ScanResult,
    active: list[Finding],
    evaluated: bool,
) -> str:
    if not evaluated:
        return NOT_EVALUATED.get(result.kind, NOT_EVALUATED[TargetKind.URL])
    if not active:
        return "Nenhum problema encontrado nas verificações realizadas."
    urgent = sum(1 for f in active if f.priority >= 75)
    if urgent == 1:
        return "1 problema exige correção imediata."
    if urgent > 1:
        return f"{urgent} problemas exigem correção imediata."
    if len(active) == 1:
        return "1 problema para corrigir, nenhum urgente."
    return f"{len(active)} problemas para corrigir, nenhum urgente."


def platform_notice(result: ScanResult, posture: scoring.Posture) -> str:
    """Aviso quando uma nota boa pode refletir a plataforma de hospedagem, não a aplicação.

    Vale para alvo de site com nota boa, tecnologia de plataforma/CDN detectada e nenhum
    sinal de back end (sem cookies do servidor, sem formulário enviado ao servidor, sem
    linguagem, framework, CMS ou servidor de aplicação identificado).
    """
    if result.kind is not TargetKind.URL or posture.grade not in GOOD_GRADES:
        return ""
    names = {str(f.data.get("name", "")).lower(): f for f in result.facts if f.kind == facts.TECH}
    platforms = [label for key, label in HOSTING_PLATFORMS.items() if key in names]
    states = [f for f in result.facts if f.kind == facts.WEB_FRONTEND]
    if not platforms or not states or any(f.data.get("backend") for f in states):
        return ""
    if any(name in _APP_SERVERS for name in names):
        return ""
    if any(f.data.get("kind") in _BACKEND_KINDS for f in names.values()):
        return ""
    return (
        f"Atenção ao ler esta nota: o site é servido por {fmt.join_pt(platforms)} e não mostra "
        "sinais de um back end (nenhum cookie de sessão, nenhum formulário enviado ao "
        "servidor). O HTTPS, o HSTS e parte dos cabeçalhos podem ser da plataforma, e não da "
        "aplicação. O resultado vale para o site como está publicado e nada diz sobre uma "
        "aplicação que ainda não existe: quando houver login, sessão e API, audite de novo."
    )


def build(
    result: ScanResult,
    *,
    posture: scoring.Posture,
    plan: list[Action],
    scenarios: list[ScenarioMatch],
    what_if: dict[str, Any] | None,
    diff: dict[str, Any] | None,
    evaluated: bool,
) -> dict[str, Any]:
    active = sorted(
        (f for f in result.findings if scoring.counts_toward_score(f)),
        key=lambda f: (-f.priority, -f.severity.rank),
    )
    paragraphs: list[str] = []

    kind_label = result.kind.label.lower()
    profile = PROFILE_LABEL.get(result.profile, result.profile).lower()
    ran = len(result.runs)
    scope = (
        f"A auditoria de {result.target} ({kind_label}, perfil {profile}) executou "
        f"{fmt.plural(ran, 'verificação', 'verificações')} em {fmt.duration(result.duration)}."
    )
    if result.status == "cancelada":
        scope += " Ela foi cancelada antes do fim, então o resultado é parcial."
    paragraphs.append(scope)

    if evaluated:
        if active:
            paragraphs.append(
                f"Foram encontrados {fmt.plural(len(active), 'problema', 'problemas')}: "
                f"{severity_phrase(active)}. A nota de postura é {posture.grade} "
                f"({posture.score}/100, {posture.label.lower()})."
                + (f" {posture.cap_reason}" if posture.cap_reason else "")
            )
            top = active[0]
            entry = entry_for(top)
            risk = f" {entry.risk}" if entry.risk else ""
            paragraphs.append(f"O ponto mais urgente é “{top.title}” em {top.asset}.{risk}")
        else:
            paragraphs.append(
                f"Nenhum problema foi encontrado e a nota de postura é {posture.grade} "
                f"({posture.score}/100). Isso vale para o que foi verificado; mantenha as "
                "auditorias periódicas."
            )
        notice = platform_notice(result, posture)
        if notice:
            paragraphs.append(notice)

    if scenarios:
        first = scenarios[0]
        count = len(scenarios)
        intro = (
            "Há 1 combinação perigosa de problemas"
            if count == 1
            else f"Há {count} combinações perigosas de problemas"
        )
        paragraphs.append(
            f"{intro}. A mais grave: {first.scenario.title.lower()}. "
            f"{first.scenario.narrative} {first.scenario.breaker}"
        )

    kev = [f for f in active if f.kev]
    if kev:
        cves = sorted({c for f in kev for c in f.cves})
        verb = "consta" if len(cves) == 1 else "constam"
        paragraphs.append(
            f"{fmt.join_pt(cves)} {verb} do catálogo CISA KEV: são falhas já exploradas por "
            "atacantes reais. Trate como prioridade máxima."
        )

    if plan:
        quick = sum(1 for a in plan if a.quick_win)
        text = f"O plano de correção tem {fmt.plural(len(plan), 'ação', 'ações')}"
        text += f", {quick} de esforço baixo." if quick else "."
        if what_if and what_if.get("actions"):
            n = int(what_if["actions"])
            first_n = "a primeira" if n == 1 else f"as {n} primeiras"
            text += (
                f" Fazendo {first_n}, a nota estimada vai de {posture.score} "
                f"para {what_if['score']} ({what_if['grade']})."
            )
        paragraphs.append(text)

    if diff:
        fixed, new, still = len(diff["fixed"]), len(diff["new"]), len(diff["persisting"])
        paragraphs.append(
            f"Em relação à auditoria de {fmt.date_time(diff['previous_date'])}: "
            f"{fmt.plural(fixed, 'problema corrigido', 'problemas corrigidos')}, "
            f"{fmt.plural(new, 'novo', 'novos')} e {fmt.plural(still, 'ainda aberto', 'ainda abertos')}. "
            f"A nota foi de {diff['score_before']} para {diff['score_after']}."
        )

    if result.errors:
        paragraphs.append(
            f"{fmt.plural(len(result.errors), 'verificação não terminou', 'verificações não terminaram')}"
            " (veja a linha do tempo); o resultado pode estar incompleto."
        )

    strengths: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for control in result.passed:
        key = (control.control, control.text)
        if key in seen:
            continue
        seen.add(key)
        strengths.append({"control": control.control, "text": control.text, "asset": control.asset})

    return {
        "headline": _headline(result, active, evaluated),
        "paragraphs": paragraphs,
        "top_risks": [
            {
                "fingerprint": f.fingerprint,
                "title": f.title,
                "asset": f.asset,
                "severity": f.severity.value,
                "priority": f.priority,
                "band": f.priority_label,
                "risk": entry_for(f).risk,
            }
            for f in active[:5]
        ],
        "strengths": strengths,
        "next_steps": [
            {"group": a.group, "title": a.title, "band": a.band, "band_text": a.band_text}
            for a in plan[:3]
        ],
    }
