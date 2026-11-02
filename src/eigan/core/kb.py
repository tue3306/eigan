"""Base de conhecimento: explicação, risco e correção de cada tipo de achado.

Cada checagem registra aqui as entradas dos achados que pode emitir (pelo mesmo
``id`` usado em ``ctx.report``). É esta base — e não uma IA — que transforma um
sinal técnico em orientação: o que é o problema, o que um atacante faria com ele,
o passo a passo da correção (com exemplos por tecnologia) e como confirmar que
ficou resolvido.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Category, Severity


@dataclass(frozen=True)
class Fix:
    """Exemplo de correção para uma tecnologia específica."""

    tech: str  # chave usada para casar com a tecnologia detectada (nginx, apache, iis...)
    label: str  # nome exibido
    code: str
    lang: str = "text"


@dataclass(frozen=True)
class KBEntry:
    id: str
    title: str
    category: Category
    severity: Severity
    summary: str
    explanation: str
    risk: str
    steps: tuple[str, ...]
    verify: str
    examples: tuple[Fix, ...] = ()
    effort: str = "baixo"  # baixo | medio | alto
    fix_group: str = ""
    references: tuple[str, ...] = ()
    cwe: str | None = None
    owasp: str | None = None  # ex.: "A05:2021"
    cis: tuple[str, ...] = ()  # salvaguardas do CIS Controls v8 (ex.: "4.1")
    lgpd: bool = False  # afeta a proteção de dados pessoais (LGPD art. 46)
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        group = FIX_GROUPS.get(self.fix_group, {})
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "category_label": self.category.label,
            "severity": self.severity.value,
            "summary": self.summary,
            "explanation": self.explanation,
            "risk": self.risk,
            "steps": list(self.steps),
            "verify": self.verify,
            "examples": [
                {"tech": f.tech, "label": f.label, "code": f.code, "lang": f.lang}
                for f in self.examples
            ],
            "effort": self.effort,
            "effort_label": EFFORT_LABEL.get(self.effort, self.effort),
            "fix_group": self.fix_group,
            "fix_group_title": group.get("title", ""),
            "references": list(self.references),
            "cwe": self.cwe,
            "owasp": self.owasp,
            "owasp_label": OWASP_2021.get(self.owasp or "", ""),
            "cis": list(self.cis),
            "lgpd": self.lgpd,
            "tags": list(self.tags),
        }


EFFORT_LABEL = {
    "baixo": "Baixo (minutos)",
    "medio": "Médio (horas)",
    "alto": "Alto (dias ou mudança planejada)",
}
EFFORT_RANK = {"baixo": 0, "medio": 1, "alto": 2}

#: OWASP Top 10 — edição 2021 (https://owasp.org/Top10/)
OWASP_2021 = {
    "A01:2021": "A01 — Quebra de controle de acesso",
    "A02:2021": "A02 — Falhas criptográficas",
    "A03:2021": "A03 — Injeção",
    "A04:2021": "A04 — Design inseguro",
    "A05:2021": "A05 — Configuração incorreta de segurança",
    "A06:2021": "A06 — Componentes vulneráveis e desatualizados",
    "A07:2021": "A07 — Falhas de identificação e autenticação",
    "A08:2021": "A08 — Falhas de integridade de software e dados",
    "A09:2021": "A09 — Falhas de log e monitoramento",
    "A10:2021": "A10 — Server-Side Request Forgery (SSRF)",
}

#: CIS Controls v8 — salvaguardas citadas pela base (https://www.cisecurity.org/controls/v8)
CIS_V8 = {
    "2.2": "Garantir que o software autorizado tenha suporte do fabricante",
    "3.3": "Configurar listas de controle de acesso a dados",
    "3.10": "Criptografar dados sensíveis em trânsito",
    "3.11": "Criptografar dados sensíveis em repouso",
    "4.1": "Estabelecer e manter um processo de configuração segura",
    "4.2": "Configuração segura da infraestrutura de rede",
    "4.4": "Implementar e gerenciar firewall nos servidores",
    "4.5": "Implementar e gerenciar firewall nos dispositivos dos usuários",
    "4.6": "Gerenciar ativos e software de forma segura (protocolos seguros de gestão)",
    "4.7": "Gerenciar contas padrão em ativos e software",
    "4.8": "Desinstalar ou desativar serviços desnecessários",
    "5.2": "Usar senhas únicas",
    "5.4": "Restringir privilégios de administrador a contas dedicadas",
    "6.3": "Exigir MFA para aplicações expostas externamente",
    "6.5": "Exigir MFA para acesso administrativo",
    "7.1": "Estabelecer e manter um processo de gestão de vulnerabilidades",
    "7.3": "Gestão automatizada de patches do sistema operacional",
    "7.4": "Gestão automatizada de patches de aplicações",
    "8.2": "Coletar logs de auditoria",
    "8.5": "Coletar logs de auditoria detalhados",
    "8.11": "Revisar os logs de auditoria",
    "9.5": "Implementar DMARC",
    "10.1": "Implementar e manter software antimalware",
    "10.5": "Habilitar recursos contra exploração",
    "12.2": "Arquitetura de rede segura",
    "12.6": "Usar protocolos seguros de gestão e comunicação de rede",
    "13.1": "Centralizar alertas de eventos de segurança",
    "13.3": "Implementar detecção de intrusão na rede",
    "16.1": "Processo de desenvolvimento seguro de aplicações",
    "16.4": "Manter inventário de componentes de software de terceiros",
    "16.7": "Usar modelos de configuração endurecida na infraestrutura das aplicações",
    "16.10": "Aplicar princípios de design seguro na arquitetura das aplicações",
    "16.11": "Usar módulos ou serviços de segurança já validados",
    "16.12": "Implementar verificações de segurança no nível do código",
}

#: Grupos de correção: achados do mesmo grupo viram UMA ação no plano.
FIX_GROUPS: dict[str, dict[str, str]] = {
    "https": {"title": "Forçar HTTPS em todo o site", "area": "Web"},
    "cabecalhos": {"title": "Configurar os cabeçalhos de segurança HTTP", "area": "Web"},
    "cookies": {"title": "Proteger os cookies (Secure, HttpOnly, SameSite)", "area": "Web"},
    "cors": {"title": "Restringir o CORS às origens confiáveis", "area": "Web"},
    "exposicao": {"title": "Remover arquivos sensíveis publicados no servidor web", "area": "Web"},
    "divulgacao": {"title": "Ocultar versões e detalhes internos do servidor", "area": "Web"},
    "debug": {"title": "Desligar depuração e páginas de erro detalhadas", "area": "Web"},
    "metodos": {"title": "Restringir os métodos HTTP aceitos", "area": "Web"},
    "admin": {"title": "Proteger as áreas administrativas", "area": "Web"},
    "cms": {"title": "Endurecer o CMS (WordPress, Joomla, Drupal)", "area": "Web"},
    "conteudo": {
        "title": "Corrigir o conteúdo das páginas (scripts, formulários, segredos)",
        "area": "Web",
    },
    "bibliotecas": {"title": "Atualizar bibliotecas JavaScript vulneráveis", "area": "Web"},
    "tls": {"title": "Modernizar a configuração TLS", "area": "TLS"},
    "certificado": {"title": "Corrigir o certificado digital", "area": "TLS"},
    "email": {
        "title": "Proteger o domínio contra e-mails falsos (SPF, DKIM, DMARC)",
        "area": "DNS",
    },
    "dns": {"title": "Endurecer a configuração de DNS", "area": "DNS"},
    "takeover": {"title": "Remover registros DNS órfãos (sequestro de subdomínio)", "area": "DNS"},
    "servicos": {"title": "Fechar ou restringir serviços expostos", "area": "Rede"},
    "autenticacao": {"title": "Exigir autenticação nos serviços expostos", "area": "Rede"},
    "ssh": {"title": "Endurecer o SSH", "area": "Rede"},
    "atualizacao": {"title": "Atualizar software com vulnerabilidades conhecidas", "area": "Rede"},
    "windows": {"title": "Endurecer a configuração do Windows", "area": "Sistema"},
    "linux": {"title": "Endurecer a configuração do Linux", "area": "Sistema"},
    "sistema": {
        "title": "Manter o sistema operacional com suporte e atualizado",
        "area": "Sistema",
    },
    "dependencias": {"title": "Atualizar dependências vulneráveis do projeto", "area": "Código"},
    "segredos": {"title": "Revogar e remover segredos expostos", "area": "Código"},
    "iac": {"title": "Corrigir a configuração de containers e infraestrutura", "area": "Código"},
    "configuracao": {"title": "Corrigir arquivos de configuração inseguros", "area": "Código"},
    "codigo": {"title": "Corrigir padrões inseguros no código", "area": "Código"},
    "incidente": {"title": "Investigar e conter os indícios de ataque nos logs", "area": "Logs"},
}

_KB: dict[str, KBEntry] = {}


def register(*entries: KBEntry) -> None:
    """Registra entradas na base. ID repetido com conteúdo diferente é erro de autoria."""
    for entry in entries:
        existing = _KB.get(entry.id)
        if existing is not None and existing != entry:
            raise ValueError(f"entrada da base duplicada: {entry.id}")
        if entry.fix_group and entry.fix_group not in FIX_GROUPS:
            raise ValueError(f"{entry.id}: grupo de correção desconhecido '{entry.fix_group}'")
        if entry.effort not in EFFORT_RANK:
            raise ValueError(f"{entry.id}: esforço inválido '{entry.effort}'")
        _KB[entry.id] = entry


def get(entry_id: str) -> KBEntry | None:
    return _KB.get(entry_id)


def require(entry_id: str) -> KBEntry:
    entry = _KB.get(entry_id)
    if entry is None:
        raise KeyError(f"achado sem entrada na base de conhecimento: {entry_id}")
    return entry


def all_entries() -> list[KBEntry]:
    return sorted(_KB.values(), key=lambda e: (e.category.value, e.id))


@dataclass
class KBStats:
    total: int = 0
    by_category: dict[str, int] = field(default_factory=dict)


def stats() -> KBStats:
    result = KBStats(total=len(_KB))
    for entry in _KB.values():
        result.by_category[entry.category.value] = (
            result.by_category.get(entry.category.value, 0) + 1
        )
    return result
