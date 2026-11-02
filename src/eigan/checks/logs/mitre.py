"""Técnicas do MITRE ATT&CK citadas pela análise de logs (versão v20, outubro de 2026).

Os nomes foram conferidos em https://attack.mitre.org/techniques/enterprise/. Atenção à
limpeza de logs: na v20 ela deixou de ser T1070.001 (o T1070 não lista mais essa
subtécnica) e passou a ser T1685.005, dentro de "Disable or Modify Tools".
"""

from __future__ import annotations

from collections.abc import Iterable

TECNICAS: dict[str, str] = {
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.004": "Remote Services: SSH",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1098": "Account Manipulation",
    "T1098.007": "Account Manipulation: Additional Local or Domain Groups",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1136.002": "Create Account: Domain Account",
    "T1190": "Exploit Public-Facing Application",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1505.003": "Server Software Component: Web Shell",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1552": "Unsecured Credentials",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1569.002": "System Services: Service Execution",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
    "T1685.005": "Disable or Modify Tools: Clear Windows Event Logs",
}


def url(tecnica: str) -> str:
    """Endereço da técnica no site do ATT&CK."""
    return f"https://attack.mitre.org/techniques/{tecnica.replace('.', '/')}/"


def detalhes(tecnicas: Iterable[str]) -> list[dict[str, str]]:
    """Técnicas como dados estruturados para ``Finding.details``."""
    return [{"id": t, "nome": TECNICAS[t], "url": url(t)} for t in tecnicas]


def texto(tecnicas: Iterable[str]) -> str:
    """Técnicas em uma linha, para a evidência do achado."""
    return "; ".join(f"{t} ({TECNICAS[t]})" for t in tecnicas)
