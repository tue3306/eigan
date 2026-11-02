#!/usr/bin/env python3
"""Confere catalogo.json x portas.env x lib.sh x verificar.py (sem subir nada).

Falha (codigo 1) se: houver porta do catalogo ausente do portas.env, porta publica do portas.env
sem entrada no catalogo, porta repetida, processo do catalogo desconhecido pelo subir.sh, ou
alvo estatico apontando para arquivo inexistente.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
RAIZ_REPO = LAB.parent.parent
INTERNAS = {
    "PORT_TOMCAT_INS_SHUTDOWN",
    "PORT_TOMCAT_END_SHUTDOWN",
    "PORT_ETCD_INS_PEER",
    "PORT_ETCD_END_PEER",
}


def main() -> int:
    erros: list[str] = []
    portas = {
        m.group(1): int(m.group(2))
        for ln in (LAB / "portas.env").read_text(encoding="utf-8").splitlines()
        if (m := re.match(r"(PORT_\w+)=(\d+)", ln.strip()))
    }
    valores = list(portas.values())
    for v in {x for x in valores if valores.count(x) > 1}:
        erros.append(f"porta repetida em portas.env: {v}")
    cat = json.loads((LAB / "catalogo.json").read_text(encoding="utf-8"))
    usadas = set()
    lib = (LAB / "lib.sh").read_text(encoding="utf-8")
    ids_lib = set(re.findall(r'^\s*"([a-z0-9-]+)\|', lib, re.M))
    for s in cat["servicos"]:
        var = s["porta_var"]
        usadas.add(var)
        if portas.get(var) != s["porta"]:
            erros.append(
                f"{s['id']}: porta {s['porta']} difere de portas.env ({var}={portas.get(var)})"
            )
        if s["processo"] not in ids_lib:
            erros.append(f"{s['id']}: processo '{s['processo']}' nao existe em lib.sh")
        if s["modo"] not in ("inseguro", "endurecido") or s["tipo"] not in ("real", "simulado"):
            erros.append(f"{s['id']}: modo/tipo invalido")
        if s["modo"] == "inseguro" and not s["falhas_plantadas"]:
            erros.append(f"{s['id']}: inseguro sem falhas_plantadas")
        if s["modo"] == "endurecido" and s["falhas_plantadas"]:
            erros.append(f"{s['id']}: endurecido com falhas_plantadas")
    for var in portas:
        if var not in usadas and var not in INTERNAS:
            erros.append(f"{var} esta em portas.env mas nao no catalogo")
    ids = [s["id"] for s in cat["servicos"]]
    for i in {x for x in ids if ids.count(x) > 1}:
        erros.append(f"id repetido: {i}")
    for a in cat["alvos_estaticos"]:
        if a["tipo"] != "segredos-falsos-gerados" and not (RAIZ_REPO / a["caminho"]).exists():
            erros.append(f"alvo ausente: {a['caminho']}")
    for e in erros:
        print("ERRO:", e)
    print(
        f"catalogo: {len(cat['servicos'])} servicos, {len(cat['alvos_estaticos'])} alvos, {len(erros)} erro(s)"
    )
    return 1 if erros else 0


if __name__ == "__main__":
    sys.exit(main())
