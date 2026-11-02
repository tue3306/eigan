#!/usr/bin/env bash
# EIGAN Lab - mostra o que esta no ar. Saida: tabela; codigo 0 se tudo esperado estiver no ar.
#   ./status.sh [--json]
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
json=0; [[ "${1:-}" == "--json" ]] && json=1
tot=0; ok=0; out=()
((json)) || printf '%-22s %-9s %-6s %s\n' SERVICO TIPO ESTADO PORTAS
for entry in "${LAB_SERVICES[@]}"; do
  IFS='|' read -r id vars tipo <<<"$entry"
  tot=$((tot+1)); estado="parado"; ps=""; abertas=0; todas=0
  for v in $vars; do
    p="${!v}"; todas=$((todas+1))
    if tcp_open 127.0.0.1 "$p"; then abertas=$((abertas+1)); ps+="$p+ "; else ps+="$p- "; fi
  done
  if ((abertas == todas)); then estado="no ar"; ok=$((ok+1)); elif ((abertas > 0)); then estado="parcial"; fi
  if ((json)); then out+=("{\"servico\":\"$id\",\"tipo\":\"$tipo\",\"estado\":\"$estado\",\"portas\":\"${ps% }\"}")
  else printf '%-22s %-9s %-6s %s\n' "$id" "$tipo" "$estado" "$ps"; fi
done
if ((json)); then (IFS=,; echo "[${out[*]}]"); else echo "--- $ok/$tot no ar (+ aberta, - fechada)"; fi
((ok == tot))
