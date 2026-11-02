#!/usr/bin/env bash
# EIGAN Lab - para tudo que o subir.sh iniciou (pelos pidfiles). Dados em ~/.eigan-lab/run sao mantidos;
# use ./parar.sh --limpar para apagar tambem dados e configuracoes geradas (certificados incluidos).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
n=0
if [[ -d "$PIDS" ]]; then
  for pf in "$PIDS"/*.pid; do
    [[ -e "$pf" ]] || continue
    id="$(basename "$pf" .pid)"
    lab_stop "$id"; log "parado: $id"; n=$((n+1))
  done
fi
# varredura final: qualquer processo cujo binario esteja dentro de $LAB_HOME
for p in $(pgrep -f "$LAB_HOME/(mamba|debroot|tomcat)|$LAB_DIR/simuladores" 2>/dev/null); do
  [[ "$p" == "$$" ]] && continue
  kill "$p" 2>/dev/null || true
done
[[ "${1:-}" == "--limpar" ]] && { rm -rf "$RUN"; log "run/ apagado"; }
log "$n servico(s) parado(s)."
