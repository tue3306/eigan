#!/usr/bin/env bash
# EIGAN Lab - sobe os servicos (todos em 127.0.0.1, portas em portas.env).
#   ./subir.sh                  sobe tudo
#   ./subir.sh nginx-inseguro redis-endurecido   sobe so esses
#   ./subir.sh --real | --simulado | --inseguro | --endurecido   filtros
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
lab_dirs
for f in "$LAB_DIR"/servicos/*.sh; do source "$f"; done

[[ -x "$MM" ]] || die "laboratorio nao instalado. Rode: tests/lab/instalar.sh"
"$LAB_DIR/gerar_certs.sh" >/dev/null || die "falha ao gerar certificados"
[[ -d "$LAB_DIR/alvos/projeto-vulneravel" ]] || lab_python "$LAB_DIR/ferramentas/gerar_alvos.py" >/dev/null
[[ -d "$LAB_DIR/alvos/_gerado/segredos" ]] || lab_python "$LAB_DIR/ferramentas/gerar_alvos.py" --segredos >/dev/null
[[ -d "$LAB_DIR/alvos/logs" ]] || lab_python "$LAB_DIR/ferramentas/gerar_logs.py" >/dev/null

want=(); filtro=""
for a in "$@"; do
  case "$a" in
    --real) filtro="real" ;; --simulado) filtro="simulado" ;;
    --inseguro) filtro="inseguro" ;; --endurecido) filtro="endurecido" ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) want+=("$a") ;;
  esac
done

falhas=0; subidos=0
for entry in "${LAB_SERVICES[@]}"; do
  IFS='|' read -r id vars tipo <<<"$entry"
  if ((${#want[@]})); then [[ " ${want[*]} " == *" $id "* ]] || continue; fi
  case "$filtro" in
    real|simulado) [[ "$tipo" == "$filtro" ]] || continue ;;
    inseguro|endurecido) [[ "$id" == *"$filtro" ]] || continue ;;
  esac
  fn="$(svc_fn "$id")"
  if ! declare -F "$fn" >/dev/null; then warn "$id: sem funcao $fn (ainda nao implementado)"; continue; fi
  log "subindo $id ($tipo)"
  if ! "$fn"; then warn "$id: falhou ao iniciar (veja $LOGS/$id.log)"; falhas=$((falhas+1)); continue; fi
  first="$(ports_of "$id" | awk '{print $1}')"
  if [[ -n "$first" ]] && ! wait_port "$first" 40; then
    warn "$id: porta $first nao abriu (veja $LOGS/$id.log)"; falhas=$((falhas+1))
  else
    subidos=$((subidos+1))
  fi
done
log "$subidos servico(s) no ar, $falhas falha(s). Portas: $LAB_DIR/portas.env  |  logs: $LOGS"
exit $((falhas > 0 ? 1 : 0))
