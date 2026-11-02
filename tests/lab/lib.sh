#!/usr/bin/env bash
# EIGAN Lab - funcoes comuns. Use com:  source "$(dirname "$0")/lib.sh"
# Nada aqui exige root. Tudo mora em $LAB_HOME (padrao ~/.eigan-lab), fora do repositorio.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_HOME="${EIGAN_LAB_HOME:-$HOME/.eigan-lab}"
export LAB_DIR LAB_HOME
export MAMBA_ROOT_PREFIX="$LAB_HOME/mamba"
MM="$LAB_HOME/bin/micromamba"
RUN="$LAB_HOME/run"
LOGS="$RUN/logs"; PIDS="$RUN/pids"; CERTS="$RUN/certs"; DATA="$RUN/data"; CONF="$RUN/conf"; WWW="$RUN/www"
DEBROOT="$LAB_HOME/debroot"
export RUN LOGS PIDS CERTS DATA CONF WWW DEBROOT

set -a
# shellcheck source=portas.env
. "$LAB_DIR/portas.env"
set +a

# Servicos conhecidos, na ordem de subida. Cada <id> chama a funcao start_<id com _>.
# Formato: id|variaveis de porta (principal primeiro)|tipo (real|simulado)
LAB_SERVICES=(
  "nginx-inseguro|PORT_NGINX_INS_HTTP PORT_NGINX_INS_TLS_LEGADO PORT_NGINX_INS_TLS_EXPIRADO PORT_NGINX_INS_TLS_AUTOASSINADO PORT_NGINX_INS_TLS_HOSTERRADO PORT_NGINX_INS_SOFT404|real"
  "nginx-endurecido|PORT_NGINX_END_HTTP PORT_NGINX_END_TLS|real"
  "apache-inseguro|PORT_APACHE_INS_HTTP PORT_APACHE_INS_TLS|real"
  "apache-endurecido|PORT_APACHE_END_HTTP PORT_APACHE_END_TLS|real"
  "tomcat-inseguro|PORT_TOMCAT_INS_HTTP PORT_TOMCAT_INS_AJP|real"
  "tomcat-endurecido|PORT_TOMCAT_END_HTTP|real"
  "sshd-inseguro|PORT_SSHD_INS|real"
  "sshd-endurecido|PORT_SSHD_END|real"
  "redis-inseguro|PORT_REDIS_INS|real"
  "redis-endurecido|PORT_REDIS_END|real"
  "memcached-inseguro|PORT_MEMCACHED_INS|real"
  "memcached-endurecido|PORT_MEMCACHED_END|real"
  "postgres-inseguro|PORT_POSTGRES_INS|real"
  "postgres-endurecido|PORT_POSTGRES_END|real"
  "mysql-inseguro|PORT_MYSQL_INS|real"
  "mysql-endurecido|PORT_MYSQL_END|real"
  "mongo-inseguro|PORT_MONGO_INS|real"
  "mongo-endurecido|PORT_MONGO_END|real"
  "etcd-inseguro|PORT_ETCD_INS_CLIENT|real"
  "etcd-endurecido|PORT_ETCD_END_CLIENT|real"
  "ftp-inseguro|PORT_FTP_INS|real"
  "ftp-endurecido|PORT_FTP_END|real"
  "smb-inseguro|PORT_SMB_INS|real"
  "smb-endurecido|PORT_SMB_END|real"
  "dns-inseguro|PORT_DNS_INS|real"
  "dns-endurecido|PORT_DNS_END|real"
  "mqtt-inseguro|PORT_MQTT_INS|real"
  "mqtt-endurecido|PORT_MQTT_END|real"
  "sim-rdp|PORT_SIM_RDP_INS PORT_SIM_RDP_END|simulado"
  "sim-mssql|PORT_SIM_MSSQL_INS PORT_SIM_MSSQL_END|simulado"
  "sim-vnc|PORT_SIM_VNC_INS PORT_SIM_VNC_END|simulado"
  "sim-docker|PORT_SIM_DOCKER_INS PORT_SIM_DOCKER_END|simulado"
  "sim-k8s|PORT_SIM_K8S_INS PORT_SIM_K8S_END|simulado"
  "sim-telnet|PORT_SIM_TELNET_INS|simulado"
  "sim-smtp|PORT_SIM_SMTP_INS PORT_SIM_SMTP_END|simulado"
  "sim-elastic|PORT_SIM_ELASTIC_INS PORT_SIM_ELASTIC_END|simulado"
  "sim-winrm|PORT_SIM_WINRM_INS|simulado"
  "sim-banners|PORT_BANNER_HTTP_APACHE PORT_BANNER_HTTP_NGINX PORT_BANNER_FTP_VSFTPD PORT_BANNER_FTP_PROFTPD PORT_BANNER_SSH_OLD PORT_BANNER_SMTP_EXIM PORT_BANNER_SMTP_POSTFIX PORT_BANNER_MYSQL_OLD PORT_BANNER_REDIS_OLD|simulado"
)

log()  { printf '\033[1;36m[lab]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[lab] aviso:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[lab] erro:\033[0m %s\n' "$*" >&2; exit 1; }

lab_dirs() { mkdir -p "$LOGS" "$PIDS" "$CERTS" "$DATA" "$CONF" "$WWW"; }

env_bin() { printf '%s/envs/%s/bin' "$MAMBA_ROOT_PREFIX" "$1"; }
lab_python() { "$(env_bin core)/python" "$@"; }

# Bibliotecas dos pacotes .deb extraidos (apache2, bind9, memcached).
deb_env() { export LD_LIBRARY_PATH="$DEBROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; }

svc_fn() { printf 'start_%s' "${1//-/_}"; }

lab_running() {  # $1=id
  local pf="$PIDS/$1.pid"
  [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

# Sobe um processo em primeiro plano como daemon: lab_daemon <id> <cmd...>
lab_daemon() {
  local id="$1"; shift
  lab_dirs
  if lab_running "$id"; then log "$id ja esta rodando (pid $(cat "$PIDS/$id.pid"))"; return 0; fi
  setsid nohup "$@" >"$LOGS/$id.log" 2>&1 < /dev/null &
  echo $! > "$PIDS/$id.pid"
}

lab_stop() {  # $1=id
  local pf="$PIDS/$1.pid" pid
  [[ -f "$pf" ]] || return 0
  pid="$(cat "$pf")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
    kill -0 "$pid" 2>/dev/null && { kill -9 -- "-$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true; }
  fi
  rm -f "$pf"
}

tcp_open() {  # host port
  (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && return 0 || return 1
}

wait_port() {  # port [segundos]
  local port="$1" t="${2:-30}" i
  for i in $(seq 1 $((t * 4))); do
    tcp_open 127.0.0.1 "$port" && return 0
    sleep 0.25
  done
  return 1
}

ports_of() {  # id -> lista de numeros de porta
  local entry id vars v
  for entry in "${LAB_SERVICES[@]}"; do
    IFS='|' read -r id vars _ <<<"$entry"
    [[ "$id" == "$1" ]] || continue
    for v in $vars; do printf '%s ' "${!v}"; done
    return 0
  done
}

# Servicos que so falam UDP (a porta TCP nao abre).
UDP_ONLY=" mqtt-nenhum "

require_tool() {  # caminho  dica
  [[ -x "$1" ]] || die "ferramenta ausente: $1  (rode tests/lab/instalar.sh)"
}

# Senha FALSA usada pelos servicos endurecidos que exigem autenticacao (valor de laboratorio, nao e segredo).
LAB_PASS="${LAB_PASS:-Lab-Endurecido-9xK2mQ4v}"
export LAB_PASS
