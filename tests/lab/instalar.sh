#!/usr/bin/env bash
# EIGAN Lab - instalacao idempotente em ~/.eigan-lab (sem root, sem Docker).
#
#   ./instalar.sh            instala tudo que falta
#   ./instalar.sh --forcar   recria os ambientes conda
#
# Fontes (todas oficiais):
#   * micromamba      github.com/mamba-org/micromamba-releases   (binario unico)
#   * conda-forge     nginx, openssh, redis, etcd, postgresql, mysql, mongodb,
#                     python + pyftpdlib + pyopenssl, openjdk  (hashes verificados pelo micromamba)
#   * Ubuntu (apt-get download, SEM root, assinado pelo apt)  apache2, bind9, memcached
#   * Apache Tomcat   downloads.apache.org (sha512 publicado conferido)
#   * PyPI            impacket (SMB)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FORCAR=0; [[ "${1:-}" == "--forcar" ]] && FORCAR=1
TOMCAT_VERSION="${TOMCAT_VERSION:-10.1.61}"
lab_dirs
mkdir -p "$LAB_HOME/bin" "$LAB_HOME/downloads"

# ---------------------------------------------------------------- micromamba
if [[ ! -x "$MM" ]]; then
  log "baixando micromamba (binario unico, GitHub oficial)"
  curl -fsSL -o "$MM.tmp" \
    "https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-linux-64"
  chmod +x "$MM.tmp"; mv "$MM.tmp" "$MM"
fi
log "micromamba $("$MM" --version)"

mkenv() {  # nome pacotes...
  local name="$1"; shift
  local dir="$MAMBA_ROOT_PREFIX/envs/$name"
  if [[ -f "$dir/.eigan-ok" && $FORCAR -eq 0 ]]; then log "ambiente '$name' ja instalado"; return 0; fi
  log "criando ambiente conda '$name': $*"
  rm -rf "$dir"
  "$MM" create -y -q -n "$name" -c conda-forge --override-channels "$@"
  touch "$dir/.eigan-ok"
}

mkenv core   nginx openssh redis-server etcd "python=3.12" pyftpdlib pyopenssl "openjdk=21" openssl
mkenv pg     postgresql
mkenv mysql  mysql
mkenv mongo  mongodb


# ---------------------------------------------------------------- impacket (SMB)
PY="$(env_bin core)/python"
if ! "$PY" -c 'import impacket, pymongo, asynchat' 2>/dev/null; then
  log "instalando impacket (SMB) , pymongo (usuario do Mongo endurecido) e pyasynchat (necessario ao pyftpdlib no Python 3.12) via PyPI"
  "$PY" -m pip install --quiet --disable-pip-version-check impacket pymongo pyasynchat pyasyncore
fi
log "impacket $("$PY" -c 'import importlib.metadata as m; print(m.version("impacket"))')"

# ---------------------------------------------------------------- Tomcat
TC_DIR="$LAB_HOME/tomcat/apache-tomcat-$TOMCAT_VERSION"
if [[ ! -x "$TC_DIR/bin/catalina.sh" ]]; then
  major="${TOMCAT_VERSION%%.*}"
  tgz="apache-tomcat-$TOMCAT_VERSION.tar.gz"
  work="$LAB_HOME/downloads/tomcat-$TOMCAT_VERSION"; rm -rf "$work"; mkdir -p "$work"
  for base in "https://downloads.apache.org/tomcat/tomcat-$major/v$TOMCAT_VERSION/bin" \
              "https://archive.apache.org/dist/tomcat/tomcat-$major/v$TOMCAT_VERSION/bin"; do
    if curl -fsSL -o "$work/$tgz" "$base/$tgz" && curl -fsSL -o "$work/$tgz.sha512" "$base/$tgz.sha512"; then break; fi
    rm -f "$work/$tgz" "$work/$tgz.sha512"
  done
  [[ -f "$work/$tgz" ]] || die "nao consegui baixar o Tomcat $TOMCAT_VERSION"
  (cd "$work" && sha512sum -c "$tgz.sha512") || die "sha512 do Tomcat nao confere"
  mkdir -p "$LAB_HOME/tomcat"; tar -xzf "$work/$tgz" -C "$LAB_HOME/tomcat"
  rm -rf "$work"
fi
log "tomcat $TOMCAT_VERSION em $TC_DIR"
ln -sfn "$TC_DIR" "$LAB_HOME/tomcat/atual"

# ---------------------------------------------------------------- pacotes .deb (sem root)
deb_fetch() {  # pacotes... : baixa o pacote e as dependencias ainda nao instaladas no sistema
  local work="$LAB_HOME/downloads/debs"; mkdir -p "$work"; cd "$work"
  local want=("$@") all dep
  mapfile -t all < <(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
      --no-breaks --no-replaces --no-enhances "${want[@]}" 2>/dev/null | grep -E '^[a-z0-9]' | sort -u)
  local need=()
  for dep in "${all[@]}"; do
    if dpkg -s "$dep" >/dev/null 2>&1; then
      # ja instalado: so baixamos se for um dos pedidos
      [[ " ${want[*]} " == *" $dep "* ]] && need+=("$dep")
    else
      need+=("$dep")
    fi
  done
  # pacotes virtuais nao baixam; ignora silenciosamente
  for dep in "${need[@]}"; do
    ls "${dep}_"*.deb >/dev/null 2>&1 || apt-get download "$dep" >/dev/null 2>&1 || true
  done
  for f in "$work"/*.deb; do dpkg -x "$f" "$DEBROOT"; done
}
if [[ ! -x "$DEBROOT/usr/sbin/apache2" || ! -x "$DEBROOT/usr/sbin/named" || ! -x "$DEBROOT/usr/bin/memcached" || ! -x "$DEBROOT/usr/sbin/mosquitto" || ! -x "$DEBROOT/usr/bin/dig" || $FORCAR -eq 1 ]]; then
  log "baixando pacotes Ubuntu sem root (apt-get download): apache2, bind9, memcached, mosquitto"
  if [[ "$(apt-cache policy apache2 | grep -c 'Candidate: [0-9]')" -eq 0 ]]; then
    sudo -n apt-get update >/dev/null 2>&1 || warn "lista do apt vazia e sem sudo; a instalacao pode falhar"
  fi
  mkdir -p "$DEBROOT"
  deb_fetch apache2 apache2-bin apache2-data apache2-utils bind9 bind9-utils bind9-dnsutils memcached mosquitto
fi
deb_env
for b in usr/sbin/apache2 usr/sbin/named usr/bin/memcached; do
  missing="$(ldd "$DEBROOT/$b" 2>&1 | grep 'not found' || true)"
  [[ -z "$missing" ]] || warn "$b com bibliotecas faltando: $missing"
done

# ---------------------------------------------------------------- resumo
log "versoes instaladas:"
{
  "$(env_bin core)/nginx" -v 2>&1 | head -1
  "$(env_bin core)/sshd" -V 2>&1 | head -1 || true
  "$(env_bin core)/ssh" -V 2>&1 | head -1
  "$(env_bin core)/redis-server" --version | head -1
  "$(env_bin core)/etcd" --version | head -1
  "$(env_bin pg)/postgres" --version
  ls "$(env_bin mysql)" | grep -E '^mysqld$' || true
  "$(env_bin mongo)/mongod" --version 2>&1 | head -1
  "$DEBROOT/usr/sbin/apache2" -v | head -1
  LD_LIBRARY_PATH="$DEBROOT/usr/lib/x86_64-linux-gnu" "$DEBROOT/usr/sbin/named" -V | head -1
  LD_LIBRARY_PATH="$DEBROOT/usr/lib/x86_64-linux-gnu" "$DEBROOT/usr/bin/memcached" -h | head -1
} 2>&1 | sed 's/^/   /'
log "instalacao concluida em $LAB_HOME"
