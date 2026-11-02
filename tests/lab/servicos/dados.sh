#!/usr/bin/env bash
# Redis, Memcached, PostgreSQL, MySQL, MongoDB, etcd (todos reais, 127.0.0.1).

# ------------------------------------------------------------------ Redis
start_redis_inseguro() {
  mkdir -p "$DATA/redis-inseguro"
  lab_daemon redis-inseguro "$(env_bin core)/redis-server" --port "$PORT_REDIS_INS" --bind 127.0.0.1 \
    --protected-mode no --dir "$DATA/redis-inseguro" --save "" --appendonly no
  wait_port "$PORT_REDIS_INS" 15 && "$(env_bin core)/redis-cli" -p "$PORT_REDIS_INS" set lab:flag "dado-ficticio-do-lab" >/dev/null
}
start_redis_endurecido() {
  mkdir -p "$DATA/redis-endurecido"
  lab_daemon redis-endurecido "$(env_bin core)/redis-server" --port "$PORT_REDIS_END" --bind 127.0.0.1 \
    --protected-mode yes --requirepass "$LAB_PASS" --dir "$DATA/redis-endurecido" --save "" --appendonly no \
    --rename-command CONFIG "" --rename-command FLUSHALL "" --rename-command FLUSHDB "" --rename-command DEBUG ""
}

# ------------------------------------------------------------------ Memcached
start_memcached_inseguro() {
  deb_env
  # sem autenticacao, UDP habilitado (vetor classico de amplificacao)
  lab_daemon memcached-inseguro "$DEBROOT/usr/bin/memcached" -l 127.0.0.1 -p "$PORT_MEMCACHED_INS" \
    -U "$PORT_MEMCACHED_INS" -m 16 -c 128
}
start_memcached_endurecido() {
  deb_env
  # UDP desligado e SASL ligado (so protocolo binario autenticado)
  export SASL_CONF_PATH="$CONF/sasl"; mkdir -p "$SASL_CONF_PATH"
  printf 'mech_list: plain\n' > "$SASL_CONF_PATH/memcached.conf"
  lab_daemon memcached-endurecido "$DEBROOT/usr/bin/memcached" -l 127.0.0.1 -p "$PORT_MEMCACHED_END" \
    -U 0 -S -m 16 -c 128
}

# ------------------------------------------------------------------ PostgreSQL
_pg_init() {  # modo dir
  local dir="$DATA/postgres-$1" pg; pg="$(env_bin pg)"
  [[ -f "$dir/PG_VERSION" ]] && return 0
  mkdir -p "$dir"; chmod 700 "$dir"
  if [[ "$1" == inseguro ]]; then
    "$pg/initdb" -D "$dir" -U postgres --auth=trust >/dev/null
  else
    printf '%s' "$LAB_PASS" > "$dir.pw"
    "$pg/initdb" -D "$dir" -U postgres --auth-host=scram-sha-256 --auth-local=scram-sha-256 --pwfile="$dir.pw" >/dev/null
    rm -f "$dir.pw"
  fi
}
start_postgres_inseguro() {
  _pg_init inseguro
  local sock="$RUN/sock/pg-ins"; mkdir -p "$sock"
  lab_daemon postgres-inseguro "$(env_bin pg)/postgres" -D "$DATA/postgres-inseguro" -p "$PORT_POSTGRES_INS" \
    -c listen_addresses=127.0.0.1 -c unix_socket_directories="$sock" -c ssl=off -c fsync=off
}
start_postgres_endurecido() {
  _pg_init endurecido
  local sock="$RUN/sock/pg-end"; mkdir -p "$sock"
  lab_daemon postgres-endurecido "$(env_bin pg)/postgres" -D "$DATA/postgres-endurecido" -p "$PORT_POSTGRES_END" \
    -c listen_addresses=127.0.0.1 -c unix_socket_directories="$sock" -c fsync=off \
    -c ssl=on -c ssl_cert_file="$CERTS/ok-cadeia.pem" -c ssl_key_file="$CERTS/ok.key" \
    -c ssl_min_protocol_version=TLSv1.2 -c password_encryption=scram-sha-256 \
    -c log_connections=on
}

# ------------------------------------------------------------------ MySQL
_mysql_init() {  # modo
  local dir="$DATA/mysql-$1" my; my="$(env_bin mysql)"
  [[ -d "$dir/mysql" ]] && return 0
  mkdir -p "$dir"
  "$my/mysqld" --no-defaults --initialize-insecure --datadir="$dir" --basedir="$MAMBA_ROOT_PREFIX/envs/mysql" \
    >"$LOGS/mysql-$1.init.log" 2>&1 || { tail -5 "$LOGS/mysql-$1.init.log" >&2; return 1; }
}
start_mysql_inseguro() {
  _mysql_init inseguro || return 1
  local sock="$RUN/sock/mysql-ins"; mkdir -p "$sock"
  # root sem senha, escuta so em loopback, LOAD DATA LOCAL ligado, sem TLS obrigatorio
  lab_daemon mysql-inseguro "$(env_bin mysql)/mysqld" --no-defaults --datadir="$DATA/mysql-inseguro" \
    --basedir="$MAMBA_ROOT_PREFIX/envs/mysql" --port="$PORT_MYSQL_INS" --bind-address=127.0.0.1 \
    --socket="$sock/m.sock" --mysqlx=OFF --local-infile=1 --pid-file="$sock/m.pid"
}
start_mysql_endurecido() {
  _mysql_init endurecido || return 1
  local sock="$RUN/sock/mysql-end"; mkdir -p "$sock"
  printf "ALTER USER 'root'@'localhost' IDENTIFIED BY '%s';\nDELETE FROM mysql.user WHERE user='';\n" "$LAB_PASS" > "$DATA/mysql-endurecido.init.sql"
  local initfile=()
  [[ -f "$DATA/mysql-endurecido/.senha-definida" ]] || initfile=(--init-file="$DATA/mysql-endurecido.init.sql")
  touch "$DATA/mysql-endurecido/.senha-definida"
  lab_daemon mysql-endurecido "$(env_bin mysql)/mysqld" --no-defaults --datadir="$DATA/mysql-endurecido" \
    --basedir="$MAMBA_ROOT_PREFIX/envs/mysql" --port="$PORT_MYSQL_END" --bind-address=127.0.0.1 \
    --socket="$sock/m.sock" --mysqlx=OFF --local-infile=0 --pid-file="$sock/m.pid" \
    --require-secure-transport=ON --tls-version=TLSv1.2,TLSv1.3 \
    --ssl-ca="$CERTS/ca.pem" --ssl-cert="$CERTS/ok-rsa.pem" --ssl-key="$CERTS/ok-rsa.key" "${initfile[@]}"
}

# ------------------------------------------------------------------ MongoDB
start_mongo_inseguro() {
  mkdir -p "$DATA/mongo-inseguro"
  lab_daemon mongo-inseguro "$(env_bin mongo)/mongod" --dbpath "$DATA/mongo-inseguro" --port "$PORT_MONGO_INS" \
    --bind_ip 127.0.0.1 --noauth --nounixsocket
}
start_mongo_endurecido() {
  mkdir -p "$DATA/mongo-endurecido"
  lab_daemon mongo-endurecido "$(env_bin mongo)/mongod" --dbpath "$DATA/mongo-endurecido" --port "$PORT_MONGO_END" \
    --bind_ip 127.0.0.1 --auth --nounixsocket
  if wait_port "$PORT_MONGO_END" 40 && [[ ! -f "$DATA/mongo-endurecido/.usuario-criado" ]]; then
    # excecao de localhost do proprio MongoDB: cria o primeiro usuario administrador
    lab_python - <<PYEOF && touch "$DATA/mongo-endurecido/.usuario-criado"
from pymongo import MongoClient
c = MongoClient("127.0.0.1", $PORT_MONGO_END, serverSelectionTimeoutMS=8000)
c.admin.command("createUser", "labadmin", pwd="$LAB_PASS", roles=[{"role": "root", "db": "admin"}])
PYEOF
  fi
}

# ------------------------------------------------------------------ etcd
start_etcd_inseguro() {
  local u="http://127.0.0.1"
  lab_daemon etcd-inseguro "$(env_bin core)/etcd" --name ins --data-dir "$DATA/etcd-inseguro" \
    --listen-client-urls "$u:$PORT_ETCD_INS_CLIENT" --advertise-client-urls "$u:$PORT_ETCD_INS_CLIENT" \
    --listen-peer-urls "$u:$PORT_ETCD_INS_PEER" --initial-advertise-peer-urls "$u:$PORT_ETCD_INS_PEER" \
    --initial-cluster "ins=$u:$PORT_ETCD_INS_PEER"
}
start_etcd_endurecido() {
  local u="https://127.0.0.1"
  lab_daemon etcd-endurecido "$(env_bin core)/etcd" --name end --data-dir "$DATA/etcd-endurecido" \
    --listen-client-urls "$u:$PORT_ETCD_END_CLIENT" --advertise-client-urls "$u:$PORT_ETCD_END_CLIENT" \
    --listen-peer-urls "$u:$PORT_ETCD_END_PEER" --initial-advertise-peer-urls "$u:$PORT_ETCD_END_PEER" \
    --initial-cluster "end=$u:$PORT_ETCD_END_PEER" \
    --cert-file "$CERTS/ok.pem" --key-file "$CERTS/ok.key" --client-cert-auth --trusted-ca-file "$CERTS/ca.pem" \
    --peer-cert-file "$CERTS/ok.pem" --peer-key-file "$CERTS/ok.key" --peer-client-cert-auth --peer-trusted-ca-file "$CERTS/ca.pem"
}
