#!/usr/bin/env bash
# sshd (OpenSSH conda-forge, modo usuario), Tomcat, FTP (pyftpdlib), SMB (impacket).

# ------------------------------------------------------------------ sshd
_sshd_prep() {  # modo
  local d="$CONF/sshd-$1"; mkdir -p "$d"
  local kg; kg="$(env_bin core)/ssh-keygen"
  [[ -f "$d/ed25519" ]] || "$kg" -q -t ed25519 -N "" -f "$d/ed25519" -C "eigan-lab-$1"
  if [[ "$1" == inseguro ]]; then
    [[ -f "$d/rsa" ]] || "$kg" -q -t rsa -b 1024 -N "" -f "$d/rsa" -C "eigan-lab-rsa1024"   # chave de host fraca
    [[ -f "$d/ecdsa" ]] || "$kg" -q -t ecdsa -b 256 -N "" -f "$d/ecdsa" -C "eigan-lab-ecdsa"
  else
    [[ -f "$d/rsa" ]] || "$kg" -q -t rsa -b 3072 -N "" -f "$d/rsa" -C "eigan-lab-rsa3072"
  fi
  printf '%s' "$d"
}

start_sshd_inseguro() {
  local d; d="$(_sshd_prep inseguro)"
  cat > "$d/sshd_config" <<EOF
Port $PORT_SSHD_INS
ListenAddress 127.0.0.1
HostKey $d/rsa
HostKey $d/ecdsa
HostKey $d/ed25519
PidFile $d/sshd.pid
LogLevel VERBOSE
PasswordAuthentication yes
PermitEmptyPasswords yes
PermitRootLogin yes
PubkeyAuthentication yes
ChallengeResponseAuthentication yes
X11Forwarding yes
AllowTcpForwarding yes
AllowAgentForwarding yes
PermitTunnel yes
GatewayPorts yes
MaxAuthTries 10
LoginGraceTime 120
StrictModes no
Banner $d/banner
# algoritmos legados explicitamente habilitados
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc
MACs +hmac-md5,hmac-sha1,hmac-md5-96,hmac-sha1-96
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
EOF
  printf 'Servidor de TESTE do EIGAN (inseguro). Acesso autorizado apenas.\n' > "$d/banner"
  "$(env_bin core)/sshd" -t -f "$d/sshd_config" || return 1
  lab_daemon sshd-inseguro "$(env_bin core)/sshd" -D -e -f "$d/sshd_config"
}

start_sshd_endurecido() {
  local d; d="$(_sshd_prep endurecido)"
  cat > "$d/sshd_config" <<EOF
Port $PORT_SSHD_END
ListenAddress 127.0.0.1
HostKey $d/ed25519
HostKey $d/rsa
PidFile $d/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers $(id -un)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF
  "$(env_bin core)/sshd" -t -f "$d/sshd_config" || return 1
  lab_daemon sshd-endurecido "$(env_bin core)/sshd" -D -e -f "$d/sshd_config"
}

# ------------------------------------------------------------------ Tomcat
_tomcat_prep() {  # modo
  local home="$LAB_HOME/tomcat/atual" base="$RUN/tomcat-$1" j
  [[ -x "$home/bin/catalina.sh" ]] || { warn "Tomcat nao instalado"; return 1; }
  mkdir -p "$base"/{logs,temp,work,conf,webapps}
  cp -f "$home"/conf/{web.xml,catalina.properties,logging.properties,context.xml,tomcat-users.xml} "$base/conf/" 2>/dev/null || true
  j="$MAMBA_ROOT_PREFIX/envs/core/lib/jvm"; [[ -d "$j" ]] || j="$MAMBA_ROOT_PREFIX/envs/core"
  export JAVA_HOME="$j" CATALINA_HOME="$home" CATALINA_BASE="$base" CATALINA_PID="$PIDS/tomcat-$1.catalina.pid"
  export CATALINA_OPTS="-Xms32m -Xmx128m -Djava.net.preferIPv4Stack=true -Djava.security.egd=file:/dev/urandom"
}

start_tomcat_inseguro() {
  _tomcat_prep inseguro || return 1
  local base="$CATALINA_BASE"
  for app in ROOT docs examples manager host-manager; do ln -sfn "$CATALINA_HOME/webapps/$app" "$base/webapps/$app"; done
  cat > "$base/conf/server.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- EIGAN Lab: Tomcat INSEGURO (AJP sem segredo, apps padrao, versao nas paginas de erro) -->
<Server port="$PORT_TOMCAT_INS_SHUTDOWN" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$PORT_TOMCAT_INS_HTTP" address="127.0.0.1" protocol="HTTP/1.1" connectionTimeout="20000" server="Apache-Coyote/1.1" />
    <Connector protocol="AJP/1.3" address="127.0.0.1" port="$PORT_TOMCAT_INS_AJP" secretRequired="false" allowedRequestAttributesPattern=".*" />
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="false" autoDeploy="false" />
    </Engine>
  </Service>
</Server>
EOF
  lab_daemon tomcat-inseguro "$CATALINA_HOME/bin/catalina.sh" run
}

start_tomcat_endurecido() {
  _tomcat_prep endurecido || return 1
  local base="$CATALINA_BASE"
  mkdir -p "$base/webapps/ROOT"
  printf '<!doctype html><title>App Lab (endurecido)</title><h1>App Lab</h1>\n' > "$base/webapps/ROOT/index.html"
  cat > "$base/conf/server.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- EIGAN Lab: Tomcat ENDURECIDO (sem AJP, sem shutdown por rede, sem apps padrao, sem versao nos erros) -->
<Server port="-1" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$PORT_TOMCAT_END_HTTP" address="127.0.0.1" protocol="HTTP/1.1" connectionTimeout="20000" server="" xpoweredBy="false" />
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="false" autoDeploy="false">
        <Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false" />
      </Host>
    </Engine>
  </Service>
</Server>
EOF
  lab_daemon tomcat-endurecido "$CATALINA_HOME/bin/catalina.sh" run
}

# ------------------------------------------------------------------ FTP (pyftpdlib)
start_ftp_inseguro() {
  mkdir -p "$DATA/ftp-publico"; printf 'arquivo publico do lab\n' > "$DATA/ftp-publico/leia-me.txt"
  lab_daemon ftp-inseguro "$(env_bin core)/python" "$LAB_DIR/ferramentas/ftp_server.py" \
    --modo inseguro --porta "$PORT_FTP_INS" --raiz "$DATA/ftp-publico"
}
start_ftp_endurecido() {
  mkdir -p "$DATA/ftp-privado"; printf 'arquivo privado do lab\n' > "$DATA/ftp-privado/leia-me.txt"
  lab_daemon ftp-endurecido "$(env_bin core)/python" "$LAB_DIR/ferramentas/ftp_server.py" \
    --modo endurecido --porta "$PORT_FTP_END" --raiz "$DATA/ftp-privado" \
    --cert "$CERTS/ok-rsa-cadeia.pem" --chave "$CERTS/ok-rsa.key" --senha "$LAB_PASS"
}

# ------------------------------------------------------------------ SMB (impacket)
start_smb_inseguro() {
  mkdir -p "$DATA/smb-publico"; printf 'compartilhamento publico do lab\n' > "$DATA/smb-publico/leia-me.txt"
  lab_daemon smb-inseguro "$(env_bin core)/python" "$LAB_DIR/ferramentas/smb_server.py" \
    --modo inseguro --porta "$PORT_SMB_INS" --raiz "$DATA/smb-publico"
}
start_smb_endurecido() {
  mkdir -p "$DATA/smb-privado"; printf 'compartilhamento privado do lab\n' > "$DATA/smb-privado/leia-me.txt"
  lab_daemon smb-endurecido "$(env_bin core)/python" "$LAB_DIR/ferramentas/smb_server.py" \
    --modo endurecido --porta "$PORT_SMB_END" --raiz "$DATA/smb-privado" --senha "$LAB_PASS"
}
