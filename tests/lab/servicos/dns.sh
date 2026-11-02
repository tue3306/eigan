#!/usr/bin/env bash
# DNS (BIND 9 real, pacote Ubuntu extraido) e MQTT (Mosquitto real) em dois modos.

_named_run() {  # modo porta
  deb_env
  local d="$RUN/dns-$1"
  "$DEBROOT/usr/bin/named-checkconf" "$d/named.conf" 2>&1 | head -5 >&2 || true
  lab_daemon "dns-$1" "$DEBROOT/usr/sbin/named" -g -c "$d/named.conf"
}

start_dns_inseguro() {
  local d="$RUN/dns-inseguro"; mkdir -p "$d"
  cat > "$d/named.conf" <<EOF
options {
  directory "$d";
  listen-on port $PORT_DNS_INS { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "$d/named.pid";
  session-keyfile "$d/session.key";
  recursion yes;                       // resolvedor aberto
  allow-recursion { any; };
  allow-query { any; };
  allow-transfer { any; };             // AXFR para qualquer um
  dnssec-validation no;
  // "version" nao e ocultado: version.bind revela o BIND
};
controls { };
zone "lab-inseguro.test" { type primary; file "$d/lab-inseguro.test.zone"; allow-transfer { any; }; };
EOF
  cat > "$d/lab-inseguro.test.zone" <<'EOF'
$TTL 300
@       IN SOA ns1 hostmaster ( 2026110201 3600 600 1209600 300 )
@       IN NS  ns1
ns1     IN A   127.0.0.1
@       IN A   127.0.0.1
www     IN CNAME @
mail    IN A   127.0.0.1
@       IN MX  10 mail
; SPF permissivo: qualquer servidor do mundo pode enviar em nome do dominio
@       IN TXT "v=spf1 +all"
; DMARC existe mas so monitora (p=none) e sem relatorio
_dmarc  IN TXT "v=DMARC1; p=none"
; curinga: qualquer nome resolve
*       IN A   127.0.0.1
; CNAMEs apontando para servicos de terceiros que podem nao existir (candidatos a takeover)
dev     IN CNAME eigan-lab-inexistente.herokuapp.com.
arquivo IN CNAME eigan-lab-inexistente.s3.amazonaws.com.
; endereco privado vazando em DNS publico
intranet IN A  10.10.0.5
; sem CAA, sem DNSSEC, sem MTA-STS, sem TLS-RPT
EOF
  _named_run inseguro
}

start_dns_endurecido() {
  local d="$RUN/dns-endurecido"; mkdir -p "$d/keys"
  local dkim=""
  if command -v openssl >/dev/null; then
    openssl genrsa -out "$d/dkim.key" 2048 2>/dev/null
    dkim="$(openssl rsa -in "$d/dkim.key" -pubout -outform DER 2>/dev/null | base64 -w0)"
  fi
  cat > "$d/named.conf" <<EOF
options {
  directory "$d";
  key-directory "$d/keys";
  listen-on port $PORT_DNS_END { 127.0.0.1; };
  listen-on-v6 { none; };
  pid-file "$d/named.pid";
  session-keyfile "$d/session.key";
  recursion no;
  allow-recursion { none; };
  allow-query { any; };
  allow-transfer { none; };
  version none;
  hostname none;
  server-id none;
  minimal-responses yes;
  rate-limit { responses-per-second 20; };
  dnssec-validation auto;
};
controls { };
zone "lab-endurecido.test" {
  type primary;
  file "$d/lab-endurecido.test.zone";
  allow-transfer { none; };
  dnssec-policy default;
  inline-signing yes;
};
EOF
  cat > "$d/lab-endurecido.test.zone" <<EOF
\$TTL 3600
@       IN SOA ns1 hostmaster ( 2026110201 3600 600 1209600 300 )
@       IN NS  ns1
ns1     IN A   127.0.0.1
@       IN A   127.0.0.1
www     IN CNAME @
mail    IN A   127.0.0.1
@       IN MX  10 mail
@       IN TXT "v=spf1 mx -all"
_dmarc  IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@lab-endurecido.test; adkim=s; aspf=s"
selector1._domainkey IN TXT "v=DKIM1; k=rsa; p=${dkim:0:200}" "${dkim:200:200}" "${dkim:400:200}"
_mta-sts IN TXT "v=STSv1; id=20261102"
_smtp._tls IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@lab-endurecido.test"
@       IN CAA 0 issue "letsencrypt.org"
@       IN CAA 0 issuewild ";"
@       IN CAA 0 iodef "mailto:seguranca@lab-endurecido.test"
EOF
  _named_run endurecido
}

# ------------------------------------------------------------------ MQTT (Mosquitto)
start_mqtt_inseguro() {
  local d="$RUN/mqtt-inseguro"; mkdir -p "$d"; deb_env
  cat > "$d/mosquitto.conf" <<EOF
listener $PORT_MQTT_INS 127.0.0.1
allow_anonymous true
persistence false
log_dest stderr
EOF
  lab_daemon mqtt-inseguro "$DEBROOT/usr/sbin/mosquitto" -c "$d/mosquitto.conf"
}
start_mqtt_endurecido() {
  local d="$RUN/mqtt-endurecido"; mkdir -p "$d"; deb_env
  rm -f "$d/passwd"
  "$DEBROOT/usr/bin/mosquitto_passwd" -b -c "$d/passwd" labuser "$LAB_PASS" 2>/dev/null
  cat > "$d/mosquitto.conf" <<EOF
listener $PORT_MQTT_END 127.0.0.1
allow_anonymous false
password_file $d/passwd
cafile $CERTS/ca.pem
certfile $CERTS/ok-rsa.pem
keyfile $CERTS/ok-rsa.key
tls_version tlsv1.2
persistence false
log_dest stderr
EOF
  lab_daemon mqtt-endurecido "$DEBROOT/usr/sbin/mosquitto" -c "$d/mosquitto.conf"
}
