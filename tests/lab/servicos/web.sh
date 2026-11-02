#!/usr/bin/env bash
# nginx (conda-forge) e Apache httpd (pacote Ubuntu extraido) em dois modos.
# Carregado por subir.sh; usa as funcoes de lib.sh.

NGINX_BIN() { printf '%s/nginx' "$(env_bin core)"; }
NGINX_MIME() { printf '%s/etc/nginx/mime.types' "$MAMBA_ROOT_PREFIX/envs/core"; }

_www_pronto() {
  [[ -d "$WWW/inseguro" ]] || lab_python "$LAB_DIR/ferramentas/gerar_www.py" "$WWW" >/dev/null
}

_nginx_base() {  # nome -> cabecalho comum da configuracao (escreve em stdout)
  local n="$1" d="$RUN/nginx-$1"
  mkdir -p "$d/tmp"
  cat <<EOF
worker_processes 1;
daemon off;
pid $d/nginx.pid;
error_log $LOGS/nginx-$n.error.log warn;
events { worker_connections 128; }
http {
  include $(NGINX_MIME);
  access_log $LOGS/nginx-$n.access.log;
  client_body_temp_path $d/tmp/body; proxy_temp_path $d/tmp/proxy;
  fastcgi_temp_path $d/tmp/fcgi; uwsgi_temp_path $d/tmp/uwsgi; scgi_temp_path $d/tmp/scgi;
  default_type text/plain;
EOF
}

start_nginx_inseguro() {
  _www_pronto
  local c="$CONF/nginx-inseguro.conf" r="$WWW/inseguro"
  {
    _nginx_base inseguro
    cat <<EOF
  server_tokens on;
  autoindex on;

  # --- HTTP simples: sem cabecalhos de seguranca, listagem, arquivos sensiveis ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_HTTP;
    server_name localhost;
    root $r;
    add_header Set-Cookie "PHPSESSID=lab0123456789abcdef0123456789; path=/" always;
    location = /actuator { alias $r/actuator/index.json; default_type application/json; }
    location /actuator/ { default_type application/json; }
    location = /nginx_status { stub_status; }
    location /api/ {
      add_header Access-Control-Allow-Origin \$http_origin always;
      add_header Access-Control-Allow-Credentials true always;
      default_type application/json;
      return 200 '{"ok":true,"lab":"inseguro"}';
    }
  }

  # --- TLS legado: TLS 1.0/1.1 e cifras fracas (CBC-SHA, sem sigilo perfeito) ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_TLS_LEGADO ssl;
    server_name localhost;
    root $r;
    ssl_certificate $CERTS/ok-rsa-cadeia.pem;
    ssl_certificate_key $CERTS/ok-rsa.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers 'ALL:@SECLEVEL=0';
    ssl_prefer_server_ciphers on;
  }
  # --- certificado expirado (so isso de errado) ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_TLS_EXPIRADO ssl;
    server_name localhost;
    root $r;
    ssl_certificate $CERTS/expirado-cadeia.pem;
    ssl_certificate_key $CERTS/expirado.key;
    ssl_protocols TLSv1.2 TLSv1.3;
  }
  # --- certificado autoassinado ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_TLS_AUTOASSINADO ssl;
    server_name localhost;
    root $r;
    ssl_certificate $CERTS/autoassinado.pem;
    ssl_certificate_key $CERTS/autoassinado.key;
    ssl_protocols TLSv1.2 TLSv1.3;
  }
  # --- certificado emitido para outro nome ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_TLS_HOSTERRADO ssl;
    server_name localhost;
    root $r;
    ssl_certificate $CERTS/hosterrado-cadeia.pem;
    ssl_certificate_key $CERTS/hosterrado.key;
    ssl_protocols TLSv1.2 TLSv1.3;
  }
  # --- SPA que responde 200 para tudo (nao pode gerar achados de exposicao) ---
  server {
    listen 127.0.0.1:$PORT_NGINX_INS_SOFT404;
    server_name localhost;
    root $WWW/soft404;
    server_tokens off;
    autoindex off;
    location / { try_files /index.html =404; }
  }
}
EOF
  } > "$c"
  "$(NGINX_BIN)" -t -c "$c" -p "$RUN/nginx-inseguro" 2>&1 | tail -2 >&2
  lab_daemon nginx-inseguro "$(NGINX_BIN)" -c "$c" -p "$RUN/nginx-inseguro"
}

start_nginx_endurecido() {
  _www_pronto
  local c="$CONF/nginx-endurecido.conf" r="$WWW/endurecido"
  {
    _nginx_base endurecido
    cat <<EOF
  server_tokens off;
  autoindex off;
  server {
    listen 127.0.0.1:$PORT_NGINX_END_HTTP;
    server_name localhost;
    return 301 https://localhost:$PORT_NGINX_END_TLS\$request_uri;
  }
  server {
    listen 127.0.0.1:$PORT_NGINX_END_TLS ssl;
    http2 on;
    server_name localhost;
    root $r;
    ssl_certificate $CERTS/ok-cadeia.pem;
    ssl_certificate_key $CERTS/ok.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:LABSSL:1m;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Set-Cookie "sid=lab0123456789abcdef; Path=/; Secure; HttpOnly; SameSite=Strict" always;

    if (\$request_method !~ ^(GET|HEAD|POST|OPTIONS)\$) { return 405; }
    error_page 404 /404.html;
    location ~ /\.(?!well-known) { return 404; }
    location / { try_files \$uri \$uri/ =404; }
    location = /nginx_status { return 404; }
  }
}
EOF
  } > "$c"
  "$(NGINX_BIN)" -t -c "$c" -p "$RUN/nginx-endurecido" 2>&1 | tail -2 >&2
  lab_daemon nginx-endurecido "$(NGINX_BIN)" -c "$c" -p "$RUN/nginx-endurecido"
}

# ------------------------------------------------------------------ Apache httpd
_apache_modules() {
  local m
  for m in "$@"; do
    printf 'LoadModule %s_module %s/usr/lib/apache2/modules/mod_%s.so\n' "$m" "$DEBROOT" "$m"
  done
}

_apache_base() {  # nome porta-http porta-tls
  local n="$1" d="$RUN/apache-$1"
  mkdir -p "$d/run"
  printf 'text/html html
text/plain txt
application/json json
application/xml xml
' > "$d/mime.types"
  cat <<EOF
TypesConfig "$d/mime.types"
ServerRoot "$d"
ServerName localhost
PidFile "$d/apache.pid"
DefaultRuntimeDir "$d/run"
Mutex file:$d/run default
ErrorLog "$LOGS/apache-$n.error.log"
LogLevel warn
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog "$LOGS/apache-$n.access.log" combined
Listen 127.0.0.1:$2
Listen 127.0.0.1:$3
$(_apache_modules mpm_event authz_core authz_host dir mime alias autoindex headers setenvif access_compat allowmethods socache_shmcb ssl status info)
StartServers 1
ThreadsPerChild 8
MinSpareThreads 4
MaxSpareThreads 8
ServerLimit 2
MaxRequestWorkers 16
AddType text/html .html
AddType text/plain .txt .log .sql .env
AddType application/json .json
AddType application/xml .xml
DirectoryIndex index.html
<Directory />
  AllowOverride None
  Require all denied
</Directory>
EOF
}

start_apache_inseguro() {
  _www_pronto; deb_env
  local c="$CONF/apache-inseguro.conf" r="$WWW/inseguro"
  {
    _apache_base inseguro "$PORT_APACHE_INS_HTTP" "$PORT_APACHE_INS_TLS"
    cat <<EOF
ServerTokens Full
ServerSignature On
TraceEnable On
FileETag All
DocumentRoot "$r"
<Directory "$r">
  Options Indexes FollowSymLinks
  Require all granted
</Directory>
AliasMatch "^/actuator$" "$r/actuator/index.json"
<Location "/actuator">
  ForceType application/json
  Require all granted
</Location>
<Location "/server-status">
  SetHandler server-status
  Require all granted
</Location>
<Location "/server-info">
  SetHandler server-info
  Require all granted
</Location>
# CORS que espelha qualquer Origin, com credenciais
SetEnvIfNoCase Origin "(.+)" CORS_ORIGIN=\$1
Header always set Access-Control-Allow-Origin "%{CORS_ORIGIN}e" env=CORS_ORIGIN
Header always set Access-Control-Allow-Credentials "true" env=CORS_ORIGIN
# Cookie sem Secure/HttpOnly/SameSite
Header always add Set-Cookie "JSESSIONID=lab0123456789abcdef; path=/"
<VirtualHost 127.0.0.1:$PORT_APACHE_INS_TLS>
  SSLEngine on
  SSLCertificateFile "$CERTS/ok-rsa.pem"
  SSLCertificateKeyFile "$CERTS/ok-rsa.key"
  SSLCertificateChainFile "$CERTS/ca.pem"
  SSLProtocol all +TLSv1 +TLSv1.1
  SSLCipherSuite "ALL:@SECLEVEL=0"
  SSLHonorCipherOrder on
</VirtualHost>
EOF
  } > "$c"
  "$DEBROOT/usr/sbin/apache2" -t -f "$c" -d "$RUN/apache-inseguro" 2>&1 | tail -3 >&2
  lab_daemon apache-inseguro "$DEBROOT/usr/sbin/apache2" -D FOREGROUND -f "$c" -d "$RUN/apache-inseguro"
}

start_apache_endurecido() {
  _www_pronto; deb_env
  local c="$CONF/apache-endurecido.conf" r="$WWW/endurecido"
  {
    _apache_base endurecido "$PORT_APACHE_END_HTTP" "$PORT_APACHE_END_TLS"
    cat <<EOF
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag MTime Size
DocumentRoot "$r"
<Directory "$r">
  Options None
  Require all granted
  <LimitExcept GET POST HEAD OPTIONS>
    Require all denied
  </LimitExcept>
</Directory>
<FilesMatch "^\.(?!well-known)">
  Require all denied
</FilesMatch>
<VirtualHost 127.0.0.1:$PORT_APACHE_END_HTTP>
  Redirect permanent / https://localhost:$PORT_APACHE_END_TLS/
</VirtualHost>
<VirtualHost 127.0.0.1:$PORT_APACHE_END_TLS>
  SSLEngine on
  SSLCertificateFile "$CERTS/ok.pem"
  SSLCertificateKeyFile "$CERTS/ok.key"
  SSLCertificateChainFile "$CERTS/ca.pem"
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305
  SSLHonorCipherOrder off
  SSLSessionTickets off
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
  Header always set Cross-Origin-Resource-Policy "same-origin"
  Header always add Set-Cookie "sid=lab0123456789abcdef; Path=/; Secure; HttpOnly; SameSite=Strict"
</VirtualHost>
EOF
  } > "$c"
  "$DEBROOT/usr/sbin/apache2" -t -f "$c" -d "$RUN/apache-endurecido" 2>&1 | tail -3 >&2
  lab_daemon apache-endurecido "$DEBROOT/usr/sbin/apache2" -D FOREGROUND -f "$c" -d "$RUN/apache-endurecido"
}
