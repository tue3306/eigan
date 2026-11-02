#!/usr/bin/env bash
# EIGAN Lab - gera TODOS os certificados de teste em $RUN/certs (nunca versionados).
# Usa so o openssl do sistema (3.x). Idempotente: use --forcar para regerar.
#
#   ok            valido, SAN localhost/127.0.0.1, ECDSA P-256, sha256, 90 dias (CA do laboratorio)
#   ok-rsa        valido, RSA 3072, sha256, 90 dias (para servicos que preferem RSA)
#   expirado      emitido pela CA, validade 2020-01-01 a 2020-04-01
#   autoassinado  sem CA: emissor == titular
#   hosterrado    valido, mas SAN/CN = site-errado.example.test (nao cobre localhost)
#   fraco         RSA 1024 + SHA-1 + validade de 10 anos (pior caso)
#   cliente       certificado de cliente (etcd/mongo mTLS)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
lab_dirs
cd "$CERTS"
[[ "${1:-}" == "--forcar" ]] && rm -f ./*.pem ./*.key ./*.csr ./*.srl index.txt* serial* ca.cnf

if [[ -f ok.pem && -f expirado.pem && -f fraco.pem ]]; then log "certificados ja existem em $CERTS"; exit 0; fi

cat > ca.cnf <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $CERTS
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
default_md = sha256
policy = policy_any
unique_subject = no
copy_extensions = none
[ policy_any ]
commonName = supplied
CNF
: > index.txt; echo 1000 > serial

openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 \
  -subj "/O=EIGAN Lab (TESTE)/CN=EIGAN Lab CA (TESTE)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca.key -out ca.pem 2>/dev/null

emitir() {  # nome  CN  SAN  keyspec  md  [datas do openssl ca...]
  local nome="$1" cn="$2" san="$3" keyspec="$4" md="$5"; shift 5
  if [[ "$keyspec" == ec ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$nome.key" 2>/dev/null
  else
    openssl genrsa -out "$nome.key" "$keyspec" 2>/dev/null
  fi
  openssl req -new -key "$nome.key" -subj "/O=EIGAN Lab (TESTE)/CN=$cn" -out "$nome.csr" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$san" > "$nome.ext"
  openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -md "$md" \
    -in "$nome.csr" -out "$nome.crt" -extfile "$nome.ext" -notext "$@" >/dev/null 2>&1
  openssl x509 -in "$nome.crt" -out "$nome.pem"
  cat "$nome.pem" ca.pem > "$nome-cadeia.pem"
  rm -f "$nome.crt" "$nome.csr" "$nome.ext"
}

SAN_LOCAL="DNS:localhost,IP:127.0.0.1"
emitir ok         localhost                 "$SAN_LOCAL"                  ec   sha256 -days 90
emitir ok-rsa     localhost                 "$SAN_LOCAL"                  3072 sha256 -days 90
emitir expirado   localhost                 "$SAN_LOCAL"                  2048 sha256 -startdate 20200101000000Z -enddate 20200401000000Z
emitir hosterrado site-errado.example.test  "DNS:site-errado.example.test" 2048 sha256 -days 90
emitir fraco      localhost                 "$SAN_LOCAL"                  1024 sha1   -days 3650
emitir cliente    eigan-lab-cliente         "DNS:eigan-lab-cliente"       ec   sha256 -days 90

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -sha256 -subj "/O=EIGAN Lab (TESTE)/CN=localhost" \
  -addext "subjectAltName=$SAN_LOCAL" -keyout autoassinado.key -out autoassinado.pem 2>/dev/null

# parametros DH fixos pequenos nao sao usados de proposito (cifras ECDHE bastam); ver README.
chmod 600 ./*.key
log "certificados gerados em $CERTS:"
for f in ok ok-rsa expirado autoassinado hosterrado fraco cliente; do
  printf '   %-13s %s\n' "$f" "$(openssl x509 -in "$f.pem" -noout -subject -enddate -sigalg 2>/dev/null | tr '\n' ' ' | sed 's/Signature Algorithm: //')"
done
