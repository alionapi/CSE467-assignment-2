#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "[*] Generating Root CA for proxy..."
openssl genrsa -out ca_proxy.key 2048

openssl req -x509 -new -nodes \
  -key ca_proxy.key \
  -sha256 -days 3650 \
  -out ca_proxy.pem \
  -subj "/C=KR/ST=Ulsan/L=Unistgil/O=Demo Org/OU=Demo Unit/CN=Demo Root CA Proxy"

echo "[*] Generating Root CA for server..."
openssl genrsa -out ca_server.key 2048

openssl req -x509 -new -nodes \
  -key ca_server.key \
  -sha256 -days 3650 \
  -out ca_server.pem \
  -subj "/C=KR/ST=Ulsan/L=Unistgil/O=Demo Org/OU=Demo Unit/CN=Demo Root CA Server"

cat > leaf_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:demo.local
EOF

SUBJ="/C=KR/ST=Ulsan/L=Unistgil/O=Demo Service/OU=Endpoint/CN=demo.local"

echo "[*] Generating proxy key and CSR..."
openssl genrsa -out proxy.key 2048
openssl req -new -key proxy.key -out proxy.csr -subj "${SUBJ}"

echo "[*] Signing proxy certificate with proxy CA..."
openssl x509 -req -in proxy.csr \
  -CA ca_proxy.pem -CAkey ca_proxy.key -CAcreateserial \
  -out proxy.crt -days 825 -sha256 -extfile leaf_ext.cnf

echo "[*] Generating server key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "${SUBJ}"

echo "[*] Signing server certificate with server CA..."
openssl x509 -req -in server.csr \
  -CA ca_server.pem -CAkey ca_server.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile leaf_ext.cnf

echo "[*] Creating CA bundle for client..."
cat ca_proxy.pem ca_server.pem > ca_bundle.pem

echo "[*] Verifying subjects..."
echo "---- proxy subject ----"
openssl x509 -in proxy.crt -noout -subject
echo "---- server subject ----"
openssl x509 -in server.crt -noout -subject

echo "[*] Verifying issuers..."
echo "---- proxy issuer ----"
openssl x509 -in proxy.crt -noout -issuer
echo "---- server issuer ----"
openssl x509 -in server.crt -noout -issuer

echo "[*] Done."
echo
echo "Generated files in ${CERT_DIR}/:"
ls -1
