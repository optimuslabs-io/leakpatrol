#!/bin/sh
# Generate a throwaway CA and a server cert for registry.coder.com /
# www.coder-infra.com, into lab/tls/. The CA is mounted read-only into the coder
# container's SSL_CERT_FILE ONLY -- it is never added to the host trust store, and
# `make lab-down` deletes it.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
set -eu
dir="$(dirname "$0")/tls"
mkdir -p "$dir"
cd "$dir"

if [ -f server.pem ] && [ -f ca.pem ]; then
  echo "tls already generated (rm lab/tls to regenerate)"
  exit 0
fi

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 30 -subj "/CN=leakpatrol-lab CA" >/dev/null 2>&1

# Server key + CSR
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=registry.coder.com" >/dev/null 2>&1

cat > ext.cnf <<'EOF'
subjectAltName = DNS:registry.coder.com, DNS:www.coder-infra.com
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 30 -extfile ext.cnf >/dev/null 2>&1

rm -f server.csr ext.cnf ca.srl
echo "generated lab CA + server cert for registry.coder.com / www.coder-infra.com (30-day, throwaway)"
