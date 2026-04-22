#!/bin/bash
# Generate SSL certificates for Gorgona Mesh
CERT_DIR="/etc/gorgona"
sudo mkdir -p $CERT_DIR

echo "Generating RSA Private Key and Self-Signed Certificate..."
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -subj "/C=US/ST=Mesh/L=Gorgona/O=Infrastructure/CN=gorgona.local"

sudo chmod 600 "$CERT_DIR/server.key"
echo "Certificates generated in $CERT_DIR"
