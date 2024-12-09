#!/bin/bash

# Define the directories
PUBLIC_DIR="certs/public"
PRIVATE_DIR="certs/private"

# Create the directories if they don't exist
mkdir -p "$PUBLIC_DIR" "$PRIVATE_DIR"

echo "Directories created or already exist:"
echo "- $PUBLIC_DIR"
echo "- $PRIVATE_DIR"

# Generate the certificate and private key using OpenSSL
openssl req -x509 -newkey rsa:4096 -keyout "$PRIVATE_DIR/key.pem" -out "$PUBLIC_DIR/cert.pem" -sha256 -days 365 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CAA"

# Define the key file path
KEY_FILE="$PRIVATE_DIR/key.pem"

# Check if the key file exists
if [[ ! -f "$KEY_FILE" ]]; then
  echo "Error: Private key file '$KEY_FILE' not found!"
  exit 1
fi

# Base64 encode the private key and export it as an environment variable
export PRIVATE_KEY=$(base64 "$KEY_FILE")

# Confirm the key is loaded (you can remove this for better security)
echo "Private key has been loaded into the PRIVATE_KEY environment variable."
