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

# Define the key file path
PUB_KEY_FILE="$PUBLIC_DIR/cert.pem"

# Check if the key file exists
if [[ ! -f "$PUB_KEY_FILE" ]]; then
  echo "Error: Public key file '$PUB_KEY_FILE' not found!"
  exit 1
fi

PRIVATE_KEY_CONTENT=$(cat "$KEY_FILE")
PUBLIC_KEY_CONTENT=$(cat "$PUB_KEY_FILE")

# Write the PRIVATE_KEY to the .env file
ENV_FILE=".env"

echo "PUBLIC_KEY=\"$PUBLIC_KEY_CONTENT\"" > "$ENV_FILE"
#echo "PUBLIC_KEY='$PUBLIC_KEY_CONTENT'" | paste -sd '\\n' - > "$ENV_FILE"

echo "Private key has been saved to '$ENV_FILE' as PUBLIC_KEY."

echo "PUBLIC_KEY is now set in $ENV_FILE"

echo "PRIVATE_KEY=\"$PRIVATE_KEY_CONTENT\"" >> "$ENV_FILE"
#echo "PRIVATE_KEY='$PRIVATE_KEY_CONTENT'" | paste -sd '\\n' - >> "$ENV_FILE"

echo "Private key has been saved to '$ENV_FILE' as PRIVATE_KEY."

echo "PRIVATE_KEY is now set in $ENV_FILE"
