#!/bin/bash

# Define the directories
PUBLIC_DIR="certs/public"
PRIVATE_DIR="certs/private"

# Create the directories if they don't exist
mkdir -p "$PUBLIC_DIR" "$PRIVATE_DIR"

echo "Directories created or already exist:"
echo "- $PUBLIC_DIR"
echo "- $PRIVATE_DIR"

openssl req -x509 -newkey rsa:4096 -keyout $PRIVATE_DIR/key.pem -out $PUBLIC_DIR/cert.pem -sha256 -days 365 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CAA"
