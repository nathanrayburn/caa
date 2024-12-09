#!/bin/bash

# Path to the private key file
KEY_FILE="keys/key.pem"

# Check if the key file exists
if [[ ! -f "$KEY_FILE" ]]; then
  echo "Error: Private key file '$KEY_FILE' not found!"
  exit 1
fi

# Read the private key securely and export it as an environment variable
export PRIVATE_KEY=$(cat "$KEY_FILE")

# Confirm the key is loaded (you can remove this for better security)
echo "Private key has been loaded into the PRIVATE_KEY environment variable."
