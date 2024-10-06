#!/bin/bash

# Create config.hcl file
echo '## Config file:
storage "file" {
  path = "./vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}

disable_mlock = true

api_addr = "http://127.0.0.1:8200"

ui = true' > config.hcl

# Create admin-policy.hcl file
echo '# Read system health check
path "sys/health"
{
  capabilities = ["read", "sudo"]
}

# Create and manage ACL policies broadly across Vault

# List existing policies
path "sys/policies/acl"
{
  capabilities = ["list"]
}

# Create and manage ACL policies
path "sys/policies/acl/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Enable and manage authentication methods broadly across Vault

# Manage auth methods broadly across Vault
path "auth/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Create, update, and delete auth methods
path "sys/auth/*"
{
  capabilities = ["create", "update", "delete", "sudo"]
}

# List auth methods
path "sys/auth"
{
  capabilities = ["read"]
}

# Enable and manage the key/value secrets engine at  path

# List, create, update, and delete key/value secrets
path "secret/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Enable secrets engine
path "sys/mounts/*" {
  capabilities = [ "create", "read", "update", "delete", "list" ]
}

# List enabled secrets engine
path "sys/mounts" {
  capabilities = [ "read", "list" ]
}

# Work with pki secrets engine
path "pki*" {
  capabilities = [ "create", "read", "update", "delete", "list", "sudo", "patch" ]
}' > admin-policy.hcl

# Create intra-policy.hcl file
echo 'path "pki_int/issue/intra-heig-vd-ch" {
  capabilities = ["create", "update"]
}' > intra-policy.hcl

# Start the Vault server with the config file
vault server -config=config.hcl &

# export to HTTP
export VAULT_ADDR='http://127.0.0.1:8200'


echo "Waiting for Vault server to start..."
until curl -s $VAULT_ADDR/v1/sys/health | grep -q 'sealed'; do
echo -e "\e[32mTrying to start server....T\e[0m"
  sleep 3
done

echo -e "\e[32mVault server started.\e[0m"


# Parse the initialization output to extract two unseal keys and the root token
vault_init_output=$(vault operator init -key-shares=6 -key-threshold=2)

unseal_key_primary=$(echo "$vault_init_output" | grep "Unseal Key 1:" | awk '{print $4}')
unseal_key_secondary=$(echo "$vault_init_output" | grep "Unseal Key 2:" | awk '{print $4}')
root_access_token=$(echo "$vault_init_output" | grep "Initial Root Token:" | awk '{print $4}')

# Write keys and tokens to a JSON file
echo '{
  "unseal_key_1": "'$unseal_key_primary'",
  "unseal_key_2": "'$unseal_key_secondary'",
  "root_token": "'$root_access_token'"
}' > vault_keys.json

echo -e "\e[32mVault keys and tokens have been saved to vault_keys.json\e[0m"

echo -e "\e[32mUnsealing the vault.\e[0m"
vault operator unseal $unseal_key_primary
vault operator unseal $unseal_key_secondary

echo -e "\e[32mVault login authentification with root access token.\e[0m"
vault login $root_access_token

echo -e "\e[32mCreating the admin policy and gen the admin token.\e[0m"

# Write the admin policy
vault policy write admin admin-policy.hcl

# Create ADMIN Token
admin_token=$(vault token create -format=json -policy="admin" | jq -r ".auth.client_token")

# Append the admin token to the JSON file
echo -e "\e[32mAdding admin token to json file.\e[0m"
jq '. + {"admin_token": "'$admin_token'"}' vault_keys.json > vault_keys_updated.json && mv vault_keys_updated.json vault_keys.json

echo -e "\e[32mAdmin token has been saved to vault_keys.json.\e[0m"

echo -e "\e[32mSetting up Root CA.\e[0m"

# Enabling PKI
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki # 10 years

# Generate Root certificate
vault write -field=certificate pki/root/generate/internal \
     common_name="HEIG-VD-Root" \
     issuer_name="HEIG-VD-Root" \
     ttl=87600h > root_heig_vd_2024_ca.crt

# Create a role for the Root CA
vault write pki/roles/heig_root allow_any_name=true

# Configure URLS
vault write pki/config/urls \
     issuing_certificates="$VAULT_ADDRESS/v1/pki/ca" \
     crl_distribution_points="$VAULT_ADDRESS/v1/pki/crl"

echo -e "\e[32mRoot CA done.\e[0m"

echo -e "\e[32mSetting up Intermediate CA.\e[0m"

# Enabling pki_int
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

vault write -format=json pki_int/intermediate/generate/internal \
     common_name="HEIG-VD-Intermediate" \
     issuer_name="HEIG-VD-Root" \
     | jq -r '.data.csr' > pki_intermediate.csr

vault write -format=json pki/root/sign-intermediate \
     issuer_ref="HEIG-VD-Root" \
     csr=@pki_intermediate.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > intermediate_cert.pem

vault write pki_int/intermediate/set-signed certificate=@intermediate_cert.pem

echo -e "\e[32mIntermediate CA done.\e[0m"

echo "Setting up intra policy, role, and certificate..."

# Creating an intra role only for intra.heig-vd.ch
vault write pki_int/roles/intra_heig_vd_ch \
     issuer_ref="$(vault read -field=default pki_int/config/issuers)" \
     allowed_domains="intra.heig-vd.ch" \
     allow_bare_domains=true \
     allow_subdomains=false \
     max_ttl="720h"

# Write intra policy
vault policy write intra intra-policy.hcl

vault write -format=json pki_int/issue/intra_heig_vd_ch \
     common_name="intra.heig-vd.ch" \
     format=pem_bundle ttl="24h" \
     | jq -r '.data.certificate' > intra_heig_vd_ch.pem

echo -e "\e[32mIntra policy, role, and certificate are configured.\e[0m"

echo "Generating wildcard certificate for heig-vd.ch..."

vault write pki_int/roles/heig_vd_ch \
  issuer_ref="$(vault read -field=default pki_int/config/issuers)" \
  allowed_domains="heig-vd.ch" \
  allow_bare_domains=false \
  allow_subdomains=true \
  max_ttl="720h"

vault write -format=json pki_int/issue/heig_vd_ch \
    common_name="*.heig-vd.ch" \
    format=pem_bundle \
    ttl="24h" \
    | jq -r '.data.certificate' > heig_vd_wildcard.pem
  
echo -e "\e[32mWildcard certificate are generated.\e[0m"

echo "Adding user accounts to Vault..."
vault auth enable userpass

vault write auth/userpass/users/toto \
    password=titi \
    policies=intra

vault write auth/userpass/users/admin \
    password=admin \
    policies=admin

echo -e "\e[32mUser accounts have been created in Vault.\e[0m"
