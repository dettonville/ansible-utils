#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"
#VAULT_PASS_FILE="~/.vault_pass"
VAULT_PASS_FILE=".vault_pass"

echo "SCRIPT_DIR=[${SCRIPT_DIR}]"
echo "PROJECT_DIR=${PROJECT_DIR}"

#ansible-playbook -i "${PROJECT_DIR}/test/inventory/"
ansible-playbook "test-update-inventory-role.yml" --vault-password-file "${VAULT_PASS_FILE}"
