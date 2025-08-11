#!/usr/bin/env bash

#set -eux

#source virtualenv.sh

# Requirements have to be installed prior to running ansible-playbook
# because plugins and requirements are loaded before the task runs

#pip install -r requirements.txt

#echo "==> ENV"
#echo "$(export -p | sed 's/declare -x //')"

#VERSION="2025.7.1"
KEEP_TEMP_DIR=1

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_NAME_PREFIX="${SCRIPT_NAME%.*}"

PLAYBOOK="${SCRIPT_NAME_PREFIX}.yml"
PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"

## only needed if sourcing local private collections by source instead of galaxy
## NEEDED when there is are updates/changes to the dependent collections
## to be deployed along with the project repo update(s)
#PROJECT_PARENT_DIR="${PROJECT_DIR}/.."
PROJECT_PARENT_DIR=$(dirname "${PROJECT_DIR}")

VAULTPASS_FILEPATH="${HOME}/.vault_pass"
if [[ -f "${PROJECT_DIR}/.vault_pass" ]]; then
  VAULTPASS_FILEPATH="${PROJECT_DIR}/.vault_pass"
fi
VAULT_FILEPATH="./../integration_config.vault.yml"
#TEST_VARS_FILE="test-vars.yml"

INSTALL_GALAXY_COLLECTIONS=1
UPGRADE_GALAXY_COLLECTIONS=1
RESET_GALAXY_CACHE=1

USE_SOURCE_COLLECTIONS=0
SOURCE_COLLECTIONS_PATH="${PROJECT_PARENT_DIR}/requirements_collections"

echo "SCRIPT_DIR=[${SCRIPT_DIR}]"
echo "SCRIPT_NAME=[${SCRIPT_NAME}]"
echo "PLAYBOOK=[${PLAYBOOK}]"
echo "PROJECT_PARENT_DIR=${PROJECT_PARENT_DIR}"
echo "PROJECT_DIR=${PROJECT_DIR}"

echo "VAULT_FILEPATH=${VAULT_FILEPATH}"
echo "VAULT_ID=${VAULT_ID}"

#ANSIBLE_COLLECTION_REQUIREMENTS="${PROJECT_DIR}/tests/requirements.yml"
#ANSIBLE_COLLECTION_REQUIREMENTS="${PROJECT_DIR}/requirements.yml"
ANSIBLE_COLLECTION_REQUIREMENTS="${PROJECT_DIR}/tests/integration/requirements.yml"

export LOCAL_COLLECTIONS_PATH="${HOME}/.ansible/collections"
#export LOCAL_COLLECTIONS_PATH="${HOME}/.ansible"
#export ANSIBLE_ROLES_PATH=./
#export ANSIBLE_COLLECTIONS_PATH="${LOCAL_COLLECTIONS_PATH}:${PROJECT_DIR}/collections:${PROJECT_PARENT_DIR}/requirements_collections"
#export ANSIBLE_COLLECTIONS_PATH="${PROJECT_DIR}/collections:${PROJECT_PARENT_DIR}/requirements_collections"
#export ANSIBLE_COLLECTIONS_PATH="${PROJECT_PARENT_DIR}/requirements_collections"
#export ANSIBLE_COLLECTIONS_PATH="${PROJECT_DIR}/collections"
#export ANSIBLE_COLLECTIONS_PATH="${PROJECT_DIR}/collections:${LOCAL_COLLECTIONS_PATH}"
export ANSIBLE_COLLECTIONS_PATH="${LOCAL_COLLECTIONS_PATH}"

if [[ "${USE_SOURCE_COLLECTIONS}" -eq 1 ]]; then
  export ANSIBLE_COLLECTIONS_PATH=${SOURCE_COLLECTIONS_PATH}:${ANSIBLE_COLLECTIONS_PATH}
fi

#export ANSIBLE_DEBUG=1
export ANSIBLE_KEEP_REMOTE_FILES=1
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

## ref: https://github.com/ansible/ansible/issues/79557#issuecomment-1344168449
#export ANSIBLE_GALAXY_IGNORE=true
#export GALAXY_IGNORE_CERTS=true

function cleanup_tmpdir() {
  test "${KEEP_TEMP_DIR:-0}" = 1 || rm -rf "${TEMP_DIR}"
}

function execute_eval_command() {
  local RUN_COMMAND="${*}"

  echo "${RUN_COMMAND}"
  COMMAND_RESULT=$(eval "${RUN_COMMAND}")
#  COMMAND_RESULT=$(eval "${RUN_COMMAND} > /dev/null 2>&1")
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    if [[ $COMMAND_RESULT != "" ]]; then
      echo "${COMMAND_RESULT}"
    fi
    echo "SUCCESS!"
  else
    echo "ERROR (${RETURN_STATUS})"
#    echo "${COMMAND_RESULT}"
    echo "Failed during: %s" "${COMMAND_RESULT}"
    exit 1
  fi

}

function install_galaxy_collections() {
  local _ANSIBLE_COLLECTION_REQUIREMENTS="${1}"

  echo "==> ansible-galaxy --version"
  ansible-galaxy --version

  ## ref: https://github.com/ansible/ansible/issues/79557#issuecomment-1344168449
  echo "==> Install Galaxy collection requirements"
#  GALAXY_INSTALL_CMD=("env ANSIBLE_GALAXY_IGNORE=true")
#  GALAXY_INSTALL_CMD+=("env GALAXY_IGNORE_CERTS=true")
#  GALAXY_INSTALL_CMD+=("ansible-galaxy collection install")
#  GALAXY_INSTALL_CMD+=("--ignore-certs")
#  GALAXY_INSTALL_CMD+=("--force")

  if [[ "${RESET_GALAXY_CACHE}" -eq 1 ]]; then
    jq '.' ~/.ansible/galaxy_cache/api.json > ~/.ansible/galaxy_cache/api.orig.json
    jq '.["galaxy.ansible.com:"] |= with_entries(if .key | startswith("/api/v3/collections/dettonville/") then empty else . end)' \
      ~/.ansible/galaxy_cache/api.orig.json > ~/.ansible/galaxy_cache/api.json
  fi

  GALAXY_INSTALL_CMD=("ansible-galaxy collection install")
  if [[ "${UPGRADE_GALAXY_COLLECTIONS}" -eq 1 ]]; then
    GALAXY_INSTALL_CMD+=("--upgrade")
    GALAXY_INSTALL_CMD+=("--force")
  fi
  GALAXY_INSTALL_CMD+=("-r ${_ANSIBLE_COLLECTION_REQUIREMENTS}")
  GALAXY_INSTALL_CMD+=("-p ${LOCAL_COLLECTIONS_PATH}")

  echo "==> ${GALAXY_INSTALL_CMD[*]}"
#  eval "${GALAXY_INSTALL_CMD[*]}"
  execute_eval_command "${GALAXY_INSTALL_CMD[*]}"
}

function setup_collection_run_dir() {

  COLLECTION_NAMESPACE=$(yq -r '.namespace' "${PROJECT_DIR}/galaxy.yml")
  COLLECTION_NAME=$(yq -r '.name' "${PROJECT_DIR}/galaxy.yml")

  ## ref: https://www.pixelstech.net/article/1577768087-Create-temp-file-in-Bash-using-mktemp-and-trap
  ## ref: https://stackoverflow.com/questions/4632028/how-to-create-a-temporary-directory
  mkdir -p "${HOME}/tmp"
  TEMP_DIR=$(mktemp -d -p "${HOME}/tmp" "${SCRIPT_NAME_PREFIX}_XXXXXX")

  trap cleanup_tmpdir INT TERM EXIT

  COLLECTION_BASE_DIR="${TEMP_DIR}"
  COLLECTION_SOURCE_DIR="${COLLECTION_BASE_DIR}/ansible_collections/${COLLECTION_NAMESPACE}/${COLLECTION_NAME}"
  echo "COLLECTION_SOURCE_DIR=${COLLECTION_SOURCE_DIR}"

  mkdir -p "$(dirname "${COLLECTION_SOURCE_DIR}")"
  ln -s "${PROJECT_DIR}" "${COLLECTION_SOURCE_DIR}"
  export ANSIBLE_COLLECTIONS_PATH="${COLLECTION_BASE_DIR}:${ANSIBLE_COLLECTIONS_PATH}"
  echo "ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH}"

}

function main() {
  ANSIBLE_ARGS=()
  if [ $# -gt 0 ]; then
    ANSIBLE_ARGS=("$@")
  fi
  echo "==> ANSIBLE_ARGS[*]=${ANSIBLE_ARGS[*]}"

  rm -f ./ansible.log

  ## ref: https://stackoverflow.com/questions/40684543/how-to-make-python-use-ca-certificates-from-mac-os-truststore
  CERT_PATH=$(python -m certifi)
  export SSL_CERT_FILE=${CERT_PATH}
  export REQUESTS_CA_BUNDLE=${CERT_PATH}

  if [[ "${INSTALL_GALAXY_COLLECTIONS}" -eq 1 || "${UPGRADE_GALAXY_COLLECTIONS}" -eq 1 ]]; then
    install_galaxy_collections "${ANSIBLE_COLLECTION_REQUIREMENTS}"
  fi
  echo "==> ansible-galaxy collection list"
  ansible-galaxy collection list

  setup_collection_run_dir

  echo "==> ansible --version"
  ansible --version

  PLAYBOOK_CMD=("ansible-playbook")
#  PLAYBOOK_CMD+=("-e @${TEST_VARS_FILE}")
#  PLAYBOOK_CMD+=("-e @${VAULT_FILEPATH}")
  PLAYBOOK_CMD+=("--vault-password-file ${VAULTPASS_FILEPATH}")
  if [[ "${#ANSIBLE_ARGS[@]}" -gt 0 ]]; then
    PLAYBOOK_CMD+=("${ANSIBLE_ARGS[*]}")
  fi
  PLAYBOOK_CMD+=("${PLAYBOOK}")

  echo "==> ${PLAYBOOK_CMD[*]}"
  eval "${PLAYBOOK_CMD[*]}"

}

main "$@"
