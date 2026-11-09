#!/usr/bin/env bash

#set -x

VERSION="2026.10.2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! PROJECT_DIR="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  PROJECT_DIR="${SCRIPT_DIR}"
fi

SCRIPT_NAME="$(basename "$0")"

# Deployment target configuration (default to local pulp)
DEPLOY_TARGET="pulp" # options: pulp, galaxy
PULP_URL="${PULP_URL:-https://pulp.example.int/pulp_ansible/galaxy/internal/}"
PULP_USERNAME="${PULP_USERNAME:-}"
PULP_PASSWORD="${PULP_PASSWORD:-}"

GALAXY_API_KEY="${ANSIBLE_GALAXY_TOKEN}"
GALAXY_BUILD_PATH="./releases"

BUILD_ONLY=0
DEPLOY_GALAXY_COLLECTION=1
INSTALL_COLLECTION_LOCALLY=0
FORCE_BUILD_COLLECTION=0
VERIFY_GALAXY_COLLECTION=0

INSTALL_COLLECTION_PATH="${HOME}/.ansible/collections"

#### LOGGING RELATED
LOG_ERROR=0
LOG_WARN=1
LOG_INFO=2
LOG_TRACE=3
LOG_DEBUG=4

declare -A LOGLEVEL_TO_STR
LOGLEVEL_TO_STR["${LOG_ERROR}"]="ERROR"
LOGLEVEL_TO_STR["${LOG_WARN}"]="WARN"
LOGLEVEL_TO_STR["${LOG_INFO}"]="INFO"
LOGLEVEL_TO_STR["${LOG_TRACE}"]="TRACE"
LOGLEVEL_TO_STR["${LOG_DEBUG}"]="DEBUG"

# string formatters
if [[ -t 1 ]]
then
  tty_escape() { printf "\033[%sm" "$1"; }
else
  tty_escape() { :; }
fi
tty_mkbold() { tty_escape "1;$1"; }
tty_underline="$(tty_escape "4;39")"
tty_blue="$(tty_mkbold 34)"
tty_red="$(tty_mkbold 31)"
tty_orange="$(tty_mkbold 33)"
tty_bold="$(tty_mkbold 39)"
tty_reset="$(tty_escape 0)"

function reverse_array() {
  local -n ARRAY_SOURCE_REF=$1
  local -n REVERSED_ARRAY_REF=$2
  for KEY in "${!ARRAY_SOURCE_REF[@]}"; do
    VALUE="${ARRAY_SOURCE_REF[$KEY]}"
    REVERSED_ARRAY_REF["$VALUE"]="$KEY"
  done
}

declare -A LOGLEVELSTR_TO_LEVEL
reverse_array LOGLEVEL_TO_STR LOGLEVELSTR_TO_LEVEL

LOG_LEVEL=${LOG_INFO}

function log_error() {
  if [ "$LOG_LEVEL" -ge "$LOG_ERROR" ]; then
  	log_message "${LOG_ERROR}" "${1}"
  fi
}

function log_warn() {
  if [ "$LOG_LEVEL" -ge "$LOG_WARN" ]; then
  	log_message "${LOG_WARN}" "${1}"
  fi
}

function log_info() {
  if [ "$LOG_LEVEL" -ge "$LOG_INFO" ]; then
  	log_message "${LOG_INFO}" "${1}"
  fi
}

function log_trace() {
  if [ "$LOG_LEVEL" -ge "$LOG_TRACE" ]; then
  	log_message "${LOG_TRACE}" "${1}"
  fi
}

function log_debug() {
  if [ "$LOG_LEVEL" -ge "$LOG_DEBUG" ]; then
  	log_message "${LOG_DEBUG}" "${1}"
  fi
}

function shell_join() {
  local arg
  printf "%s" "$1"
  shift
  for arg in "$@"
  do
    printf " "
    printf "%s" "${arg// /\ }"
  done
}

function chomp() {
  printf "%s" "${1/"$'\n'"/}"
}

function abort() {
  log_error "$@"
  exit 1
}

function warn() {
  log_warn "$@"
}

function error() {
  log_error "$@"
}

function fail() {
  error "$@"
  exit 1
}

function log_message() {
  local LOG_MESSAGE_LEVEL="${1}"
  local LOG_MESSAGE="${2}"
  local CALLING_FUNCTION_ARRAY_LENGTH=${#FUNCNAME[@]}
  local CALLING_FUNCTION_ARRAY=("${FUNCNAME[@]:2:$((CALLING_FUNCTION_ARRAY_LENGTH - 3))}")

  local CALL_ARRAY_LENGTH=${#CALLING_FUNCTION_ARRAY[@]}
  local REVERSED_CALL_ARRAY=()
  for (( i = CALL_ARRAY_LENGTH - 1; i >= 0; i-- )); do
    REVERSED_CALL_ARRAY+=( "${CALLING_FUNCTION_ARRAY[i]}" )
  done

  local SEPARATOR=":"
  local CALLING_FUNCTION_STR
  CALLING_FUNCTION_STR=$(printf "${SEPARATOR}%s" "${REVERSED_CALL_ARRAY[@]}")
  CALLING_FUNCTION_STR=${CALLING_FUNCTION_STR:${#SEPARATOR}}

  if [ "${LOGLEVEL_TO_STR[${LOG_MESSAGE_LEVEL}]+abc}" ]; then
    LOG_LEVEL_STR="${LOGLEVEL_TO_STR[${LOG_MESSAGE_LEVEL}]}"
  else
    abort "Unknown log level of [${LOG_MESSAGE_LEVEL}]"
  fi

  local LOG_LEVEL_PADDING_LENGTH=5
  local PADDED_LOG_LEVEL
  PADDED_LOG_LEVEL=$(printf "%-${LOG_LEVEL_PADDING_LENGTH}s" "${LOG_LEVEL_STR}")

  local LOG_PREFIX="${CALLING_FUNCTION_STR}():"
  if [ "${LOG_MESSAGE_LEVEL}" -eq $LOG_INFO ]; then
    printf "${tty_blue}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
  elif [ "${LOG_MESSAGE_LEVEL}" -eq $LOG_WARN ]; then
    printf "${tty_orange}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
  elif [ "${LOG_MESSAGE_LEVEL}" -le $LOG_ERROR ]; then
    printf "${tty_red}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
  else
    printf "${tty_bold}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
  fi
}

function set_log_level() {
  LOG_LEVEL_STR=$1
  if [ "${LOGLEVELSTR_TO_LEVEL[${LOG_LEVEL_STR}]+abc}" ]; then
    LOG_LEVEL="${LOGLEVELSTR_TO_LEVEL[${LOG_LEVEL_STR}]}"
  else
    abort "Unknown log level of [${LOG_LEVEL_STR}]"
  fi
}

function execute() {
  log_info "${*}"
  if ! "$@"
  then
    abort "$(printf "Failed during: %s" "$(shell_join "$@")")"
  fi
}

function execute_eval_command() {
  local RUN_COMMAND="${*}"
  log_debug "${RUN_COMMAND}"
  COMMAND_RESULT=$(eval "${RUN_COMMAND}")
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    if [[ $COMMAND_RESULT != "" ]]; then
      log_debug "${COMMAND_RESULT}"
    fi
    log_debug "SUCCESS!"
  else
    log_error "ERROR (${RETURN_STATUS})"
    abort "$(printf "Failed during: %s" "${COMMAND_RESULT}")"
  fi
}

function is_installed() {
  command -v "${1}" >/dev/null 2>&1 || return 1
}

function check_required_commands() {
  missingCommands=""
  for currentCommand in "$@"
  do
    is_installed "${currentCommand}" || missingCommands="${missingCommands} ${currentCommand}"
  done

  if [[ -n "${missingCommands}" ]]; then
    fail "Please install the following commands required by this script:${missingCommands}"
  fi
}

function deploy_ansible_collection() {
  local COLLECTION_PATH="${1-""}"

  cd "$COLLECTION_PATH" || {
    abort "Error: Could not change to collection directory. Exiting."
  }

  COLLECTION_NAMESPACE=$(yq -r '.namespace' "${PROJECT_DIR}/galaxy.yml")
  COLLECTION_NAME=$(yq -r '.name' "${PROJECT_DIR}/galaxy.yml")
  COLLECTION_VERSION=$(yq -r '.version' "${PROJECT_DIR}/galaxy.yml")

  log_info "Ansible collection => ${COLLECTION_NAMESPACE}.${COLLECTION_NAME} version: ${COLLECTION_VERSION}"

  log_debug "Building Ansible collection..."
  BUILD_GALAXY_COLLECTION_CMD_ARRAY=("ansible-galaxy collection build")
  if [ "${FORCE_BUILD_COLLECTION}" -eq 1 ]; then
    BUILD_GALAXY_COLLECTION_CMD_ARRAY+=("--force")
  fi
  BUILD_GALAXY_COLLECTION_CMD_ARRAY+=("--output-path ${GALAXY_BUILD_PATH}")

  execute_eval_command "${BUILD_GALAXY_COLLECTION_CMD_ARRAY[*]}"
  log_debug "Collection built successfully."

  if [ "${BUILD_ONLY}" -eq 1 ]; then
    log_info "Build-only specified, ending now"
    return
  fi

  # Find the generated tarball file name.
  # The format is typically <namespace>-<collection_name>-<version>.tar.gz.
  COLLECTION_TARBALL=$(find . -type f -name "${COLLECTION_NAMESPACE}-${COLLECTION_NAME}-${COLLECTION_VERSION}.tar.gz" 2>/dev/null)
  log_info "COLLECTION_TARBALL=${COLLECTION_TARBALL}"

  if [ ! -e "${COLLECTION_TARBALL}" ]; then
    abort "Error: Collection tarball ${COLLECTION_TARBALL} not found. Exiting."
  fi

  if [ "${INSTALL_COLLECTION_LOCALLY}" -eq 1 ]; then
    INSTALL_COLLECTION_CMD_ARRAY=("ansible-galaxy collection install --force ${COLLECTION_TARBALL}")
    if [ -n "${INSTALL_COLLECTION_PATH}" ]; then
      INSTALL_COLLECTION_CMD_ARRAY+=("-p ${INSTALL_COLLECTION_PATH}")
    fi
    execute_eval_command "${INSTALL_COLLECTION_CMD_ARRAY[*]}"
  fi

  if [ "${DEPLOY_GALAXY_COLLECTION}" -eq 1 ]; then
    if [ "${DEPLOY_TARGET}" == "pulp" ]; then
      log_info "Publishing collection artifact: ${COLLECTION_TARBALL} to local Pulp registry (${PULP_URL})..."

      export ANSIBLE_GALAXY_SERVER_LIST="pulp"
      export ANSIBLE_GALAXY_SERVER_PULP_URL="${PULP_URL}"
      export ANSIBLE_GALAXY_SERVER_PULP_USERNAME="${PULP_USERNAME}"
      export ANSIBLE_GALAXY_SERVER_PULP_PASSWORD="${PULP_PASSWORD}"
#      export ANSIBLE_GALAXY_SERVER_PULP_TOKEN="${PULP_PASSWORD}"

      DEPLOY_CMD_ARRAY=("ansible-galaxy collection publish ${COLLECTION_TARBALL} --server pulp")
    else
      log_info "Publishing collection artifact: ${COLLECTION_TARBALL} to Ansible Galaxy..."
      if [ -n "$GALAXY_API_KEY" ]; then
        DEPLOY_CMD_ARRAY=("ansible-galaxy collection publish ${COLLECTION_TARBALL} --api-key=${GALAXY_API_KEY}")
      else
        DEPLOY_CMD_ARRAY=("ansible-galaxy collection publish ${COLLECTION_TARBALL}")
      fi
    fi

    execute_eval_command "${DEPLOY_CMD_ARRAY[*]}"
    log_debug "Collection published successfully."

    if [ "${VERIFY_GALAXY_COLLECTION}" -eq 1 ]; then
      GALAXY_COLLECTION_VERIFY_CMD_ARRAY=("ansible-galaxy collection verify")
      GALAXY_COLLECTION_VERIFY_CMD_ARRAY+=("${COLLECTION_NAMESPACE}.${COLLECTION_NAME}")
      execute_eval_command "${GALAXY_COLLECTION_VERIFY_CMD_ARRAY[*]}"
    fi
  fi

  # Optional: Clean up the built tarball after publishing.
  # log_debug "Removing collection tarball..."
  # rm "$COLLECTION_TARBALL"

}


function usage() {
  echo "Usage: ${SCRIPT_NAME} [options] [COLLECTION_PATH]"
  echo ""
  echo "       COLLECTION_PATH=/path/to/your/ansible_collections/<namespace>/<collection_name>"
  echo "       * Set the path to your collection's root directory (where galaxy.yml is located)."
  echo "       * Default: The git repository directory where the script is located"
  echo ""
  echo "  Options:"
  echo "       -L [ERROR|WARN|INFO|TRACE|DEBUG] : run with specified log level (default: '${LOGLEVEL_TO_STR[${LOG_LEVEL}]}')"
  echo "       -P : deploy to local Pulp registry (default)"
  echo "       -G : deploy to remote Ansible Galaxy"
  echo "       -u URL : specify Pulp URL (default: ${PULP_URL})"
  echo "       -U user : specify Pulp username (default: ${PULP_USERNAME})"
  echo "       -W pass : specify Pulp password"
  echo "       -g key : specify Ansible Galaxy API key"
  echo "       -b : build collection only and skip deploy"
  echo "       -f : force build to re-create the collection artifact if necessary"
  echo "       -l : install collection locally"
  echo "       -p path : local collection install path (default: ${INSTALL_COLLECTION_PATH})"
  echo "       -s : skip collection deployment"
  echo "       -t : verify installed collection matches server deployment"
  echo "       -v : show script version"
  echo "       -h : help"
  echo ""
  echo "  Examples:"
  echo "       # Deploy to local Pulp (default):"
  echo "       export PULP_PASSWORD='your_password'"
  echo "       ${SCRIPT_NAME}"
  echo "       ${SCRIPT_NAME} /home/user123/repos/ansible_collections/test-namespace/test-collection"
  echo "    Perform local install only:"
  echo "       ${SCRIPT_NAME} -fls -p ~/.ansible/collections ~/repos/ansible_collections/demo-ns/utils"
  echo ""
  echo "       # Deploy to Ansible Galaxy:"
  echo "       ${SCRIPT_NAME} -G -g <galaxy_api_token>"
  [ -z "$1" ] || exit "$1"
}

function main() {
  check_required_commands ansible-galaxy yq

  while getopts "L:g:p:u:U:W:bflstGPvh" opt; do
      case "${opt}" in
          L) set_log_level "${OPTARG}" ;;
          g) GALAXY_API_KEY="${OPTARG}" ;;
          p) INSTALL_COLLECTION_PATH="${OPTARG}" ;;
          u) PULP_URL="${OPTARG}" ;;
          U) PULP_USERNAME="${OPTARG}" ;;
          W) PULP_PASSWORD="${OPTARG}" ;;
          P) DEPLOY_TARGET="pulp" ;;
          G) DEPLOY_TARGET="galaxy" ;;
          b) BUILD_ONLY=1 ;;
          f) FORCE_BUILD_COLLECTION=1 ;;
          l) INSTALL_COLLECTION_LOCALLY=1 ;;
          s) DEPLOY_GALAXY_COLLECTION=0 ;;
          t) VERIFY_GALAXY_COLLECTION=1 ;;
          h) usage 1 ;;
          v) echo "${VERSION}" && exit ;;
          \?) usage 2 ;;
          *) usage ;;
      esac
  done
  shift $((OPTIND-1))

  log_info "PROJECT_DIR=${PROJECT_DIR}"
  local COLLECTION_PATH="${PROJECT_DIR}"
  if [ $# -eq 1 ]; then
    COLLECTION_PATH="${1}"
  fi

  log_info "COLLECTION_PATH=${COLLECTION_PATH}"
  log_info "DEPLOY_TARGET=${DEPLOY_TARGET}"
  if [ "${DEPLOY_TARGET}" == "pulp" ]; then
    log_debug "PULP_URL=${PULP_URL}"
    log_debug "PULP_USERNAME=${PULP_USERNAME}"
  fi

  deploy_ansible_collection "${COLLECTION_PATH}"
}

main "$@"
