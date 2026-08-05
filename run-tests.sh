#!/usr/bin/env bash

VERSION="2026.8.3"

SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_NAME_PREFIX="${SCRIPT_NAME%.*}"
PROJECT_DIR="$(cd "${SCRIPT_DIR}" && git rev-parse --show-toplevel)"

# Core Requirements: Discover namespace/name from galaxy.yml dynamically
if [[ ! -f "${PROJECT_DIR}/galaxy.yml" ]]; then
  echo "Error: Collection tests require 'galaxy.yml' to discover namespace/name from galaxy.yml dynamically"
  exit 1
fi
COLLECTION_NAMESPACE=$(yq -r '.namespace' "${PROJECT_DIR}/galaxy.yml")
COLLECTION_NAME=$(yq -r '.name' "${PROJECT_DIR}/galaxy.yml")

mkdir -p "${HOME}/tmp"
TEMP_DIR=$(mktemp -d -p "${HOME}/tmp" "${SCRIPT_NAME_PREFIX}_XXXXXX")

cleanup_tmpdir() {
    log_debug "Cleaning up temporary environment at ${TEMP_DIR}"
    rm -rf "${TEMP_DIR}"
}
trap cleanup_tmpdir INT TERM EXIT

# Emulate official collection directory layout structures required by ansible-test
TEST_COLLECTION_BASE_DIR="${TEMP_DIR}/ansible_collections"
TEST_COLLECTION_SOURCE_DIR="${TEST_COLLECTION_BASE_DIR}/${COLLECTION_NAMESPACE}/${COLLECTION_NAME}"

#### LOGGING METHODS
LOG_ERROR=0; LOG_WARN=1; LOG_INFO=2; LOG_DEBUG=4
LOG_LEVEL=${LOG_INFO}

if [[ -t 1 ]]; then
  tty_escape() { printf "\033[%sm" "$1"; }
else
  tty_escape() { :; }
fi
tty_blue="$(tty_escape "1;34")"; tty_red="$(tty_escape "1;31")"; tty_green="$(tty_escape "1;32")"; tty_reset="$(tty_escape 0)"; tty_yellow="$(tty_escape "1;33")"

function log_info() { [ "${LOG_LEVEL}" -ge "${LOG_INFO}" ] && printf "${tty_blue}[INFO]: ==>${tty_reset} %s\n" "$1" >&2; }
function log_success() { printf "${tty_green}[SUCCESS]: ==>${tty_reset} %s\n" "$1" >&2; }
function log_warn() { [ "${LOG_LEVEL}" -ge "${LOG_WARN}" ] && printf "${tty_yellow}[WARN]: ==> %s${tty_reset}\n" "$1" >&2; }
function log_error() { [ "${LOG_LEVEL}" -ge "${LOG_ERROR}" ] && printf "${tty_red}[ERROR]: ==> %s${tty_reset}\n" "$1" >&2; }
function log_debug() { [ "${LOG_LEVEL}" -ge "${LOG_DEBUG}" ] && printf "[DEBUG]: ==> %s\n" "$1" >&2; }

function abort() {
  log_error "$@"
  exit 1
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

function execute() {
  log_info "Running: ${*}"
  if ! "$@"
  then
    abort "$(printf "Failed during: %s" "$(shell_join "$@")")"
  fi
}

function execute_eval_command() {
  local RUN_COMMAND="${*}"

  log_info "Running: ${RUN_COMMAND}"
  COMMAND_RESULT=$(eval "${RUN_COMMAND}")
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    if [[ $COMMAND_RESULT != "" ]]; then
      log_debug "${COMMAND_RESULT}"
    fi
    log_debug "SUCCESS!"
  else
    log_error "RETURN_STATUS=(${RETURN_STATUS})"
    abort "$(printf "Failed during: %s" "${COMMAND_RESULT}")"
  fi

  return $RETURN_STATUS
}

function execute_test_command() {
  local RUN_COMMAND="${*}"

  log_info "Running: ${RUN_COMMAND}"

  # Stream output directly to terminal instead of capturing it into a variable
  eval "${RUN_COMMAND}"
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    log_success "Command completed successfully."
  else
    log_error "Command failed with RETURN_STATUS=(${RETURN_STATUS})"
    abort "Execution failure encountered."
  fi

  return $RETURN_STATUS
}

detect_env_python_version() {
  local py_cmd=""
  if command -v python3 >/dev/null 2>&1; then
    py_cmd="python3"
  elif command -v python >/dev/null 2>&1; then
    py_cmd="python"
  else
    log_error "Neither python3 nor python could be found in current PATH."
    exit 1
  fi

  # Extract Major.Minor (e.g. "3.13") from active environment interpreter
  "${py_cmd}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
}

setup_test_env() {
  log_info "Setting up local workspace testing sandboxes..."

  log_info "TEST_COLLECTION_BASE_DIR=${TEST_COLLECTION_BASE_DIR}"
  log_info "TEST_COLLECTION_SOURCE_DIR=${TEST_COLLECTION_SOURCE_DIR}"

  log_info "Create collection source directory hierarchy..."
  mkdir -p "${TEST_COLLECTION_SOURCE_DIR}"

  log_info "Syncing repository files into the mapped layout context..."
  # Use rsync to perform a fast, true physical copy while skipping local test iteration noise
  if command -v rsync >/dev/null 2>&1; then
    rsync -a \
      --exclude='.git' \
      --exclude='tmp' \
      --filter=':- .gitignore' \
      "${PROJECT_DIR}/" "${TEST_COLLECTION_SOURCE_DIR}/"
  else
    # Fallback: tar pipeline using git ls-files
    log_info "rsync not found, using git + tar fallback..."
    (cd "${PROJECT_DIR}" && git ls-files --cached --others --exclude-standard) | tar -cf - -C "${PROJECT_DIR}" -T - | tar -xf - -C "${TEST_COLLECTION_SOURCE_DIR}"
  fi

  # Install collection dependencies matching setupTestDependencies logic
  mkdir -p "${TEST_COLLECTION_BASE_DIR}"

  local REQUIREMENTS_FILE=""
  if [[ -f "${PROJECT_DIR}/requirements.yml" ]]; then
    REQUIREMENTS_FILE="${PROJECT_DIR}/requirements.yml"
  elif [[ -f "${PROJECT_DIR}/tests/requirements.yml" ]]; then
    REQUIREMENTS_FILE="${PROJECT_DIR}/tests/requirements.yml"
  fi

  GALAXY_INSTALL_OPTS+="--clear-response-cache --force"

  GALAXY_INSTALL_CMD=("ansible-galaxy" "collection" "install")
  GALAXY_INSTALL_CMD+=("--force")
  GALAXY_INSTALL_CMD+=("--clear-response-cache")
  if [[ -n "${REQUIREMENTS_FILE}" ]]; then
    log_info "Found requirements file: ${REQUIREMENTS_FILE}. Installing collection dependencies..."
    log_info "Installing collection to: ${TEST_COLLECTION_BASE_DIR}"
    set -x
    eval "${GALAXY_INSTALL_CMD[*]} -r ${REQUIREMENTS_FILE} -p ${TEST_COLLECTION_BASE_DIR}" || abort "Failed to install dependencies from ${REQUIREMENTS_FILE}"
    set +x
  elif [[ -n "${TEST_DEPS:-}" ]]; then
    log_info "Installing test dependencies defined in TEST_DEPS: ${TEST_DEPS}"
    IFS=',' read -ra DEPS <<< "${TEST_DEPS}"
    for dep in "${DEPS[@]}"; do
      dep_trimmed=$(echo "${dep}" | xargs)
      if [[ -n "${dep_trimmed}" ]]; then
        log_info "installing collection: ${dep_trimmed} to ${TEST_COLLECTION_BASE_DIR}"
        set -x
        eval "${GALAXY_INSTALL_CMD[*]} ${dep_trimmed} -p ${TEST_COLLECTION_BASE_DIR}" || abort "Failed to install dependency ${dep_trimmed}"
        set +x
      fi
    done
  fi

  # Export path context explicitly pointing to the physical temporary base for Ansible ecosystem
  export ANSIBLE_COLLECTIONS_PATH="${TEST_COLLECTION_BASE_DIR}:~/.ansible/collections:/usr/share/ansible/collections"
  log_info "ANSIBLE_COLLECTIONS_PATH set to: ${ANSIBLE_COLLECTIONS_PATH}"

  # Inject and export base workspace path to PYTHONPATH so native python/pytest runs can resolve collection dependencies
  export PYTHONPATH="${TEST_COLLECTION_BASE_DIR}:${PYTHONPATH}"
  log_info "PYTHONPATH augmented with: ${TEST_COLLECTION_BASE_DIR}"
}

run_collection_tests() {
  local TARGET_TYPE=${1:-"sanity"}
  local HAS_EXPLICIT_PYTHON=${2}
  shift 2
  local PASSTHROUGH_ARGS=("$@")
  local CMD=""

  cd "${TEST_COLLECTION_SOURCE_DIR}" || abort "Failed to change directory to ${TEST_COLLECTION_SOURCE_DIR}"

  case "${TARGET_TYPE}" in
    sanity)
      CMD="ansible-test sanity"
      if [[ "${HAS_EXPLICIT_PYTHON}" == "false" ]]; then
        local ENV_PY_VERSION
        ENV_PY_VERSION=$(detect_env_python_version)
        log_info "No explicit --python flag provided for unit tests. Detected active environment Python: ${ENV_PY_VERSION}"
        CMD="${CMD} --python ${ENV_PY_VERSION}"
      fi
      ;;
    units|unit)
      CMD="ansible-test units --requirements"
      if [[ "${HAS_EXPLICIT_PYTHON}" == "false" ]]; then
        local ENV_PY_VERSION
        ENV_PY_VERSION=$(detect_env_python_version)
        log_info "No explicit --python flag provided for unit tests. Detected active environment Python: ${ENV_PY_VERSION}"
        CMD="${CMD} --python ${ENV_PY_VERSION}"
      fi
      ;;
    integration)
      CMD="ansible-test integration"
      if [[ "${HAS_EXPLICIT_PYTHON}" == "false" ]]; then
        local ENV_PY_VERSION
        ENV_PY_VERSION=$(detect_env_python_version)
        log_info "No explicit --python flag provided for unit tests. Detected active environment Python: ${ENV_PY_VERSION}"
        CMD="${CMD} --python ${ENV_PY_VERSION}"
      fi
      ;;
    pytest)
      CMD="pytest -q --tb=short"
      if [[ ${#PASSTHROUGH_ARGS[@]} -eq 0 ]]; then
        PASSTHROUGH_ARGS=("--log-level=CRITICAL" "tests/")
      fi
      ;;
    *)
      log_error "Unknown test type: ${TARGET_TYPE}"
      exit 1
      ;;
  esac

  # Append all raw passthrough options preserving original order
  if [[ ${#PASSTHROUGH_ARGS[@]} -gt 0 ]]; then
    CMD="${CMD} $(shell_join "${PASSTHROUGH_ARGS[@]}")"
  fi

  execute_test_command "${CMD}"
}

function usage() {
  echo "Usage: ${0} [options] [all|sanity|integration|unit|pytest] [target_path|module_name] [-- extra_args]"
  echo ""
  echo "  Options:"
  echo "       -L [ERROR|WARN|INFO|DEBUG] : Run with specified log level (default INFO)"
  echo "       -v, --version              : Show script version"
  echo "       -h, --help                 : Show this help manual"
  echo "       [extra options]            : Any extra flags pass directly to test runner (e.g. --test, --python)"
  echo ""
  echo "  Examples:"
  echo "       ${0} unit export_dicts"
  echo "       ${0} unit export_dicts --python 3.11"
  echo "       ${0} sanity --test validate-modules"
  echo "       ${0} sanity --test line-endings"
  echo "       ${0} unit export_dicts --docker"
  echo "       ${0} pytest -- -k test_my_function"
  echo "       ${0} pytest tests/unit/plugins/modules/test_prefix_validation.py"
  echo "       ${0} -L DEBUG integration"
  echo "       ${0} -v"
  [ -z "$1" ] || exit "$1"
}

function main() {
  command -v yq >/dev/null 2>&1 || { log_error "yq is required."; exit 1; }

  local TEST_TYPE=""
  local HAS_EXPLICIT_PYTHON="false"
  local PASSTHROUGH_ARGS=()

  # Parse CLI Arguments while preserving original argument sequence
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage 0
        ;;
      -v|--version)
        echo "${SCRIPT_NAME} version ${VERSION}"
        exit 0
        ;;
      -L)
        if [[ -n "$2" ]]; then
          case "${2^^}" in
            ERROR) LOG_LEVEL=${LOG_ERROR} ;;
            WARN)  LOG_LEVEL=${LOG_WARN}  ;;
            INFO)  LOG_LEVEL=${LOG_INFO}  ;;
            DEBUG) LOG_LEVEL=${LOG_DEBUG} ;;
            *)     log_error "Invalid log level: $2"; usage 1 ;;
          esac
          shift 2
        else
          log_error "-L requires an argument (ERROR|WARN|INFO|DEBUG)."
          usage 1
        fi
        ;;
      --python|--python=*)
        HAS_EXPLICIT_PYTHON="true"
        PASSTHROUGH_ARGS+=("$1")
        shift
        ;;
      --)
        # Explicit separator: everything remaining is passed through strictly as-is
        shift
        # Check if remaining arguments contain --python
        for arg in "$@"; do
          if [[ "${arg}" == "--python" || "${arg}" == --python=* ]]; then
            HAS_EXPLICIT_PYTHON="true"
            break
          fi
        done
        PASSTHROUGH_ARGS+=("$@")
        break
        ;;
      sanity|unit|units|integration|pytest)
        if [[ -z "${TEST_TYPE}" ]]; then
          TEST_TYPE="$1"
        else
          PASSTHROUGH_ARGS+=("$1")
        fi
        shift
        ;;
      *)
        PASSTHROUGH_ARGS+=("$1")
        shift
        ;;
    esac
  done

  # Fallback to default check configuration
  [[ -z "${TEST_TYPE}" ]] && TEST_TYPE="sanity"

  # Prerequisite verification based on target choice
  if [[ "${TEST_TYPE}" == "pytest" ]]; then
    command -v pytest >/dev/null 2>&1 || { log_error "pytest execution was requested but pytest is missing from the active path environment."; exit 1; }
  else
    command -v ansible-test >/dev/null 2>&1 || { log_error "ansible-test is required for the requested target execution layout."; exit 1; }
  fi

  setup_test_env

  log_info "Executing target [${TEST_TYPE}] test context..."
  run_collection_tests "${TEST_TYPE}" "${HAS_EXPLICIT_PYTHON}" "${PASSTHROUGH_ARGS[@]}"

  log_success "All requested targets completed successfully."
}

main "$@"
