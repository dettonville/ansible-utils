#!/usr/bin/env bash

VERSION="2025.6.9"

SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_NAME_PREFIX="${SCRIPT_NAME%.*}"
PROJECT_DIR="$(cd "${SCRIPT_DIR}" && git rev-parse --show-toplevel)"
#PROJECT_DIR="$( git rev-parse --show-toplevel )"

TEST_BASE_DIR="${PROJECT_DIR}/tests"

TEST_COLLECTION_SOURCE_DIR="$( basename "${PROJECT_DIR}" )"
## ref: https://www.pixelstech.net/article/1577768087-Create-temp-file-in-Bash-using-mktemp-and-trap
## ref: https://stackoverflow.com/questions/4632028/how-to-create-a-temporary-directory
mkdir -p "${HOME}/tmp"
TEMP_DIR=$(mktemp -d -p "${HOME}/tmp" "${SCRIPT_NAME_PREFIX}_XXXXXX")

trap cleanup_tmpdir INT TERM EXIT

TEST_COLLECTION_BASE_DIR="${TEMP_DIR}"
TEST_COLLECTION_SOURCE_DIR="${TEMP_DIR}/ansible_collections/${COLLECTION_NAMESPACE}/${COLLECTION_NAME}"
echo "TEST_COLLECTION_SOURCE_DIR=${TEST_COLLECTION_SOURCE_DIR}"

#TEST_COLLECTION_BASE_DIR="${PROJECT_DIR}/ansible_collections"

TEST_MODULES="
export_dicts
git_pacp
"

TEST_CASE_CONFIGS=("sanity")
TEST_CASE_CONFIGS+=("integration")
TEST_CASE_CONFIGS+=("unit")


#PYTHON_TEST_VERSION="3.10"
PYTHON_TEST_VERSION="3.12"

## ref: https://www.xmodulo.com/catch-handle-errors-bash.html
try()
{
    [[ $- = *e* ]]; SAVED_OPT_E=$?
    set +e
}

throw()
{
    exit "$1"
}

catch()
{
    export exception_code=$?
    [ "${SAVED_OPT_E}" -ne 0 ] && set +e
    return $exception_code
}


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
  # Iterate over the keys of the LOGLEVEL_TO_STR array
  for KEY in "${!ARRAY_SOURCE_REF[@]}"; do
    # Get the value associated with the current key
    VALUE="${ARRAY_SOURCE_REF[$KEY]}"
    # Add the reversed key-value pair to the REVERSED_ARRAY_REF array
    REVERSED_ARRAY_REF["$VALUE"]="$KEY"
  done
}

declare -A LOGLEVELSTR_TO_LEVEL
reverse_array LOGLEVEL_TO_STR LOGLEVELSTR_TO_LEVEL

#LOG_LEVEL=${LOG_DEBUG}
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

function ohai() {
  printf "${tty_blue}==>${tty_bold} %s${tty_reset}\n" "$(shell_join "$@")"
}

function abort() {
  log_error "$@"
  exit 1
}

function warn() {
  log_warn "$@"
#  log_warn "$(chomp "$1")"
#  printf "${tty_red}Warning${tty_reset}: %s\n" "$(chomp "$1")" >&2
}

#function abort() {
#  printf "%s\n" "$@" >&2
#  exit 1
#}

function error() {
  log_error "$@"
#  printf "%s\n" "$@" >&2
##  echo "$@" 1>&2;
}

function fail() {
  error "$@"
  exit 1
}

function log_message() {
  local LOG_MESSAGE_LEVEL="${1}"
  local LOG_MESSAGE="${2}"
  ## remove first item from FUNCNAME array
#  local CALLING_FUNCTION_ARRAY=("${FUNCNAME[@]:2}")
  ## Get the length of the array
  local CALLING_FUNCTION_ARRAY_LENGTH=${#FUNCNAME[@]}
  local CALLING_FUNCTION_ARRAY=("${FUNCNAME[@]:2:$((CALLING_FUNCTION_ARRAY_LENGTH - 3))}")
#  echo "CALLING_FUNCTION_ARRAY[@]=${CALLING_FUNCTION_ARRAY[@]}"

  local CALL_ARRAY_LENGTH=${#CALLING_FUNCTION_ARRAY[@]}
  local REVERSED_CALL_ARRAY=()
  for (( i = CALL_ARRAY_LENGTH - 1; i >= 0; i-- )); do
    REVERSED_CALL_ARRAY+=( "${CALLING_FUNCTION_ARRAY[i]}" )
  done
#  echo "REVERSED_CALL_ARRAY[@]=${REVERSED_CALL_ARRAY[@]}"

#  local CALLING_FUNCTION_STR="${CALLING_FUNCTION_ARRAY[*]}"
  ## ref: https://stackoverflow.com/questions/1527049/how-can-i-join-elements-of-a-bash-array-into-a-delimited-string#17841619
  local SEPARATOR=":"
  local CALLING_FUNCTION_STR
  CALLING_FUNCTION_STR=$(printf "${SEPARATOR}%s" "${REVERSED_CALL_ARRAY[@]}")
  CALLING_FUNCTION_STR=${CALLING_FUNCTION_STR:${#SEPARATOR}}

  ## ref: https://stackoverflow.com/a/13221491
  if [ "${LOGLEVEL_TO_STR[${LOG_MESSAGE_LEVEL}]+abc}" ]; then
    LOG_LEVEL_STR="${LOGLEVEL_TO_STR[${LOG_MESSAGE_LEVEL}]}"
  else
    abort "Unknown log level of [${LOG_MESSAGE_LEVEL}]"
  fi

  local LOG_LEVEL_PADDING_LENGTH=5

  local PADDED_LOG_LEVEL
  PADDED_LOG_LEVEL=$(printf "%-${LOG_LEVEL_PADDING_LENGTH}s" "${LOG_LEVEL_STR}")

  local LOG_PREFIX="${CALLING_FUNCTION_STR}():"
  local __LOG_MESSAGE="${LOG_PREFIX} ${LOG_MESSAGE}"
#  echo -e "[${PADDED_LOG_LEVEL}]: ==> ${__LOG_MESSAGE}"
  if [ "${LOG_MESSAGE_LEVEL}" -eq $LOG_INFO ]; then
    printf "${tty_blue}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
#    printf "${tty_blue}[${PADDED_LOG_LEVEL}]: ==>${tty_reset} %s\n" "${__LOG_MESSAGE}" >&2
#    printf "${tty_blue}[${PADDED_LOG_LEVEL}]: ==>${tty_bold} %s${tty_reset}\n" "${__LOG_MESSAGE}"
  elif [ "${LOG_MESSAGE_LEVEL}" -eq $LOG_WARN ]; then
    printf "${tty_orange}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
#    printf "${tty_orange}[${PADDED_LOG_LEVEL}]: ==>${tty_bold} %s${tty_reset}\n" "${__LOG_MESSAGE}" >&2
#    printf "${tty_red}Warning${tty_reset}: %s\n" "$(chomp "$1")" >&2
  elif [ "${LOG_MESSAGE_LEVEL}" -le $LOG_ERROR ]; then
    printf "${tty_red}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
#    printf "${tty_red}[${PADDED_LOG_LEVEL}]: ==>${tty_bold} %s${tty_reset}\n" "${__LOG_MESSAGE}" >&2
#    printf "${tty_red}Warning${tty_reset}: %s\n" "$(chomp "$1")" >&2
  else
    printf "${tty_bold}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
#    printf "[${PADDED_LOG_LEVEL}]: ==> %s\n" "${LOG_PREFIX} ${LOG_MESSAGE}"
  fi
}

function set_log_level() {
  LOG_LEVEL_STR=$1

  ## ref: https://stackoverflow.com/a/13221491
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
#  COMMAND_RESULT=$(eval "${RUN_COMMAND} > /dev/null 2>&1")
  local RETURN_STATUS=$?

  if [[ $RETURN_STATUS -eq 0 ]]; then
    if [[ $COMMAND_RESULT != "" ]]; then
      log_debug "${COMMAND_RESULT}"
    fi
    log_debug "SUCCESS!"
  else
    log_error "ERROR (${RETURN_STATUS})"
#    echo "${COMMAND_RESULT}"
    abort "$(printf "Failed during: %s" "${COMMAND_RESULT}")"
  fi

}

function is_installed() {
  command -v "${1}" >/dev/null 2>&1 || return 1
}

function check_required_commands() {
  MISSING_COMMANDS=""
  for CURRENT_COMMAND in "$@"
  do
    is_installed "${CURRENT_COMMAND}" || MISSING_COMMANDS="${MISSING_COMMANDS} ${CURRENT_COMMAND}"
  done

  if [[ -n "${MISSING_COMMANDS}" ]]; then
    fail "Please install the following commands required by this script: ${MISSING_COMMANDS}"
  fi
}

setup_test_env() {

  log_info "TEST_COLLECTION_BASE_DIR=${TEST_COLLECTION_BASE_DIR}"
  log_info "TEST_COLLECTION_SOURCE_DIR=${TEST_COLLECTION_SOURCE_DIR}"
  log_info "TEST_COLLECTION_NAME=${TEST_COLLECTION_NAME}"
  log_info "TEST_COLLECTION_DIR=${TEST_COLLECTION_DIR}"

  mkdir -p "$(dirname "${TEST_COLLECTION_SOURCE_DIR}")"
  LINK_CMD="ln -s ${PROJECT_DIR} ${TEST_COLLECTION_SOURCE_DIR}"
  execute_eval_command "${LINK_CMD}"
  export ANSIBLE_COLLECTIONS_PATH="${TEST_COLLECTION_BASE_DIR}:${ANSIBLE_COLLECTIONS_PATH}"
  echo "ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH}"

#  mkdir -p "${TEST_COLLECTION_BASE_DIR}/${TEST_COLLECTION_NAMESPACE}"
#  log_info "cd ${TEST_COLLECTION_BASE_DIR}/${TEST_COLLECTION_NAMESPACE}"
#  execute_eval_command "cd ${TEST_COLLECTION_BASE_DIR}/${TEST_COLLECTION_NAMESPACE}"

#  if [ ! -d "${TEST_COLLECTION_NAME}" ]; then
#    LINK_CMD="ln -sf ../.. ${TEST_COLLECTION_NAME}"
#    execute_eval_command "${LINK_CMD}"
#  fi

}


function run_test_case() {
  local TEST_CASE_ID=$1
  local TEST_FUNCTION=$2
  local TEST_CASES_STR=$3
  shift 3

  local RETURN_STATUS=0

  local TEST_ARGS=()
  if [ $# -gt 0 ]; then
    TEST_ARGS=("${@}")
  fi

  if stringContain "${TEST_CASE_ID}" "${TEST_CASES_STR}" ||
     stringContain "${TEST_FUNCTION}" "${TEST_CASES_STR}" ||
     [ "${TEST_CASES_STR}" == "ALL" ]
  then
    log_debug "Run test [${TEST_FUNCTION}]"

    local TEST_COMMAND="${TEST_FUNCTION}"
    log_debug "TEST_COMMAND=${TEST_COMMAND}"

#    local TEST_RESULTS=$(${TEST_FUNCTION} "${TEST_ARGS[*]}")
#    local TEST_RESULTS=$(eval "${TEST_FUNCTION} ${TEST_ARGS[*]}")
    eval "${TEST_FUNCTION} ${TEST_ARGS[*]} >/dev/null 2>&1"
    local RETURN_STATUS=$?

    if [[ $RETURN_STATUS -eq 0 ]]; then
      log_info "${TEST_FUNCTION}: SUCCESS"
    else
      log_error "${TEST_FUNCTION}: FAILED"
    fi

    if [[ $RETURN_STATUS -ne 0 || $DISPLAY_TEST_RESULTS -gt 0 ]]; then
      log_info "TEST_RESULTS ****"
      eval "${TEST_FUNCTION} ${TEST_ARGS[*]}"
    fi
    log_debug "RETURN_STATUS=${RETURN_STATUS}"
  fi
  log_debug "TEST_CASE_IDX=${TEST_CASE_IDX_PADDED} TEST_CASE=${TEST_CASE_ID} RETURN_STATUS=${RETURN_STATUS} ERROR_COUNT=${ERROR_COUNT}"
  return "${RETURN_STATUS}"

}


run_collection_tests() {
  local TEST_COLLECTION_NAMESPACE=${1}
  local TEST_COLLECTION_NAME=${2}
  local PYTHON_TEST_VERSION=${3}
  local MODULE=${4}
  shift 4
  local TEST_CASES=("${@}")
#  local TEST_CASES="$1"

  log_info "TEST_CASES[*]=${TEST_CASES[*]}"
  log_info "MODULE=${MODULE}"

  TEST_COLLECTION="${TEST_COLLECTION_NAMESPACE}.${TEST_COLLECTION_NAME}"
  TEST_COLLECTION_DIR="${TEST_COLLECTION_BASE_DIR}/${TEST_COLLECTION_NAMESPACE}/${TEST_COLLECTION_NAME}"

  log_info "TEST_COLLECTION=${TEST_COLLECTION}"
  log_info "TEST_COLLECTION_DIR=${TEST_COLLECTION_DIR}"

#  TEST_RESULTS_FILENAME="${SCRIPT_NAME_PREFIX}.${TEST_COLLECTION}.results.${TEST_RESULTS_TIMESTAMP}.log"
#  TEST_RESULTS_FILENAME="${SCRIPT_NAME_PREFIX}.${TEST_COLLECTION}.results.log"
  TEST_RESULTS_FILENAME="${SCRIPT_NAME_PREFIX}.${TEST_COLLECTION}.${MODULE}.results.log"

  log_info "TEST_RESULTS_FILENAME=${TEST_RESULTS_FILENAME}"

  TEST_RESULTS_FILE="${TEST_BASE_DIR}/${TEST_RESULTS_FILENAME}"
  log_info "TEST_RESULTS_FILE=${TEST_RESULTS_FILE}"

#  log_info "cd ${TEST_COLLECTION_DIR}"
#  cd "${TEST_COLLECTION_DIR}"
  execute_eval_command "cd ${TEST_COLLECTION_DIR}"

  log_info "PWD=${PWD}"

  # shellcheck disable=SC2194
  case "all sanity" in *"${TEST_CASES[*]}"*)
    CMD_ANSIBLE_TEST_SANITY="ansible-test sanity -v --python ${PYTHON_TEST_VERSION} ${MODULE}"
    ## #ansible-test sanity -v --color --coverage --junit --docker default --python 3.11
    ;;
  esac

  # shellcheck disable=SC2194
  case "all units" in *"${TEST_CASES[*]}"*)
    CMD_ANSIBLE_TEST_UNIT="ansible-test units -v --python ${PYTHON_TEST_VERSION} ${MODULE}"
    ;;
  esac

  # shellcheck disable=SC2194
  case "all integration" in *"${TEST_CASES[*]}"*)
    CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --python ${PYTHON_TEST_VERSION} ${MODULE}"
    ;;
  esac

  log_info "TEST_RESULTS_FILE=${TEST_RESULTS_FILE}"

  echo "*****************************" | tee -a "${TEST_RESULTS_FILE}"
  echo "Run sanity tests" | tee -a "${TEST_RESULTS_FILE}"
  echo "${CMD_ANSIBLE_TEST_SANITY}" | tee -a "${TEST_RESULTS_FILE}"
  eval "${CMD_ANSIBLE_TEST_SANITY}" | tee -a "${TEST_RESULTS_FILE}"

  echo "*****************************" | tee -a "${TEST_RESULTS_FILE}"
  echo "Run unit tests" | tee -a "${TEST_RESULTS_FILE}"
  echo "${CMD_ANSIBLE_TEST_UNIT}" | tee -a "${TEST_RESULTS_FILE}"
  eval "${CMD_ANSIBLE_TEST_UNIT}" | tee -a "${TEST_RESULTS_FILE}"

  echo "*****************************" | tee -a "${TEST_RESULTS_FILE}"
  echo "Run integration tests" | tee -a "${TEST_RESULTS_FILE}"
  echo "${CMD_ANSIBLE_TEST_INTEGRATION}" | tee -a "${TEST_RESULTS_FILE}"
  eval "${CMD_ANSIBLE_TEST_INTEGRATION}" | tee -a "${TEST_RESULTS_FILE}"

  exit ${?}
}

run_tests() {
  local TEST_COLLECTION_NAMESPACE=${1}
  local TEST_COLLECTION_NAME=${2}
  shift 2

  local TEST_CASES=("${@}")

  log_info "SCRIPT_NAME=${SCRIPT_NAME}"
  log_info "TEST_CASES=${TEST_CASES[*]}"

  #TEST_RESULTS_TIMESTAMP="$(date -Id)_$(date +%H-%M-%S)"

  setup_test_env

  for MODULE in ${TEST_MODULES}
  do

      log_info "MODULE=${MODULE}"

      ANSIBLE_MODULE_FQDN="${TEST_COLLECTION}.${MODULE}"
      log_info "ANSIBLE_MODULE_FQDN=${ANSIBLE_MODULE_FQDN}"

      log_info "Run Collection Tests on ${ANSIBLE_MODULE_FQDN}"
      RUN_COMMAND_WITH_ARGS_ARRAY=("run_collection_tests")
      RUN_COMMAND_WITH_ARGS_ARRAY+=("${TEST_COLLECTION_NAMESPACE} ${TEST_COLLECTION_NAME}")
      RUN_COMMAND_WITH_ARGS_ARRAY+=("${PYTHON_TEST_VERSION} ${MODULE}")
      RUN_COMMAND_WITH_ARGS_ARRAY+=("${TEST_CASES[*]}")
      execute_eval_command "${RUN_COMMAND_WITH_ARGS_ARRAY[*]}"

  done
}

function usage() {
  echo "Usage: ${0} [options] [all|sanity|integration|unit]"
  echo ""
  echo "  Options:"
  echo "       -L [ERROR|WARN|INFO|TRACE|DEBUG] : run with specified log level (default INFO)"
  echo "       -v : show script version"
  echo "       -h : help"
  echo "     [TEST_CASES]"
  echo ""
  echo "  Examples:"
	echo "       ${0} "
	echo "       ${0} sanity"
	echo "       ${0} integration"
	echo "       ${0} -L DEBUG"
  echo "       ${0} -v"
	[ -z "$1" ] || exit "$1"
}


function main() {

  check_required_commands ansible ansible-test yq

  while getopts "L:vh" opt; do
      case "${opt}" in
          L) set_log_level "${OPTARG}" ;;
          v) echo "${VERSION}" && exit ;;
          h) usage 1 ;;
          \?) usage 2 ;;
          *) usage ;;
      esac
  done
  shift $((OPTIND-1))

  TEST_CASES=("all")
  if [ $# -gt 0 ]; then
    TEST_CASES=("$@")
  fi

  TEST_COLLECTION_NAMESPACE=$(yq -r '.namespace' "${PROJECT_DIR}/galaxy.yml")
  TEST_COLLECTION_NAME=$(yq -r '.name' "${PROJECT_DIR}/galaxy.yml")

  log_debug "PROJECT_DIR=${PROJECT_DIR}"
  log_debug "TEST_BASE_DIR=${TEST_BASE_DIR}"

  run_tests "${TEST_COLLECTION_NAMESPACE}" "${TEST_COLLECTION_NAME}" "${TEST_CASES[*]}"

}

main "$@"
