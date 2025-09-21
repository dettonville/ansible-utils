#!/usr/bin/env bash

## ref: https://intoli.com/blog/exit-on-errors-in-bash-scripts/
# exit when any command fails
#set -e

VERSION="2025.9.20"

#SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"

REPO_DIR=$( git rev-parse --show-toplevel )
COLLECTIONS_DIR="${REPO_DIR}/."
#DOCS_DIR="${REPO_DIR}/docs/plugins"
DOCS_DIR="${REPO_DIR}/docs"

COLLECTION_NAMESPACE=$(yq -r '.namespace' "${REPO_DIR}/galaxy.yml")
COLLECTION_NAME=$(yq -r '.name' "${REPO_DIR}/galaxy.yml")

## For `PLUGIN_CONFIG_LIST` use the following format to specify any special PLUGIN_NAMEs
## [plugin_name]:[plugin_type]
##

#PLUGIN_CONFIG_LIST=""
PLUGIN_CONFIG_LIST=$( (find . -maxdepth 3 -type f -wholename "./plugins/modules/*.py" | sed 's|./||' \
  | sed "s|\(.*\)/\(.*\)/\(.*\).py|${COLLECTION_NAMESPACE}.${COLLECTION_NAME}.\3:\3:module|" && \
  find . -maxdepth 3 -type f -wholename "./plugins/lookup/*.py" | sed 's|./||' \
  | sed "s|\(.*\)/\(.*\)/\(.*\).py|${COLLECTION_NAMESPACE}.${COLLECTION_NAME}.\3:\3:lookup|" && \
  find . -maxdepth 3 -type f -wholename "./plugins/filter/*.py" | sed 's|./||' \
  | sed "s|\(.*\)/\(.*\)/\(.*\).py|${COLLECTION_NAMESPACE}.${COLLECTION_NAME}.\3:\3:filter|" ) \
  | sort)

DOC_PREFIX='

```shell
$ ansible --version
ansible [core 2.19.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /Users/ljohnson/.ansible/collections:/usr/share/ansible/collections
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.2 (with libyaml v0.2.5)
$
$ REPO_DIR="$( git rev-parse --show-toplevel )"
$ cd ${REPO_DIR}
$'


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
  missingCommands=""
  for currentCommand in "$@"
  do
    is_installed "${currentCommand}" || missingCommands="${missingCommands} ${currentCommand}"
  done

  if [[ -n "${missingCommands}" ]]; then
    fail "Please install the following commands required by this script:${missingCommands}"
  fi
}

function cleanup_tmpdir() {
  test "${KEEP_TEMP_DIR:-0}" = 1 || rm -rf "${TEMP_DIR}"
}

create_plugin_docs() {
  local DOCS_DIR=$1
  local COLLECTIONS_DIR=$2
  local PLUGIN_CONFIG_LIST=$3

  COLLECTION_NAMESPACE=$(yq -r '.namespace' "${REPO_DIR}/galaxy.yml")
  COLLECTION_NAME=$(yq -r '.name' "${REPO_DIR}/galaxy.yml")

  ## ref: https://www.pixelstech.net/article/1577768087-Create-temp-file-in-Bash-using-mktemp-and-trap
  ## ref: https://stackoverflow.com/questions/4632028/how-to-create-a-temporary-directory
  mkdir -p "${HOME}/tmp"
  TEMP_DIR=$(mktemp -d -p "${HOME}/tmp" "${SCRIPT_NAME_PREFIX}_XXXXXX")

  trap cleanup_tmpdir INT TERM EXIT

  COLLECTION_BASE_DIR="${TEMP_DIR}"
  COLLECTION_SOURCE_DIR="${COLLECTION_BASE_DIR}/ansible_collections/${COLLECTION_NAMESPACE}/${COLLECTION_NAME}"
  echo "COLLECTION_SOURCE_DIR=${COLLECTION_SOURCE_DIR}"

  mkdir -p "$(dirname "${COLLECTION_SOURCE_DIR}")"
  ln -s "${REPO_DIR}" "${COLLECTION_SOURCE_DIR}"
  export ANSIBLE_COLLECTIONS_PATH="${COLLECTION_BASE_DIR}:${ANSIBLE_COLLECTIONS_PATH}"
  echo "ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH}"

  echo "==> ansible --version"
  ansible --version

  ##
  ## for each PATH iteration create a soft PLUGIN_NAME back to all files found in the respective base directory (Sandbox/Prod)
  ##
  IFS=$'\n'
  for PLUGIN_CONFIG in ${PLUGIN_CONFIG_LIST}
  do

    log_debug "plugin [$PLUGIN_CONFIG]"
    # split sub-list if available
    if [[ $PLUGIN_CONFIG == *":"* ]]
    then
      # ref: https://stackoverflow.com/questions/12317483/array-of-arrays-in-bash
      # split server name from sub-list
#      PLUGIN_CONFIG_ARRAY=(${PLUGIN_CONFIG//:/})
      IFS=":" read -r -a PLUGIN_CONFIG_ARRAY <<< "$PLUGIN_CONFIG"
      PLUGIN_FQ_NAME=${PLUGIN_CONFIG_ARRAY[0]}
      PLUGIN_NAME=${PLUGIN_CONFIG_ARRAY[1]}
      PLUGIN_TYPE=${PLUGIN_CONFIG_ARRAY[2]}

      PLUGIN_DOC_PATH="${PLUGIN_NAME}.md"
#      PLUGIN_DOC_PATH="${PLUGIN_NAME//\.//}.md"
#      PLUGIN_DOC_DIR=$(dirname "${PLUGIN_DOC_PATH}")

      log_debug "PLUGIN_FQ_NAME=[$PLUGIN_FQ_NAME]"
      log_debug "PLUGIN_NAME=[$PLUGIN_NAME]"
      log_debug "PLUGIN_TYPE=[$PLUGIN_TYPE]"
#      log_debug "PLUGIN_DOC_PATH=[$PLUGIN_DOC_PATH]"
#      log_debug "PLUGIN_DOC_DIR=[$PLUGIN_DOC_DIR]"

      DOC_COMMAND="env ANSIBLE_NOCOLOR=True ansible-doc -t ${PLUGIN_TYPE} ${PLUGIN_FQ_NAME}"
      log_debug "${DOC_COMMAND}"
      eval "${DOC_COMMAND} > /dev/null 2>&1"
      local RETURN_STATUS=$?

      if [[ $RETURN_STATUS -eq 0 ]]; then
        mkdir -p "${DOCS_DIR}"
        echo "$DOC_PREFIX" > "${DOCS_DIR}/${PLUGIN_DOC_PATH}"
        echo "\$ ${DOC_COMMAND} | tee ${DOCS_DIR}/${PLUGIN_DOC_PATH}" >> "${DOCS_DIR}/${PLUGIN_DOC_PATH}"
        eval "$DOC_COMMAND >> ${DOCS_DIR}/${PLUGIN_DOC_PATH}"
        echo '```' >> "${DOCS_DIR}/${PLUGIN_DOC_PATH}"
        log_info "Successfully created [$PLUGIN_DOC_PATH]"
      else
        log_info "Issue when running [$DOC_COMMAND]: skipping"
      fi

    fi

  done

}

function usage() {
  echo "Usage: ${SCRIPT_NAME} [options]"
  echo ""
  echo "  Options:"
  echo "       -L [ERROR|WARN|INFO|TRACE|DEBUG] : run with specified log level (default: '${LOGLEVEL_TO_STR[${LOG_LEVEL}]}')"
  echo "       -v : show script version"
  echo "       -h : help"
  echo "     [TEST_CASES]"
  echo ""
  echo "  Examples:"
	echo "       ${SCRIPT_NAME} "
	echo "       ${SCRIPT_NAME} -L DEBUG"
  echo "       ${SCRIPT_NAME} -v"
	[ -z "$1" ] || exit "$1"
}

function main() {

  check_required_commands ansible-doc

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

  log_debug "REPO_DIR=${REPO_DIR}"

  log_debug "DOC_PREFIX=${DOC_PREFIX}"
  #log_debug "SCRIPT_DIR=${SCRIPT_DIR}"
  log_debug "REPO_DIR=${REPO_DIR}"
  log_debug "DOCS_DIR=${DOCS_DIR}"
  log_debug "PLUGIN_CONFIG_LIST=${PLUGIN_CONFIG_LIST}"

  create_plugin_docs "${DOCS_DIR}" "${COLLECTIONS_DIR}" "${PLUGIN_CONFIG_LIST}"

}

main "$@"
