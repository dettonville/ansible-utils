#!/usr/bin/env bash

## ref: https://intoli.com/blog/exit-on-errors-in-bash-scripts/
# exit when any command fails
#set -e

VERSION="2026.8.3"

SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"

REPO_DIR=$( git rev-parse --show-toplevel )
COLLECTIONS_DIR="${REPO_DIR}/."
DOCS_DIR="${REPO_DIR}/docs"

COLLECTION_NAMESPACE=$(yq -r '.namespace' "${REPO_DIR}/galaxy.yml")
COLLECTION_NAME=$(yq -r '.name' "${REPO_DIR}/galaxy.yml")

FORCE_UPDATE=0

# Dynamically construct DOC_PREFIX based on runtime `ansible --version` output
generate_doc_prefix() {
  local ANSIBLE_VER_OUTPUT
  ANSIBLE_VER_OUTPUT=$(ansible --version 2>&1)

  cat <<EOF

\`\`\`shell
$ ansible --version
${ANSIBLE_VER_OUTPUT}
$ REPO_DIR="\$( git rev-parse --show-toplevel )"
$ cd \${REPO_DIR}
EOF
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
  for KEY in "${!ARRAY_SOURCE_REF[@]}"; do
    VALUE="${ARRAY_SOURCE_REF[$KEY]}"
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

function abort() {
  log_error "$@"
  exit 1
}

function fail() {
  log_error "$@"
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
    printf "${tty_blue}[${PADDED_LOG_LEVEL}]: ==>${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
  elif [ "${LOG_MESSAGE_LEVEL}" -eq $LOG_WARN ]; then
    printf "${tty_orange}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
  elif [ "${LOG_MESSAGE_LEVEL}" -le $LOG_ERROR ]; then
    printf "${tty_red}[${PADDED_LOG_LEVEL}]: ==> ${LOG_PREFIX}${tty_bold} %s${tty_reset}\n" "${LOG_MESSAGE}" >&2
  else
    printf "${tty_bold}[${PADDED_LOG_LEVEL}]: ==>${LOG_PREFIX}${tty_reset} %s\n" "${LOG_MESSAGE}" >&2
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

# Helper method to extract plugin name(s) from DOCUMENTATION string blocks inside source python files
extract_plugin_names() {
  local src_path=$1
  local fallback_name=$2

  local names
  names=$(python3 - "$src_path" <<'PYEOF'
import sys, re, yaml

src_file = sys.argv[1]
with open(src_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Match DOCUMENTATION or DOCUMENTATION_<suffix> triple-quoted string blocks
pattern = re.compile(r'DOCUMENTATION\w*\s*=\s*"""(.*?)"""', re.DOTALL)
matches = pattern.findall(content)

found_names = []
for doc_str in matches:
    try:
        data = yaml.safe_load(doc_str)
        if isinstance(data, dict) and 'name' in data:
            found_names.append(str(data['name']).strip())
    except Exception:
        pass

if found_names:
    print("\n".join(found_names))
PYEOF
  )

  if [[ -n "${names}" ]]; then
    echo "${names}"
  else
    echo "${fallback_name}"
  fi
}

create_plugin_docs() {
  local DOCS_DIR=$1
  local COLLECTIONS_DIR=$2
  local ERRORS_FOUND=0

  COLLECTION_NAMESPACE=$(yq -r '.namespace' "${REPO_DIR}/galaxy.yml")
  COLLECTION_NAME=$(yq -r '.name' "${REPO_DIR}/galaxy.yml")

  log_debug "COLLECTION_NAMESPACE=[${COLLECTION_NAMESPACE}]"
  log_debug "COLLECTION_NAME=[${COLLECTION_NAME}]"

  mkdir -p "${HOME}/tmp"
  TEMP_DIR=$(mktemp -d -p "${HOME}/tmp" "${SCRIPT_NAME_PREFIX}_XXXXXX")

  trap cleanup_tmpdir INT TERM EXIT

  COLLECTION_BASE_DIR="${TEMP_DIR}"
  COLLECTION_SOURCE_DIR="${COLLECTION_BASE_DIR}/ansible_collections/${COLLECTION_NAMESPACE}/${COLLECTION_NAME}"

  mkdir -p "$(dirname "${COLLECTION_SOURCE_DIR}")"
  ln -s "${REPO_DIR}" "${COLLECTION_SOURCE_DIR}"
  export ANSIBLE_COLLECTIONS_PATH="${COLLECTION_BASE_DIR}:${ANSIBLE_COLLECTIONS_PATH}"

  log_debug "TEMP_DIR=[${TEMP_DIR}]"
  log_debug "COLLECTION_SOURCE_DIR=[${COLLECTION_SOURCE_DIR}]"
  log_debug "ANSIBLE_COLLECTIONS_PATH=[${ANSIBLE_COLLECTIONS_PATH}]"

  DOC_PREFIX=$(generate_doc_prefix)

  # Find all python plugin source files relative to REPO_DIR
  local PLUGIN_FILES
  PLUGIN_FILES=$(find plugins/modules plugins/lookup plugins/filter -maxdepth 2 -type f -name "*.py" 2>/dev/null | sort)

  log_debug "Discovered PLUGIN_FILES:"
  for f in ${PLUGIN_FILES}; do log_debug "  -> ${f}"; done

  for PLUGIN_SRC_RELATIVE in ${PLUGIN_FILES}
  do
    log_debug "--------------------------------------------------------"
    log_debug "Processing relative file: [${PLUGIN_SRC_RELATIVE}]"

    # Extract plugin type (modules, lookup, filter)
    local PLUGIN_TYPE_DIR
    PLUGIN_TYPE_DIR=$(echo "${PLUGIN_SRC_RELATIVE}" | cut -d'/' -f2)

    # Map directory name to ansible-doc -t type flag
    local PLUGIN_TYPE="${PLUGIN_TYPE_DIR}"
    if [[ "${PLUGIN_TYPE_DIR}" == "modules" ]]; then
      PLUGIN_TYPE="module"
    fi

    local FILE_BASE_NAME
    FILE_BASE_NAME=$(basename "${PLUGIN_SRC_RELATIVE}" .py)

    # Skip standard python package init files if present
    if [[ "${FILE_BASE_NAME}" == "__init__" ]]; then
      log_debug "Skipping __init__.py file"
      continue
    fi

    local PLUGIN_SRC_PATH="${REPO_DIR}/${PLUGIN_SRC_RELATIVE}"

    # Extract internal plugin name(s) defined in DOCUMENTATION variables
    local INTERNAL_NAMES
    INTERNAL_NAMES=$(extract_plugin_names "${PLUGIN_SRC_PATH}" "${FILE_BASE_NAME}")

    for PLUGIN_NAME in ${INTERNAL_NAMES}
    do
      local PLUGIN_FQ_NAME="${COLLECTION_NAMESPACE}.${COLLECTION_NAME}.${PLUGIN_NAME}"
      local PLUGIN_DOC_PATH="${DOCS_DIR}/${PLUGIN_NAME}.md"

      log_debug "  PLUGIN_TYPE_DIR=[${PLUGIN_TYPE_DIR}]"
      log_debug "  PLUGIN_TYPE=[${PLUGIN_TYPE}]"
      log_debug "  PLUGIN_NAME=[${PLUGIN_NAME}]"
      log_debug "  PLUGIN_FQ_NAME=[${PLUGIN_FQ_NAME}]"
      log_debug "  PLUGIN_SRC_PATH=[${PLUGIN_SRC_PATH}]"
      log_debug "  PLUGIN_DOC_PATH=[${PLUGIN_DOC_PATH}]"

      # Force update or timestamp check logic
      if [[ "${FORCE_UPDATE}" -eq 1 ]]; then
        log_debug "  Force mode active. Rebuilding documentation..."
      elif [[ -f "${PLUGIN_DOC_PATH}" && -f "${PLUGIN_SRC_PATH}" ]]; then
        log_debug "  Both doc and src exist. Comparing timestamps..."
        if [[ "${PLUGIN_SRC_PATH}" -ot "${PLUGIN_DOC_PATH}" ]]; then
          log_info "Skipping [${PLUGIN_NAME}.md]: Documentation is up to date."
          continue
        else
          log_debug "  Source file is NEWER than doc file. Rebuilding documentation..."
        fi
      else
        log_debug "  Doc file missing or src missing. Forcing generation..."
      fi

      DOC_COMMAND="env ANSIBLE_NOCOLOR=True ansible-doc -t ${PLUGIN_TYPE} ${PLUGIN_FQ_NAME}"
      log_debug "  DOC_COMMAND string: [${DOC_COMMAND}]"

      # Execute and capture stderr output
      CMD_ERR=$(eval "${DOC_COMMAND}" 2>&1 >/dev/null)
      local RETURN_STATUS=$?

      log_debug "  RETURN_STATUS=[${RETURN_STATUS}]"

      if [[ $RETURN_STATUS -eq 0 ]]; then
        mkdir -p "${DOCS_DIR}"
        echo "$DOC_PREFIX" > "${PLUGIN_DOC_PATH}"
        {
          echo "\$ ${DOC_COMMAND} | tee ${PLUGIN_DOC_PATH}"
          eval "${DOC_COMMAND}" 2>&1
          echo '```'
        } >> "${PLUGIN_DOC_PATH}"
        log_info "Successfully created [${PLUGIN_NAME}.md]"
      else
        log_error "Failed executing [${DOC_COMMAND}] (exit code: ${RETURN_STATUS})"
        if [[ -n "${CMD_ERR}" ]]; then
          log_error "  ansible-doc stderr:"
          log_error "  ${CMD_ERR}"
        fi
        ERRORS_FOUND=1
      fi
    done

  done

  return ${ERRORS_FOUND}
}

function usage() {
  echo "Usage: ${SCRIPT_NAME} [options]"
  echo ""
  echo "  Options:"
  echo "       -f, --force                      : force update of all plugin documentation"
  echo "       -L [ERROR|WARN|INFO|TRACE|DEBUG] : run with specified log level (default: '${LOGLEVEL_TO_STR[${LOG_LEVEL}]}')"
  echo "       -v                               : show script version"
  echo "       -h, --help                       : help"
  echo ""
  echo "  Examples:"
	echo "       ${SCRIPT_NAME}"
	echo "       ${SCRIPT_NAME} -f"
	echo "       ${SCRIPT_NAME} --force -L DEBUG"
  echo "       ${SCRIPT_NAME} -v"
	[ -z "$1" ] || exit "$1"
}

function main() {
  check_required_commands ansible-doc yq python3

  while [[ $# -gt 0 ]]; do
      case "$1" in
          -f|--force)
              FORCE_UPDATE=1
              shift
              ;;
          -L)
              set_log_level "$2"
              shift 2
              ;;
          -v)
              echo "${VERSION}"
              exit 0
              ;;
          -h|--help)
              usage 1
              ;;
          *)
              echo "Unknown option: $1"
              usage 2
              ;;
      esac
  done

  create_plugin_docs "${DOCS_DIR}" "${COLLECTIONS_DIR}"
  local SCRIPT_RC=$?

  if [[ $SCRIPT_RC -ne 0 ]]; then
    log_error "Documentation generation failed for one or more plugins."
    exit $SCRIPT_RC
  fi

  log_info "Documentation generation complete."
  exit 0
}

main "$@"
