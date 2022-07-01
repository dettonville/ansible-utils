#!/usr/bin/env bash

TEST_MODULES="
export_dicts
"

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


run_module_tests() {
  MODULE_PATH=$1
  TEST_RESULTS_FILE_NAME=$2

  CURRENT_DIR=${PWD}

  MODULE="$(basename "${MODULE_PATH}")"
  MODULE_DIR=${CURRENT_DIR}/${MODULE_PATH}

#  TEST_DIR=${PROJECT_DIR}/collections/ansible_collections/dettonville/utils
  ## Set TEST_DIR to parent of MODULE_DIR
  TEST_DIR="$(dirname "${MODULE_DIR}")"
  TEST_RESULTS_FILE="${CURRENT_DIR}/tests/${TEST_RESULTS_FILE_NAME}"

  echo "MODULE=$MODULE"
  echo "MODULE_PATH=$MODULE_PATH"
#  echo "MODULE_DIR=$MODULE_DIR"

  echo "TEST_DIR=$TEST_DIR"
  echo "TEST_RESULTS_FILE=$TEST_RESULTS_FILE"

  cd "${TEST_DIR}"
  echo "*****************************" | tee -a "${TEST_RESULTS_FILE}"
  echo "Run sanity tests" | tee -a "${TEST_RESULTS_FILE}"
  echo "ansible-test sanity -v --docker --python 3.9 ${MODULE}" | tee -a "${TEST_RESULTS_FILE}"
  ansible-test sanity -v --docker --python 3.9 "${MODULE}" | tee -a "${TEST_RESULTS_FILE}"
  echo "*****************************" | tee -a "${TEST_RESULTS_FILE}"
  echo "Run integration tests" | tee -a "${TEST_RESULTS_FILE}"
  echo "ansible-test integration ${MODULE}" | tee -a "${TEST_RESULTS_FILE}"
  ansible-test integration "${MODULE}" | tee -a "${TEST_RESULTS_FILE}"

  exit ${?}
}


SCRIPT_FILE=$(basename "$0")

TEST_RESULTS_FILE_BASE="${SCRIPT_FILE%.*}"

echo "SCRIPT_FILE=${SCRIPT_FILE}"
echo "TEST_RESULTS_FILE_BASE=${TEST_RESULTS_FILE_BASE}"

TEST_RESULTS_TIMESTAMP="$(date -Id)_$(date +%H-%M-%S)"

IFS=$'\n'
for MODULE_PATH in ${TEST_MODULES}
do
  MODULE="$(basename "${MODULE_PATH}")"

  TEST_RESULTS_FILENAME="${TEST_RESULTS_FILE_BASE}.${MODULE}.results.${TEST_RESULTS_TIMESTAMP}.log"

  echo "MODULE=${MODULE}"
  echo "TEST_RESULTS_FILENAME=${TEST_RESULTS_FILENAME}"

  echo "Run Module Tests for ${MODULE}"
  RUN_COMMAND_WITH_ARGS="run_module_tests ${MODULE_PATH} ${TEST_RESULTS_FILENAME}"
  echo "${RUN_COMMAND_WITH_ARGS}"
#  eval ${RUN_COMMAND_WITH_ARGS}

  try
  (
    eval "${RUN_COMMAND_WITH_ARGS}"
  )
  catch || {
    export exception_code=$?
    echo "Error occurred: $exception_code"
    throw "$exception_code"    # re-throw an unhandled exception
  }



done


