#!/usr/bin/env bash

TEST_COLLECTIONS="
ansible_collections/dettonville/utils
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


run_collection_tests() {
  COLLECTION_PATH=$1
  TEST_RESULTS_FILE_NAME=$2

  echo "COLLECTION_PATH=$COLLECTION_PATH"

  CURRENT_DIR=${PWD}

  ## ref: https://stackoverflow.com/questions/229551/how-to-check-if-a-string-contains-a-substring-in-bash
  if [[ -d "${COLLECTION_PATH}" ]]; then
    COLLECTION_DIR=${CURRENT_DIR}/${COLLECTION_PATH}
    echo "Changing to COLLECTION_DIR=${COLLECTION_DIR}"
    cd "${COLLECTION_DIR}"
  else
    COLLECTION_DIR=${CURRENT_DIR}
    echo "Already in test COLLECTION_DIR=${COLLECTION_DIR}"
  fi

#  if [[ ${CURRENT_DIR} == *"${COLLECTION_PATH}"* ]]; then
#    COLLECTION_DIR=${CURRENT_DIR}
#    echo "Already in test COLLECTION_DIR=${COLLECTION_DIR}"
#  else
#    COLLECTION_DIR=${CURRENT_DIR}/${COLLECTION_PATH}
#    echo "Changing to COLLECTION_DIR=${COLLECTION_DIR}"
#    cd "${COLLECTION_DIR}"
#  fi


  TEST_DIR="${COLLECTION_DIR}"
  TEST_RESULTS_FILE="${CURRENT_DIR}/tests/${TEST_RESULTS_FILE_NAME}"

  PYTHON_TEST_VERSION="3.9"

#  CMD_ANSIBLE_TEST_SANITY="ansible-test sanity -v --docker --python ${PYTHON_TEST_VERSION}"
  CMD_ANSIBLE_TEST_SANITY="ansible-test sanity --docker default -v"

  CMD_ANSIBLE_TEST_UNIT="ansible-test units --docker default --python ${PYTHON_TEST_VERSION} -v"

  ## ref: https://github.com/ansible/ansible/issues/72528
  # ansible-test integration shippable/ --docker ubuntu1804
  # ansible-test integration --color -v --retry-on-error shippable/cloud/group1/ --coverage --remote-terminate always --remote-stage prod --docker --python 3.8
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v shippable/ --docker --python 3.9"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker --python 3.9"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v shippable/ --docker ubuntu1804 --controller docker:default"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker ubuntu2004"

  ## Can use custom docker container to run test (works)
  ## ref: https://www.jeffgeerling.com/blog/2019/how-add-integration-tests-ansible-collection-ansible-test
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker geerlingguy/docker-centos8-ansible --python 3.8"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker geerlingguy/docker-ubuntu1804-ansible --python 3.8"
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker geerlingguy/docker-ubuntu2004-ansible --python 3.8"

  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker --python 3.9"

  ## Using default container (works)
#  CMD_ANSIBLE_TEST_INTEGRATION="ansible-test integration -v --docker"

  echo "TEST_DIR=$TEST_DIR"
  echo "TEST_RESULTS_FILE=$TEST_RESULTS_FILE"

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


SCRIPT_FILE=$(basename "$0")

TEST_RESULTS_FILE_BASE="${SCRIPT_FILE%.*}"

echo "SCRIPT_FILE=${SCRIPT_FILE}"
echo "TEST_RESULTS_FILE_BASE=${TEST_RESULTS_FILE_BASE}"

#TEST_RESULTS_TIMESTAMP="$(date -Id)_$(date +%H-%M-%S)"

IFS=$'\n'
for COLLECTION_PATH in ${TEST_COLLECTIONS}
do
  COLLECTION_ID=$(basename "${COLLECTION_PATH}")
  COLLECTION_NAMESPACE=$(basename "$(dirname "${COLLECTION_PATH}")")

  COLLECTION_NAME="${COLLECTION_NAMESPACE}.${COLLECTION_ID}"

#  TEST_RESULTS_FILENAME="${TEST_RESULTS_FILE_BASE}.${COLLECTION_NAME}.results.${TEST_RESULTS_TIMESTAMP}.log"
  TEST_RESULTS_FILENAME="${TEST_RESULTS_FILE_BASE}.${COLLECTION_NAME}.results.log"

  echo "COLLECTION_NAME=${COLLECTION_NAME}"
  echo "TEST_RESULTS_FILENAME=${TEST_RESULTS_FILENAME}"

  echo "Run Collection Tests for ${COLLECTION_NAME}"
  RUN_COMMAND_WITH_ARGS="run_collection_tests ${COLLECTION_PATH} ${TEST_RESULTS_FILENAME}"
  echo "${RUN_COMMAND_WITH_ARGS}"

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
