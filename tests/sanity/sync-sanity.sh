#!/usr/bin/env bash

# sync sanity files - were they are the same content
# ref: https://stackoverflow.com/a/42042791/2791368

PROJECT_DIR=$( git rev-parse --show-toplevel )
cd "${PROJECT_DIR}" || exit

SOURCE_FILE="./tests/sanity/ignore.txt"

# Define prepend content per version using an associative array
declare -A VERSION_PREPEND
#VERSION_PREPEND["2.10"]="plugins/module_utils/test_results_logger.py no-basestring!skip"
#VERSION_PREPEND["2.12"]="plugins/module_utils/test_results_logger.py no-basestring!skip"
#VERSION_PREPEND["2.16"]="plugins/module_utils/test_results_logger.py no-basestring!skip"

DEST_FILE_LIST=()
DEST_FILE_LIST+=("ignore-2.10.txt")
DEST_FILE_LIST+=("ignore-2.12.txt")
DEST_FILE_LIST+=("ignore-2.14.txt")
DEST_FILE_LIST+=("ignore-2.16.txt")
DEST_FILE_LIST+=("ignore-2.17.txt")
DEST_FILE_LIST+=("ignore-2.18.txt")
DEST_FILE_LIST+=("ignore-2.19.txt")
DEST_FILE_LIST+=("ignore-2.20.txt")
DEST_FILE_LIST+=("ignore-2.21.txt")

IFS=$'\n'
for DEST_FILE in "${DEST_FILE_LIST[@]}"; do
  [[ "${DEST_FILE}" ]] || continue # Ignore empty lines

  TARGET_PATH="./tests/sanity/${DEST_FILE}"
  COPY_CMD="cp -p ${SOURCE_FILE} ${TARGET_PATH}"
  echo "${COPY_CMD}"
  eval "${COPY_CMD}"

  # Extract version number from filename (e.g., ignore-2.10.txt -> 2.10)
  VERSION=$(echo "${DEST_FILE}" | sed -E 's/^ignore-([0-9]+\.[0-9]+)\.txt$/\1/')

  # Check if a specific prepend rule exists for this version
  if [[ -n "${VERSION}" && -n "${VERSION_PREPEND[$VERSION]}" ]]; then
    PREPEND_CONTENT="${VERSION_PREPEND[$VERSION]}"
    echo "Prepending rule to ${DEST_FILE} (version ${VERSION})"

    # Prepend the content to the target file safely using a temp file
    { echo "${PREPEND_CONTENT}"; cat "${TARGET_PATH}"; } > "${TARGET_PATH}.tmp" && mv "${TARGET_PATH}.tmp" "${TARGET_PATH}"
  fi
done
