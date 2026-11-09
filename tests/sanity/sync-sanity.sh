#!/usr/bin/env bash

# sync sanity files - were they are the same content
# ref: https://stackoverflow.com/a/42042791/2791368

PROJECT_DIR=$( git rev-parse --show-toplevel )
cd "${PROJECT_DIR}" || exit

SOURCE_FILE="./tests/sanity/ignore.txt"
DEST_FILE_LIST=$(find . -type f -wholename "./tests/sanity/ignore-*.txt")

IFS=$'\n'
for DEST_FILE in ${DEST_FILE_LIST}; do
  [[ "${DEST_FILE}" ]] || continue # Ignore empty lines
  echo "Copying to ${DEST_FILE}"
  cp -p "${SOURCE_FILE}" "${DEST_FILE}"
done
