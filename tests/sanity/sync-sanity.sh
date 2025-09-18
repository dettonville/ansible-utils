#!/usr/bin/env bash

# sync sanity files - were they are the same content
# ref: https://stackoverflow.com/a/42042791/2791368

PROJECT_DIR=$( git rev-parse --show-toplevel )
cd "${PROJECT_DIR}" || exit

SOURCE_FILE="./tests/sanity/ignore.txt"
#DEST_FILE_LIST=$(find . -type f -wholename "./tests/sanity/ignore-*.txt")

DEST_FILE_LIST=()
DEST_FILE_LIST+=("ignore-2.17.txt")
DEST_FILE_LIST+=("ignore-2.18.txt")
DEST_FILE_LIST+=("ignore-2.19.txt")
DEST_FILE_LIST+=("ignore-2.20.txt")

IFS=$'\n'
for DEST_FILE in "${DEST_FILE_LIST[@]}"; do
  [[ "${DEST_FILE}" ]] || continue # Ignore empty lines
  COPY_CMD="cp -p ${SOURCE_FILE} ./tests/sanity/${DEST_FILE}"
  echo "${COPY_CMD}"
  eval "${COPY_CMD}"
done
