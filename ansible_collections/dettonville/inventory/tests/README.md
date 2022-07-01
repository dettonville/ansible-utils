
# Testing Modules

## Test environment

```shell
$ PROJECT_DIR="$( cd "$SCRIPT_DIR/" && git rev-parse --show-toplevel )"
$ COLLECTION_DIR=${PROJECT_DIR}/collections/ansible_collections/dettonville/inventory
$ echo "COLLECTION_DIR=${COLLECTION_DIR}"
$ cd ${COLLECTION_DIR}
```

### Testing

### Run All Tests

```shell
run_tests.sh > run_test.results.txt

```

### Run Individually

## Sanity Testing

```shell
ansible-test sanity -v --docker --python 3.10 update_hosts

```

## Integration Testing

```shell
ansible-test integration -v --docker --python 3.10 update_hosts

```
