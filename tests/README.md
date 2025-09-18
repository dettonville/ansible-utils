
# Testing Modules

## Prepare test environment

```shell
export TEST_PYTHON_VERSION="3.12"
export ANSIBLE_KEEP_REMOTE_FILES=1
export ANSIBLE_DEBUG=1

```

### Sanity tests

```shell
ansible-test sanity --python 3.12  ## runs all sanity tests
ansible-test sanity --python 3.12 --test pep8
ansible-test sanity --python ${TEST_PYTHON_VERSION} --test pylint
ansible-test sanity --python ${TEST_PYTHON_VERSION} --test validate-modules
ansible-test sanity -v --docker --python ${TEST_PYTHON_VERSION} export_dicts
```

* Note: MacOS Issues

If running on MacOS may get the following error:
```output
 __NSCFConstantString initialize] may have been in progress in another thread when fork() was called

```

Resolved with the following setting:
```shell
## ref: https://github.com/ansible/ansible/issues/76322
## ref: https://github.com/ansible/ansible/issues/32499
$ export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

### Run All Tests

```shell
tests/run_tests.sh > run_test.results.txt
tests/run_tests.sh sanity
tests/run_tests.sh integration
tests/run_tests.sh -L DEBUG sanity

```

### Run Individually

## Sanity Testing

```shell
cd ${TEST_COLLECTION_DIR}
ansible-test sanity --test pep8
ansible-test sanity --python 3.12
```

To run automated resolve of issues using autopep8:

```shell
cd ${TEST_COLLECTION_DIR}
pip install autopep8
autopep8 --in-place plugins/modules/test_results_logger.py
autopep8 --in-place --aggressive --aggressive plugins/**/*.py
```

To run automated resolve of issues using black:

```shell
pip install black
black plugins/
ansible-test sanity --python 3.12 --test pep8
ansible-test sanity --python 3.12 --test pylint
```

To run automated resolve of unused imports/variables issues using autoflake (https://github.com/PyCQA/autoflake):

```shell
pip install autoflake
autoflake plugins/
autoflake -r --in-place --remove-unused-variables plugins/
autoflake -r --in-place --remove-unused-variables --remove-all-unused-imports plugins/
ansible-test sanity --python 3.12 --test pylint
```

To run automated resolve of issues using ruff (https://github.com/astral-sh/ruff):

```shell
pip install ruff
ruff format plugins/
ansible-test sanity --python 3.12 --test pep8
ansible-test sanity --python 3.12 --test pylint
```

```shell
ansible-test sanity -vv --python 3.12 --test pep8
ansible-test sanity --python 3.12 --python-interpreter ~/.pyenv/versions/3.12.3/bin/python3.12 --local --venv-system-site-packages
ansible-test sanity -v --docker --python ${TEST_PYTHON_VERSION} export_dicts
ansible-test sanity -v --docker --python ${TEST_PYTHON_VERSION} x509_certificate_verify
ansible-test sanity --python 3.12 x509_certificate_verify | tee -a ansible-test-sanity-results.log
ansible-test sanity -v --color --coverage --junit --docker default --python ${TEST_PYTHON_VERSION}
ansible-test sanity -v --color --coverage --junit --docker default --python ${TEST_PYTHON_VERSION} export_dicts
```

## Integration Testing

```shell
ansible-test integration export_dicts

```
