
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
ansible-test sanity --test pep8
```

To fix yamllint issues
```shell
pip install yamlfix
yamlfix example_directory/
```

To run automated resolve of issues using autopep8:

```shell
cd ${TEST_COLLECTION_DIR}
pip install autopep8
autopep8 --in-place plugins/modules/test_results_logger.py
autopep8 --in-place --aggressive plugins/**/*.py
```

To run automated resolve of issues using black:

```shell
pip install black
black plugins/
ansible-test sanity --python 3.12
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
ansible-test sanity -v --color --coverage --junit --docker default --python ${TEST_PYTHON_VERSION}
ansible-test sanity -v --color --coverage --junit --docker default --python ${TEST_PYTHON_VERSION} export_dicts
```
