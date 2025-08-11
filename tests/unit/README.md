
# Unit Testing

## Running the tests directly

```shell
ansible-test units --python 3.12
ansible-test units --python 3.12 export_dicts
ansible-test units --python 3.12 --containers '{}' --color yes
ansible-test units --python 3.12 --containers '{}' --truncate 0 --color yes
ansible-test units -v --python 3.12 --containers '{}' --coverage --truncate 0 --color yes
ansible-test units --docker -v --python 3.12 export_dicts
ansible-test units --docker -v --python 3.12 git_pacp
```

```shell
## ref: https://github.com/ansible/ansible/issues/27446#issuecomment-318777441
export PYTHONPATH=$PYTHONPATH:/path/to/your/ansible_collections
pytest -r a --color yes path/to/the/test(s) -vvv
```

```shell
cd ${HOME}/repos/ansible/ansible_collections/dettonville/utils
export PYTHONPATH=${HOME}/repos/ansible
## show logs for failed tests
pytest -s --color yes tests/unit/plugins/modules/test_export_dicts.py
## show logs for all tests (success and failed)
pytest -rP --color yes tests/unit/plugins/modules/test_export_dicts.py
## turn up verbosity
pytest -vvv -r a --color yes tests/unit/plugins/modules/test_export_dicts.py
pytest -r a --color yes tests/unit/plugins/modules/test_git_pacp.py -vvv
pytest -r a --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitPacpModule::test_setup_module_object
pytest -s --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitActions::test_write_ssh_wrapper_content

```

when using the python 'logging' module, need to specify to turn on logging output in addition to -s for generic stdout. Based on Logging within pytest tests:
ref: https://stackoverflow.com/questions/4673373/logging-within-pytest-tests

```shell
pytest --log-cli-level=DEBUG -s --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitActions::test_write_ssh_wrapper_content
pytest --log-cli-level=DEBUG -s --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitActions::test_get_url_scheme_https
pytest --log-cli=true -s --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitActionsErrorHandling::test_push_remote_add_failure
```

To avoid having to add the log-cli option to the pytest command each time, add the following content to the pytest.ini:
```ini
[pytest]
log_cli = 1
log_cli_level = ERROR
log_cli_format = %(message)s

log_file = pytest.log
log_file_level = DEBUG
log_file_format = %(asctime)s [%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)
log_file_date_format=%Y-%m-%d %H:%M:%S

```

```shell
ansible-test units --docker -v --python 3.12
```

```shell
pytest -r a -n auto --color yes -p no:cacheprovider \
  --rootdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  --confcutdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  tests/unit/plugins/modules/test_export_dicts.py

pytest -r a -n auto --color yes -p no:cacheprovider \
  -c /Users/ljohnson/.pyenv/versions/3.12.3/lib/python3.12/site-packages/ansible_test/_data/pytest/config/default.ini \
  --junit-xml /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/junit/python3.12-modules-units.xml \
  --strict-markers \
  --rootdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  --confcutdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  tests/unit/plugins/modules/test_export_dicts.py
```



```shell
cd ${PROJECT_DIR}/tests/unit/plugins/modules

# Run all tests
python -m unittest test_export_dicts.py -v

# Run specific test class
python -m unittest test_export_dicts.TestExportDicts -v

# Run individual test
python -m unittest test_export_dicts.TestExportDictUtils.test_get_headers_and_fields -v
python -m unittest test_export_dicts.TestExportDictUtils.test_get_headers_and_fields_no_headers -v
python -m unittest test_export_dicts.TestExportDictUtils.test_write_csv_file_success -v
```
