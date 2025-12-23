
# Unit Testing

## Running the tests directly

```shell
ansible-test units --python 3.13
ansible-test units --python 3.13 export_dicts
ansible-test units --python 3.13 git_pacp
ansible-test units --python 3.13 x509_certificate_verify
ansible-test units --python 3.13 tests/unit/plugins/filter/test_redact_sensitive_values.py
ansible-test units --python 3.13 tests/unit/plugins/filter/test_remove_sensitive_keys.py
ansible-test units x509_certificate_verify | tee -a ansible-test-unit-results.log
ansible-test units dettonville.utils.tests.unit.plugins.modules.test_x509_certificate_verify::TestX509CertificateVerifyModule::test_main_version_mismatch
ansible-test units x509_certificate_verify --test dettonville.utils.tests.unit.plugins.modules.test_x509_certificate_verify::TestX509CertificateVerifyModule::test_main_version_mismatch
ansible-test --test dettonville.utils.tests.unit.plugins.modules.test_x509_certificate_verify::TestX509CertificateVerifyModule::test_main_version_mismatch  units x509_certificate_verify
ansible-test units -v --color no --truncate 0 --coverage --docker --python 3.13 x509_certificate_verify | tee ansible-test-unit-docker-results.log
ansible-test units --python 3.13 --containers '{}' --color yes
ansible-test units --python 3.13 --containers '{}' --truncate 0 --color yes
ansible-test units -v --python 3.13 --containers '{}' --coverage --truncate 0 --color yes
ansible-test units --docker -v --python 3.13 export_dicts
ansible-test units --docker -v --python 3.13 git_pacp
```

Create test coverage results
```shell
ansible-test units --python 3.13 x509_certificate_verify --coverage --verbose
```

Generate a new coverage report
```shell
ansible-test coverage report
ansible-test coverage html
open tests/output/reports/coverage/index.html
```

Check if the coverage for x509_certificate_verify.py improves (e.g., closer to 90–95%). If missed lines remain, review the HTML report to identify them.

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
ansible-test units --docker -v --python 3.13
```

```shell
pytest -r a -n auto --color yes -p no:cacheprovider \
  --rootdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  --confcutdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  tests/unit/plugins/modules/test_export_dicts.py

pytest -r a -n auto --color yes -p no:cacheprovider \
  -c /Users/ljohnson/.pyenv/versions/3.13.3/lib/python3.13/site-packages/ansible_test/_data/pytest/config/default.ini \
  --junit-xml /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/junit/python3.13-modules-units.xml \
  --strict-markers \
  --rootdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  --confcutdir /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils \
  tests/unit/plugins/modules/test_export_dicts.py
```



```shell
cd ${PROJECT_DIR}/tests/unit/plugins/modules

# Run all tests
python -m unittest test_export_dicts.py -v
python -m unittest test_x509_certificate_verify -v

# Run specific test class
python -m unittest test_export_dicts.TestExportDicts -v

# Run individual test
python -m unittest test_export_dicts.TestExportDictUtils.test_get_headers_and_fields -v
python -m unittest test_export_dicts.TestExportDictUtils.test_get_headers_and_fields_no_headers -v
python -m unittest test_export_dicts.TestExportDictUtils.test_write_csv_file_success -v
```
