
# Unit Testing

## Running the tests directly

```shell
ansible-test units --python 3.12 export_dicts
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
pytest -r a --color yes tests/unit/plugins/modules/test_export_dicts.py -v
pytest -r a --color yes tests/unit/plugins/modules/test_git_pacp.py -vvv
pytest -r a --color yes tests/unit/plugins/modules/test_git_pacp.py::TestGitPacpModule::test_setup_module_object

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
