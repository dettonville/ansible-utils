
# Testing Modules

Distribution specific containers for Ansible integration testing:
[Ansible Integration Test Container Definitions](https://github.com/ansible/distro-test-containers)

Container used by ansible-test for distribution independent tests of collections:
[Ansible Default Integration Test Container for Collections](https://github.com/ansible/default-test-container/)


## Setup test environment

```shell
mkdir -p ansible_collections/dettonville
git clone https://github.com/dettonville/ansible-collection ansible-dettonville-collection ansible_collections/dettonville/utils
cd ansible_collections/dettonville/utils
```

## Sanity Testing

```shell
ansible-test sanity -v --docker --python 3.9 export_dicts

Assuming Docker is available on localhost.
Run command: docker -v
Detected "docker" container runtime version: Docker version 20.10.13, build a224086
Starting new "ansible-test-controller-G3epaZBd" container.
Run command: docker image inspect quay.io/ansible/default-test-container:4.2.0
Run command: docker run --volume /sys/fs/cgroup:/sys/fs/cgroup:ro --privileged=false --security-opt seccomp=unconfined --volume /var/run/docker.sock:/var/run/docker.sock --name ansible-test-controller-G3epaZBd -d quay.io/ansible/default-test-container:4.2.0
Adding "ansible-test-controller-G3epaZBd" to container database.
Run command: docker inspect c7187e28672105bf184fec54661880c55d205bad80a8b49411d0088967483154
Run command: docker exec -i ansible-test-controller-G3epaZBd /bin/sh
Scanning collection root: /Users/ljohnson/repos/ansible/ansible_collections
Run command: git ls-files -z --cached --others --exclude-standard
Run command: git ls-files -z --deleted
Run command: git submodule status --recursive
Including collection: community.general (2317 files)
Including collection: dettonville.utils (43 files)
Creating a payload archive containing 3162 files...
Created a 3494296 byte payload archive containing 3162 files in 1 seconds.
Run command: docker exec -i ansible-test-controller-G3epaZBd tar oxzf - -C /root
Creating container database.
Run command: docker exec -it ansible-test-controller-G3epaZBd /usr/bin/env ANSIBLE_TEST_CONTENT_ROOT=/root/ansible_collections/dettonville/utils LC_ALL=en_US.UTF-8 /usr/bin/python3.9 /root/ansible/bin/ansible-test sanity -v export_dicts --containers '{}' --meta ...
Parsing container database.
Read 5 sanity test ignore line(s) for Ansible 2.12 from: tests/sanity/ignore-2.12.txt
Loaded configuration: tests/config.yml
Running sanity test "action-plugin-docs"
Initializing "/tmp/ansible-test-h5utj9oj-injector" as the temporary injector directory.
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/action-plugin-docs.py
Running sanity test "ansible-doc"
Run command: ansible-doc -t module dettonville.utils.export_dicts
Run command: ansible-doc -t module --json dettonville.utils.export_dicts
Running sanity test "changelog"
No tests applicable.
Running sanity test "compile" on Python 3.9
Run command: /usr/bin/python3.9 /root/ansible/test/lib/ansible_test/_util/target/sanity/compile/compile.py
Running sanity test "empty-init"
No tests applicable.
Running sanity test "future-import-boilerplate"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/future-import-boilerplate.py
Running sanity test "ignores"
Running sanity test "import" on Python 3.9
Run command: importer.py
Running sanity test "line-endings"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/line-endings.py
Running sanity test "metaclass-boilerplate"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/metaclass-boilerplate.py
Running sanity test "no-assert"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-assert.py
Running sanity test "no-basestring"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-basestring.py
Running sanity test "no-dict-iteritems"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-dict-iteritems.py
Running sanity test "no-dict-iterkeys"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-dict-iterkeys.py
Running sanity test "no-dict-itervalues"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-dict-itervalues.py
Running sanity test "no-get-exception"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-get-exception.py
Running sanity test "no-illegal-filenames"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-illegal-filenames.py
Running sanity test "no-main-display"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-main-display.py
Running sanity test "no-smart-quotes"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-smart-quotes.py
Running sanity test "no-unicode-literals"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/no-unicode-literals.py
Running sanity test "pep8"
Run command: /root/.ansible/test/venv/sanity.pep8/3.9/8987e035/bin/python -m pycodestyle --max-line-length 160 --config /dev/null --ignore E402,E741,W503,W504 plugins/modules/export_dicts.py
Running sanity test "pslint"
No tests applicable.
Running sanity test "pylint"
Run command: /root/.ansible/test/venv/sanity.pylint/3.9/2ae51da1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/tools/collection_detail.py /root/ansible_collections/dettonville/utils
Checking 1 file(s) in context "modules" with config: /root/ansible/test/lib/ansible_test/_util/controller/sanity/pylint/config/collection.cfg
Run command: /root/.ansible/test/venv/sanity.pylint/3.9/2ae51da1/bin/python -m pylint --jobs 0 --reports n --max-line-length 160 --max-complexity 20 --rcfile /root/ansible/test/lib/ansible_test/_util/controller/sanity/pylint/config/collection.cfg --output-forma ...
Running sanity test "replace-urlopen"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/replace-urlopen.py
Running sanity test "runtime-metadata"
No tests applicable.
Running sanity test "shebang"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/shebang.py
Running sanity test "shellcheck"
No tests applicable.
Running sanity test "symlinks"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/symlinks.py
Running sanity test "use-argspec-type-path"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/use-argspec-type-path.py
Running sanity test "use-compat-six"
Run command: /root/.ansible/test/venv/sanity/3.9/4f53cda1/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/code-smell/use-compat-six.py
Running sanity test "validate-modules"
Run command: /root/.ansible/test/venv/sanity.validate-modules/3.9/5e1e301c/bin/python /root/ansible/test/lib/ansible_test/_util/controller/tools/collection_detail.py /root/ansible_collections/dettonville/utils
Run command: /root/.ansible/test/venv/sanity.validate-modules/3.9/5e1e301c/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/validate-modules/validate-modules --format json --arg-spec plugins/modules/export_dicts.py --collection ansible_col ...
Running sanity test "yamllint"
Run command: /root/.ansible/test/venv/sanity.yamllint/3.9/e5ec9979/bin/python /root/ansible/test/lib/ansible_test/_util/controller/sanity/yamllint/yamllinter.py
Run command: docker exec -i ansible-test-controller-G3epaZBd sh -c 'tar cf - -C /root/ansible_collections/dettonville/utils/tests --exclude .tmp output | gzip'
Run command: tar oxzf - -C /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests
Run command: docker rm -f ansible-test-controller-G3epaZBd

```

## Integration Testing

```shell
ansible-test integration export_dicts
Running export_dicts integration test role
[WARNING]: running playbook inside collection dettonville.utils

PLAY [testhost] **********************************************************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ***************************************************************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [setup_remote_tmp_dir : make sure we have the ansible_os_family and ansible_distribution_version facts] *************************************************************************************************************************************************************
skipping: [testhost]

TASK [setup_remote_tmp_dir : include_tasks] ******************************************************************************************************************************************************************************************************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-25ge54os-ÅÑŚÌβŁÈ/tests/integration/targets/setup_remote_tmp_dir/tasks/default.yml for testhost

TASK [setup_remote_tmp_dir : create temporary directory] *****************************************************************************************************************************************************************************************************************
changed: [testhost]

TASK [setup_remote_tmp_dir : record temporary directory] *****************************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : record the output directory] ************************************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : include tasks to perform basic tests] ***************************************************************************************************************************************************************************************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-25ge54os-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/00-basic.yml for testhost

TASK [export_dicts : test-basic 1 - specify bad file location and fail] **************************************************************************************************************************************************************************************************
fatal: [testhost]: FAILED! => {"changed": false, "msg": "Destination directory /bad/location does not exist!", "rc": 257}
...ignoring

TASK [export_dicts : test-basic 1 - verify error message] ****************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : reset output file] **********************************************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : include tasks to perform csv tests] *****************************************************************************************************************************************************************************************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-25ge54os-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/01-csv-values.yml for testhost

TASK [export_dicts : test-value 1-1 | add to specified file] *************************************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : Display result1] ************************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "result1": {
        "changed": true,
        "failed": false,
        "message": "The csv file has been created successfully at /tmp/ansible.90xkk0yf.test/foo.csv"
    }
}

TASK [export_dicts : test-value 1-1 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 1-1 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected1] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : Display content1] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : test-value 1-1 | Verify content of csv file is as expected and export_dicts 'changed' is true] ******************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-2 | Check add option with empty string value] ******************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 1-2 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 1-2 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected2] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n"
}

TASK [export_dicts : Display content2] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n"
}

TASK [export_dicts : test-value 1-2 | Verify content of csv file is as expected and export_dicts 'changed' is true] ******************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-3 | Check add option with encoded string values] ***************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 1-3 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 1-3 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected3] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n"
}

TASK [export_dicts : Display content3] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n"
}

TASK [export_dicts : test-value 1-3 | Verify content of csv file is as expected and export_dicts 'changed' is true] ******************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-4 | export to csv with specified columns] **********************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 1-4 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 1-4 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected4] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : Display content4] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : test-value 1-4 | Verify content of csv file is as expected and export_dicts 'changed' is true] ******************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : reset output file] **********************************************************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : include tasks to perform markdown tests] ************************************************************************************************************************************************************************************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-25ge54os-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/02-md-values.yml for testhost

TASK [export_dicts : test-value 2-1 | add to specified file] *************************************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : Display result1] ************************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "result1": {
        "changed": true,
        "failed": false,
        "message": "The markdown file has been created successfully at /tmp/ansible.90xkk0yf.test/foo.md"
    }
}

TASK [export_dicts : test-value 2-1 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 2-1 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected1] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : Display content1] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : test-value 2-1 | Verify content of markdown file is as expected and export_dicts 'changed' is true] *************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-2 | Check add option with empty string value] ******************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 2-2 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 2-2 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected2] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n"
}

TASK [export_dicts : Display content2] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n"
}

TASK [export_dicts : test-value 2-2 | Verify content of markdown file is as expected and export_dicts 'changed' is true] *************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-3 | Check add option with encoded string values] ***************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 2-3 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 2-3 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected3] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n"
}

TASK [export_dicts : Display content3] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n"
}

TASK [export_dicts : test-value 2-3 | Verify content of markdown file is as expected and export_dicts 'changed' is true] *************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-4 | export to markdown with specified columns] *****************************************************************************************************************************************************************************************
changed: [testhost]

TASK [export_dicts : test-value 2-4 | read content from output file] *****************************************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : test-value 2-4 | set expected content and get current ini file content] *****************************************************************************************************************************************************************************
ok: [testhost]

TASK [export_dicts : Display expected4] **********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "expected4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : Display content4] ***********************************************************************************************************************************************************************************************************************************
ok: [testhost] => {
    "content4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : test-value 2-4 | Verify content of markdown file is as expected and export_dicts 'changed' is true] *************************************************************************************************************************************************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

RUNNING HANDLER [setup_remote_tmp_dir : delete temporary directory] ******************************************************************************************************************************************************************************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-25ge54os-ÅÑŚÌβŁÈ/tests/integration/targets/setup_remote_tmp_dir/tasks/default-cleanup.yml for testhost

RUNNING HANDLER [setup_remote_tmp_dir : delete temporary directory] ******************************************************************************************************************************************************************************************************
changed: [testhost]

PLAY RECAP ***************************************************************************************************************************************************************************************************************************************************************
testhost                   : ok=64   changed=11   unreachable=0    failed=0    skipped=1    rescued=0    ignored=1   

```
