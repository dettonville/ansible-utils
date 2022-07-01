
```shell
ansible-test integration -v --color --docker --python 3.10 export_dicts | aha > tests/integration/test-results.export_dicts.html

Falling back to tests in "tests/integration/targets/" because "roles/test/" was not found.
Creating container database.
Run command: /Users/ljohnson/.pyenv/versions/3.10.2/bin/python3.10 /Users/ljohnson/.pyenv/versions/3.10.2/lib/python3.10/site-packages/ansible_test/_util/controller/tools/yamlcheck.py
Configuring target inventory.
Running export_dicts integration test role
Initializing "/tmp/ansible-test-t60wzyv4-injector" as the temporary injector directory.
Injecting "/tmp/python-vv9y0umc-ansible/python" as a execv wrapper for the "/Users/ljohnson/.pyenv/versions/3.10.2/bin/python3.10" interpreter.
Run command: ansible-playbook export_dicts-i_5s91mk.yml -i inventory -v
Using /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/integration.cfg as config file

PLAY [testhost] ****************************************************************

TASK [Gathering Facts] *********************************************************
ok: [testhost]

TASK [setup_remote_tmp_dir : make sure we have the ansible_os_family and ansible_distribution_version facts] ***
skipping: [testhost] => {"changed": false, "skip_reason": "Conditional result was False"}

TASK [setup_remote_tmp_dir : include_tasks] ************************************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/targets/setup_remote_tmp_dir/tasks/default.yml for testhost

TASK [setup_remote_tmp_dir : create temporary directory] ***********************
changed: [testhost] => {"changed": true, "gid": 0, "group": "wheel", "mode": "0700", "owner": "ljohnson", "path": "/tmp/ansible.ypifnylq.test", "size": 64, "state": "directory", "uid": 501}

TASK [setup_remote_tmp_dir : record temporary directory] ***********************
ok: [testhost] => {"ansible_facts": {"remote_tmp_dir": "/tmp/ansible.ypifnylq.test"}, "changed": false}

TASK [export_dicts : record the output directory] ******************************
ok: [testhost] => {"ansible_facts": {"bad_location_file": "/bad/location/bad.csv", "non_existing_file": "/tmp/ansible.ypifnylq.test/bar.csv", "output_file": "/tmp/ansible.ypifnylq.test/foo.csv", "output_file_csv": "/tmp/ansible.ypifnylq.test/foo.csv", "output_file_md": "/tmp/ansible.ypifnylq.test/foo.md"}, "changed": false}

TASK [export_dicts : include tasks to perform basic tests] *********************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/00-basic.yml for testhost

TASK [export_dicts : test-basic 1 - specify bad file location and fail] ********
fatal: [testhost]: FAILED! => {"changed": false, "msg": "Destination directory /bad/location does not exist!", "rc": 257}
...ignoring

TASK [export_dicts : test-basic 1 - verify error message] **********************
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : reset output file] ****************************************
ok: [testhost] => {"changed": false, "path": "/tmp/ansible.ypifnylq.test/foo.csv", "state": "absent"}

TASK [export_dicts : include tasks to perform csv tests] ***********************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/01-csv-values.yml for testhost

TASK [export_dicts : test-value 1-1 | add to specified file] *******************
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : Display result1] ******************************************
ok: [testhost] => {
    "result1": {
        "changed": true,
        "failed": false,
        "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"
    }
}

TASK [export_dicts : test-value 1-1 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "a2V5MSxrZXkyLGtleTMsa2V5NAp2YWx1ZTExLHZhbHVlMTIsdmFsdWUxMyx2YWx1ZTE0CnZhbHVlMjEsdmFsdWUyMix2YWx1ZTIzLHZhbHVlMjQKdmFsdWUzMSx2YWx1ZTMyLHZhbHVlMzMsdmFsdWUzNAp2YWx1ZTQxLHZhbHVlNDIsdmFsdWU0Myx2YWx1ZTQ0Cg==", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-1 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n", "expected1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"}, "changed": false}

TASK [export_dicts : Display expected1] ****************************************
ok: [testhost] => {
    "expected1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : Display content1] *****************************************
ok: [testhost] => {
    "content1": "key1,key2,key3,key4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : test-value 1-1 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-2 | Check add option with empty string value] ***
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-2 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "a2V5MSxrZXkyLGtleTMsa2V5NAosdmFsdWUxMix2YWx1ZTEzLHZhbHVlMTQKdmFsdWUyMSwsdmFsdWUyMyx2YWx1ZTI0CnZhbHVlMzEsdmFsdWUzMiwsdmFsdWUzNAp2YWx1ZTQxLHZhbHVlNDIsLAo=", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-2 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n", "expected2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n"}, "changed": false}

TASK [export_dicts : Display expected2] ****************************************
ok: [testhost] => {
    "expected2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n"
}

TASK [export_dicts : Display content2] *****************************************
ok: [testhost] => {
    "content2": "key1,key2,key3,key4\n,value12,value13,value14\nvalue21,,value23,value24\nvalue31,value32,,value34\nvalue41,value42,,\n"
}

TASK [export_dicts : test-value 1-2 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-3 | Check add option with encoded string values] ***
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-3 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "a2V5MSxrZXkyLGtleTMsa2V5NApiw6V6LHZhbHVlMTIsdmFsdWUxMyx2YWx1ZTE0CnZhbHVlMjEs76yAw7bDuCx2YWx1ZTIzLHZhbHVlMjQKdmFsdWUzMSx2YWx1ZTMyLOG4g8OixZcsdmFsdWUzNAp2YWx1ZTQxLHZhbHVlNDIs76yAw7bDuCxiw6V6Cg==", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-3 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n", "expected3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n"}, "changed": false}

TASK [export_dicts : Display expected3] ****************************************
ok: [testhost] => {
    "expected3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n"
}

TASK [export_dicts : Display content3] *****************************************
ok: [testhost] => {
    "content3": "key1,key2,key3,key4\nbåz,value12,value13,value14\nvalue21,ﬀöø,value23,value24\nvalue31,value32,ḃâŗ,value34\nvalue41,value42,ﬀöø,båz\n"
}

TASK [export_dicts : test-value 1-3 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-4 | export to csv with specified columns] ****
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-4 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "S2V5ICMxLEtleSAjMixLZXkgIzMsS2V5ICM0CnZhbHVlMTEsdmFsdWUxMix2YWx1ZTEzLHZhbHVlMTQKdmFsdWUyMSx2YWx1ZTIyLHZhbHVlMjMsdmFsdWUyNAp2YWx1ZTMxLHZhbHVlMzIsdmFsdWUzMyx2YWx1ZTM0CnZhbHVlNDEsdmFsdWU0Mix2YWx1ZTQzLHZhbHVlNDQK", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-4 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n", "expected4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"}, "changed": false}

TASK [export_dicts : Display expected4] ****************************************
ok: [testhost] => {
    "expected4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : Display content4] *****************************************
ok: [testhost] => {
    "content4": "Key #1,Key #2,Key #3,Key #4\nvalue11,value12,value13,value14\nvalue21,value22,value23,value24\nvalue31,value32,value33,value34\nvalue41,value42,value43,value44\n"
}

TASK [export_dicts : test-value 1-4 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-5 | export to csv where columns does not contain all columns in the provided list] ***
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-5 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "S2V5ICMxLEtleSAjMixLZXkgIzQKdmFsdWUxMSx2YWx1ZTEyLHZhbHVlMTQKdmFsdWUyMSx2YWx1ZTIyLHZhbHVlMjQKdmFsdWUzMSx2YWx1ZTMyLHZhbHVlMzQKdmFsdWU0MSx2YWx1ZTQyLHZhbHVlNDQK", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-5 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content5": "Key #1,Key #2,Key #4\nvalue11,value12,value14\nvalue21,value22,value24\nvalue31,value32,value34\nvalue41,value42,value44\n", "expected5": "Key #1,Key #2,Key #4\nvalue11,value12,value14\nvalue21,value22,value24\nvalue31,value32,value34\nvalue41,value42,value44\n"}, "changed": false}

TASK [export_dicts : Display expected5] ****************************************
ok: [testhost] => {
    "expected5": "Key #1,Key #2,Key #4\nvalue11,value12,value14\nvalue21,value22,value24\nvalue31,value32,value34\nvalue41,value42,value44\n"
}

TASK [export_dicts : Display content5] *****************************************
ok: [testhost] => {
    "content5": "Key #1,Key #2,Key #4\nvalue11,value12,value14\nvalue21,value22,value24\nvalue31,value32,value34\nvalue41,value42,value44\n"
}

TASK [export_dicts : test-value 1-5 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 1-6 | export to csv with columns specifying different order] ***
changed: [testhost] => {"changed": true, "message": "The csv file has been created successfully at /tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-6 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "S2V5ICM0LEtleSAjMixLZXkgIzEsS2V5ICMzCnZhbHVlMTQsdmFsdWUxMix2YWx1ZTExLHZhbHVlMTMKdmFsdWUyNCx2YWx1ZTIyLHZhbHVlMjEsdmFsdWUyMwp2YWx1ZTM0LHZhbHVlMzIsdmFsdWUzMSx2YWx1ZTMzCnZhbHVlNDQsdmFsdWU0Mix2YWx1ZTQxLHZhbHVlNDMK", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.csv"}

TASK [export_dicts : test-value 1-6 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content6": "Key #4,Key #2,Key #1,Key #3\nvalue14,value12,value11,value13\nvalue24,value22,value21,value23\nvalue34,value32,value31,value33\nvalue44,value42,value41,value43\n", "expected6": "Key #4,Key #2,Key #1,Key #3\nvalue14,value12,value11,value13\nvalue24,value22,value21,value23\nvalue34,value32,value31,value33\nvalue44,value42,value41,value43\n"}, "changed": false}

TASK [export_dicts : Display expected6] ****************************************
ok: [testhost] => {
    "expected6": "Key #4,Key #2,Key #1,Key #3\nvalue14,value12,value11,value13\nvalue24,value22,value21,value23\nvalue34,value32,value31,value33\nvalue44,value42,value41,value43\n"
}

TASK [export_dicts : Display content6] *****************************************
ok: [testhost] => {
    "content6": "Key #4,Key #2,Key #1,Key #3\nvalue14,value12,value11,value13\nvalue24,value22,value21,value23\nvalue34,value32,value31,value33\nvalue44,value42,value41,value43\n"
}

TASK [export_dicts : test-value 1-6 | Verify content of csv file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : reset output file] ****************************************
changed: [testhost] => {"changed": true, "path": "/tmp/ansible.ypifnylq.test/foo.csv", "state": "absent"}

TASK [export_dicts : include tasks to perform markdown tests] ******************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/targets/export_dicts/tasks/tests/02-md-values.yml for testhost

TASK [export_dicts : test-value 2-1 | add to specified file] *******************
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : Display result1] ******************************************
ok: [testhost] => {
    "result1": {
        "changed": true,
        "failed": false,
        "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"
    }
}

TASK [export_dicts : test-value 2-1 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwga2V5MSB8IGtleTIgfCBrZXkzIHwga2V5NCB8IAogfC0tLSB8IC0tLSB8IC0tLSB8IC0tLSB8IAogfCB2YWx1ZTExIHwgdmFsdWUxMiB8IHZhbHVlMTMgfCB2YWx1ZTE0IHwgCiB8IHZhbHVlMjEgfCB2YWx1ZTIyIHwgdmFsdWUyMyB8IHZhbHVlMjQgfCAKIHwgdmFsdWUzMSB8IHZhbHVlMzIgfCB2YWx1ZTMzIHwgdmFsdWUzNCB8IAogfCB2YWx1ZTQxIHwgdmFsdWU0MiB8IHZhbHVlNDMgfCB2YWx1ZTQ0IHwgCg==", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-1 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n", "expected1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"}, "changed": false}

TASK [export_dicts : Display expected1] ****************************************
ok: [testhost] => {
    "expected1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : Display content1] *****************************************
ok: [testhost] => {
    "content1": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : test-value 2-1 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-2 | Check add option with empty string value] ***
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-2 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwga2V5MSB8IGtleTIgfCBrZXkzIHwga2V5NCB8IAogfC0tLSB8IC0tLSB8IC0tLSB8IC0tLSB8IAogfCAgfCB2YWx1ZTEyIHwgdmFsdWUxMyB8IHZhbHVlMTQgfCAKIHwgdmFsdWUyMSB8ICB8IHZhbHVlMjMgfCB2YWx1ZTI0IHwgCiB8IHZhbHVlMzEgfCB2YWx1ZTMyIHwgIHwgdmFsdWUzNCB8IAogfCB2YWx1ZTQxIHwgdmFsdWU0MiB8ICB8ICB8IAo=", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-2 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n", "expected2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n"}, "changed": false}

TASK [export_dicts : Display expected2] ****************************************
ok: [testhost] => {
    "expected2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n"
}

TASK [export_dicts : Display content2] *****************************************
ok: [testhost] => {
    "content2": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n |  | value12 | value13 | value14 | \n | value21 |  | value23 | value24 | \n | value31 | value32 |  | value34 | \n | value41 | value42 |  |  | \n"
}

TASK [export_dicts : test-value 2-2 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-3 | Check add option with encoded string values] ***
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-3 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwga2V5MSB8IGtleTIgfCBrZXkzIHwga2V5NCB8IAogfC0tLSB8IC0tLSB8IC0tLSB8IC0tLSB8IAogfCBiw6V6IHwgdmFsdWUxMiB8IHZhbHVlMTMgfCB2YWx1ZTE0IHwgCiB8IHZhbHVlMjEgfCDvrIDDtsO4IHwgdmFsdWUyMyB8IHZhbHVlMjQgfCAKIHwgdmFsdWUzMSB8IHZhbHVlMzIgfCDhuIPDosWXIHwgdmFsdWUzNCB8IAogfCB2YWx1ZTQxIHwgdmFsdWU0MiB8IO+sgMO2w7ggfCBiw6V6IHwgCg==", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-3 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n", "expected3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n"}, "changed": false}

TASK [export_dicts : Display expected3] ****************************************
ok: [testhost] => {
    "expected3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n"
}

TASK [export_dicts : Display content3] *****************************************
ok: [testhost] => {
    "content3": " | key1 | key2 | key3 | key4 | \n |--- | --- | --- | --- | \n | båz | value12 | value13 | value14 | \n | value21 | ﬀöø | value23 | value24 | \n | value31 | value32 | ḃâŗ | value34 | \n | value41 | value42 | ﬀöø | båz | \n"
}

TASK [export_dicts : test-value 2-3 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-4 | export to markdown with specified columns] ***
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-4 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwgS2V5ICMxIHwgS2V5ICMyIHwgS2V5ICMzIHwgS2V5ICM0IHwgCiB8LS0tIHwgLS0tIHwgLS0tIHwgLS0tIHwgCiB8IHZhbHVlMTEgfCB2YWx1ZTEyIHwgdmFsdWUxMyB8IHZhbHVlMTQgfCAKIHwgdmFsdWUyMSB8IHZhbHVlMjIgfCB2YWx1ZTIzIHwgdmFsdWUyNCB8IAogfCB2YWx1ZTMxIHwgdmFsdWUzMiB8IHZhbHVlMzMgfCB2YWx1ZTM0IHwgCiB8IHZhbHVlNDEgfCB2YWx1ZTQyIHwgdmFsdWU0MyB8IHZhbHVlNDQgfCAK", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-4 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n", "expected4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"}, "changed": false}

TASK [export_dicts : Display expected4] ****************************************
ok: [testhost] => {
    "expected4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : Display content4] *****************************************
ok: [testhost] => {
    "content4": " | Key #1 | Key #2 | Key #3 | Key #4 | \n |--- | --- | --- | --- | \n | value11 | value12 | value13 | value14 | \n | value21 | value22 | value23 | value24 | \n | value31 | value32 | value33 | value34 | \n | value41 | value42 | value43 | value44 | \n"
}

TASK [export_dicts : test-value 2-4 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-5 | export to markdown where columns does not contain all columns in the provided list] ***
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-5 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwgS2V5ICMxIHwgS2V5ICMyIHwgS2V5ICM0IHwgCiB8LS0tIHwgLS0tIHwgLS0tIHwgCiB8IHZhbHVlMTEgfCB2YWx1ZTEyIHwgdmFsdWUxNCB8IAogfCB2YWx1ZTIxIHwgdmFsdWUyMiB8IHZhbHVlMjQgfCAKIHwgdmFsdWUzMSB8IHZhbHVlMzIgfCB2YWx1ZTM0IHwgCiB8IHZhbHVlNDEgfCB2YWx1ZTQyIHwgdmFsdWU0NCB8IAo=", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-5 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content5": " | Key #1 | Key #2 | Key #4 | \n |--- | --- | --- | \n | value11 | value12 | value14 | \n | value21 | value22 | value24 | \n | value31 | value32 | value34 | \n | value41 | value42 | value44 | \n", "expected5": " | Key #1 | Key #2 | Key #4 | \n |--- | --- | --- | \n | value11 | value12 | value14 | \n | value21 | value22 | value24 | \n | value31 | value32 | value34 | \n | value41 | value42 | value44 | \n"}, "changed": false}

TASK [export_dicts : Display expected5] ****************************************
ok: [testhost] => {
    "expected5": " | Key #1 | Key #2 | Key #4 | \n |--- | --- | --- | \n | value11 | value12 | value14 | \n | value21 | value22 | value24 | \n | value31 | value32 | value34 | \n | value41 | value42 | value44 | \n"
}

TASK [export_dicts : Display content5] *****************************************
ok: [testhost] => {
    "content5": " | Key #1 | Key #2 | Key #4 | \n |--- | --- | --- | \n | value11 | value12 | value14 | \n | value21 | value22 | value24 | \n | value31 | value32 | value34 | \n | value41 | value42 | value44 | \n"
}

TASK [export_dicts : test-value 2-5 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

TASK [export_dicts : test-value 2-6 | export to markdown with columns specifying different order] ***
changed: [testhost] => {"changed": true, "message": "The markdown file has been created successfully at /tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-6 | read content from output file] ***********
ok: [testhost] => {"changed": false, "content": "IHwgS2V5ICM0IHwgS2V5ICMyIHwgS2V5ICMxIHwgS2V5ICMzIHwgCiB8LS0tIHwgLS0tIHwgLS0tIHwgLS0tIHwgCiB8IHZhbHVlMTQgfCB2YWx1ZTEyIHwgdmFsdWUxMSB8IHZhbHVlMTMgfCAKIHwgdmFsdWUyNCB8IHZhbHVlMjIgfCB2YWx1ZTIxIHwgdmFsdWUyMyB8IAogfCB2YWx1ZTM0IHwgdmFsdWUzMiB8IHZhbHVlMzEgfCB2YWx1ZTMzIHwgCiB8IHZhbHVlNDQgfCB2YWx1ZTQyIHwgdmFsdWU0MSB8IHZhbHVlNDMgfCAK", "encoding": "base64", "source": "/tmp/ansible.ypifnylq.test/foo.md"}

TASK [export_dicts : test-value 2-6 | set expected content and get current ini file content] ***
ok: [testhost] => {"ansible_facts": {"content6": " | Key #4 | Key #2 | Key #1 | Key #3 | \n |--- | --- | --- | --- | \n | value14 | value12 | value11 | value13 | \n | value24 | value22 | value21 | value23 | \n | value34 | value32 | value31 | value33 | \n | value44 | value42 | value41 | value43 | \n", "expected6": " | Key #4 | Key #2 | Key #1 | Key #3 | \n |--- | --- | --- | --- | \n | value14 | value12 | value11 | value13 | \n | value24 | value22 | value21 | value23 | \n | value34 | value32 | value31 | value33 | \n | value44 | value42 | value41 | value43 | \n"}, "changed": false}

TASK [export_dicts : Display expected6] ****************************************
ok: [testhost] => {
    "expected6": " | Key #4 | Key #2 | Key #1 | Key #3 | \n |--- | --- | --- | --- | \n | value14 | value12 | value11 | value13 | \n | value24 | value22 | value21 | value23 | \n | value34 | value32 | value31 | value33 | \n | value44 | value42 | value41 | value43 | \n"
}

TASK [export_dicts : Display content6] *****************************************
ok: [testhost] => {
    "content6": " | Key #4 | Key #2 | Key #1 | Key #3 | \n |--- | --- | --- | --- | \n | value14 | value12 | value11 | value13 | \n | value24 | value22 | value21 | value23 | \n | value34 | value32 | value31 | value33 | \n | value44 | value42 | value41 | value43 | \n"
}

TASK [export_dicts : test-value 2-6 | Verify content of markdown file is as expected and export_dicts 'changed' is true] ***
ok: [testhost] => {
    "changed": false,
    "msg": "All assertions passed"
}

RUNNING HANDLER [setup_remote_tmp_dir : delete temporary directory] ************
included: /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/ansible_collections/dettonville/utils/tests/output/.tmp/integration/export_dicts-bigo7k9n-ÅÑŚÌβŁÈ/tests/integration/targets/setup_remote_tmp_dir/tasks/default-cleanup.yml for testhost

RUNNING HANDLER [setup_remote_tmp_dir : delete temporary directory] ************
changed: [testhost] => {"censored": "the output has been hidden due to the fact that 'no_log: true' was specified for this result", "changed": true}

PLAY RECAP *********************************************************************
testhost                   : ok=88   changed=15   unreachable=0    failed=0    skipped=1    rescued=0    ignored=1   


```