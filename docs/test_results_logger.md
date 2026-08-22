## module > test_results_logger

Update test results.

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Renders test results specified in dict format into junit xml.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **logging_level**<br>`str` | Default: `"INFO"`<br>Choices:<br>- `NOTSET`<br>- `DEBUG`<br>- `INFO`<br>- `ERROR` | Parameter used to define the level of troubleshooting output. |
| **test_case_base_dir**<br>`path / **required**` |  | Base directory that test case files are located as specified in the O(test_case_file_prefix). |
| **test_case_file_prefix**<br>`str` | Default: `"testcase_"` | finds list of test case files where file names match specified prefix. must define a prefix to set/derived the test_case_id (e.g., '(prefix)(test_case_id)\.yml'). If child directories exist in O(test_case_base_dir), the `test_suite_id` is set to respective parent directory. the 'test_suite_id' is set using the parent directory for each test case file in the O(test_case_base_dir). See examples for more details. |
| **test_case_file_regex**<br>`str` |  | defines the pattern regex to find the list of test case var files. See examples for more details. if not set the derived value is set to '(test_case_file_prefix)*.yml' |
| **test_case_id_capture_regex**<br>`str` |  | defines the regex group capture pattern used to find the test case identifiers. See examples for more details. if not set the derived value is set to '(test_case_file_prefix)(.*?).yml' |
| **test_junit_report_file**<br>`path` | Default: `"junit-report.xml"` | path where the test junit report file will be written/saved. |
| **test_results**<br>`dict` |  | Specifies a dictionary of test result dicts. See examples where test_suites and test_cases contain dynamic keys<br><br>*aliases:* `results` |
| **test_results_dir**<br>`path / **required**` |  | Directory where the O(test_results_file) and O(test_junit_report_file) test results are stored. |
| **test_results_file**<br>`path` | Default: `"test-logger-results.yml"` | Path to store test suite test results using internal YAML format. |
| **test_suite_list**<br>`list / elements=str` | Default: `[]` | List of test suite directories located in the O(test_case_base_dir). Each test suite directory is set as the test_suite_id in the results dictionary |

## Examples

```yaml
- name: Initialize the test result log with all test cases
  dettonville.utils.test_results_logger:
    test_case_base_dir: "{{ role_path }}/vars/tests"
    test_case_file_prefix: "testdata_"
    test_results:
      properties:
        collection_version: 2024.5.3
        git_branch: develop-lj
        git_commit_hash: 98f3c9c
        date: '2024-05-25T18:17:27Z'

- name: Update test result log results for test case id '01' and '03'
  dettonville.utils.test_results_logger:
    test_case_base_dir: "{{ role_path }}/vars/tests"
    test_case_file_prefix: "testdata_"
    test_results:
      test_suites:
        export_dicts:
          properties:
            collection_version: 2024.5.3
            component_git_commit_hash: 98f3c9c
            date: '2024-05-25T18:17:27Z'
            failed: false
            job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
          test_cases:
            '01':
              properties:
                collection_version: 2024.5.3
                component_git_branch: develop-lj
                component_git_commit_hash: 98f3c9c
                date: '2024-05-25T18:17:27Z'
                description: CSV test
                failed: false
                job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
                assertions:
                  validate_changed:
                    failed: false
                    msg: All assertions passed
                  validate_failed:
                    failed: false
                    msg: All assertions passed
                  validate_message:
                    failed: false
                    msg: All assertions passed
                  validate_results:
                    failed: false
                    msg: All assertions passed
            '03':
              properties:
                collection_version: 2024.5.3
                component_git_branch: develop-lj
                component_git_commit_hash: 98f3c9c
                date: '2024-05-25T18:17:27Z'
                description: CSV test
                failed: false
                job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
                assertions:
                  validate_changed:
                    failed: false
                    msg: All assertions passed
                  validate_failed:
                    failed: false
                    msg: All assertions passed
                  validate_message:
                    failed: false
                    msg: All assertions passed
                  validate_results:
                    failed: true
                    msg: Difference found between test_results and test_expected!
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **changed**<br>`(bool)` | always | True if successful |
| **failed**<br>`(bool)` | always | True if update failed |
| **message**<br>`(str)` | always | Status message for update<br><br>*sample:* `"The test_junit_report_file has been created successfully at /foo/bar/junit-report.xml"` |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_cowvjbd9
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.test_results_logger | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/test_results_logger.md
> MODULE dettonville.utils.test_results_logger (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_cowvjbd9/ansible_collections/dettonville/utils/plugins/modules/test_results_logger.py)

  Renders test results specified in dict format into junit xml.

OPTIONS (= indicates it is required):

- logging_level  Parameter used to define the level of
                  troubleshooting output.
        choices: [NOTSET, DEBUG, INFO, ERROR]
        default: INFO
        type: str

= test_case_base_dir  Base directory that test case files are located
                       as specified in the `test_case_file_prefix'.
        type: path

- test_case_file_prefix  finds list of test case files where file
                          names match specified prefix.
                          must define a prefix to set/derived the
                          test_case_id (e.g.,
                          '(prefix)(test_case_id)\.yml').
                          If child directories exist in
                          `test_case_base_dir', the `test_suite_id` is
                          set to respective parent directory.
                          the 'test_suite_id' is set using the parent
                          directory for each test case file in the
                          `test_case_base_dir'.
                          See examples for more details.
        default: testcase_
        type: str

- test_case_file_regex  defines the pattern regex to find the list of
                         test case var files.
                         See examples for more details.
                         if not set the derived value is set to
                         '(test_case_file_prefix)*.yml'
        default: null
        type: str

- test_case_id_capture_regex  defines the regex group capture pattern
                               used to find the test case identifiers.
                               See examples for more details.
                               if not set the derived value is set to
                               '(test_case_file_prefix)(.*?).yml'
        default: null
        type: str

- test_junit_report_file  path where the test junit report file will
                           be written/saved.
        default: junit-report.xml
        type: path

- test_results  Specifies a dictionary of test result dicts.
                 See examples where test_suites and test_cases contain
                 dynamic keys
        aliases: [results]
        default: null
        type: dict

= test_results_dir  Directory where the `test_results_file' and
                     `test_junit_report_file' test results are stored.
        type: path

- test_results_file  Path to store test suite test results using
                      internal YAML format.
        default: test-logger-results.yml
        type: path

- test_suite_list  List of test suite directories located in the
                    `test_case_base_dir'.
                    Each test suite directory is set as the
                    test_suite_id in the results dictionary
        default: []
        elements: str
        type: list

AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
- name: Initialize the test result log with all test cases
  dettonville.utils.test_results_logger:
    test_case_base_dir: "{{ role_path }}/vars/tests"
    test_case_file_prefix: "testdata_"
    test_results:
      properties:
        collection_version: 2024.5.3
        git_branch: develop-lj
        git_commit_hash: 98f3c9c
        date: '2024-05-25T18:17:27Z'

- name: Update test result log results for test case id '01' and '03'
  dettonville.utils.test_results_logger:
    test_case_base_dir: "{{ role_path }}/vars/tests"
    test_case_file_prefix: "testdata_"
    test_results:
      test_suites:
        export_dicts:
          properties:
            collection_version: 2024.5.3
            component_git_commit_hash: 98f3c9c
            date: '2024-05-25T18:17:27Z'
            failed: false
            job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
          test_cases:
            '01':
              properties:
                collection_version: 2024.5.3
                component_git_branch: develop-lj
                component_git_commit_hash: 98f3c9c
                date: '2024-05-25T18:17:27Z'
                description: CSV test
                failed: false
                job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
                assertions:
                  validate_changed:
                    failed: false
                    msg: All assertions passed
                  validate_failed:
                    failed: false
                    msg: All assertions passed
                  validate_message:
                    failed: false
                    msg: All assertions passed
                  validate_results:
                    failed: false
                    msg: All assertions passed
            '03':
              properties:
                collection_version: 2024.5.3
                component_git_branch: develop-lj
                component_git_commit_hash: 98f3c9c
                date: '2024-05-25T18:17:27Z'
                description: CSV test
                failed: false
                job_link: '[test job link](https://infracicdd1s1.example.org/jenkins/job/INFRA/run-module-tests/949/)'
                assertions:
                  validate_changed:
                    failed: false
                    msg: All assertions passed
                  validate_failed:
                    failed: false
                    msg: All assertions passed
                  validate_message:
                    failed: false
                    msg: All assertions passed
                  validate_results:
                    failed: true
                    msg: Difference found between test_results and test_expected!

RETURN VALUES:

- changed  True if successful
        returned: always
        type: bool

- failed  True if update failed
        returned: always
        type: bool

- message  Status message for update
        returned: always
        sample: '"The test_junit_report_file has been created successfully at /foo/bar/junit-report.xml"'
        type: str
```
