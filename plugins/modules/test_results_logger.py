#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license (https://opensource.org/license/mit/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: test_results_logger
author:
    - "Lee Johnson (@lj020326)"
short_description: Update test results.
description:
    - Renders test results specified in dict format into junit xml.
options:
    test_results_dir:
      description:
        - Directory where the O(test_results_file) and O(test_junit_report_file) test results are stored.
      required: true
      type: path
    test_results_file:
      description:
        - Path to store test suite test results using internal YAML format. 
      required: false
      type: path
      default: 'test-logger-results.yml'
    test_junit_report_file:
      description:
        - path where the test junit report file will be written/saved.
      required: false
      type: path
      default: 'junit-report.xml'
    test_case_base_dir:
      description:
          - Base directory that test case files are located as specified in the O(test_case_file_prefix). 
      required: true
      type: path
    test_suite_list:
      description:
          - List of test suite directories located in the O(test_case_base_dir). 
          - Each test suite directory is set as the test_suite_id in the results dictionary
      required: false
      type: list
      elements: str
      default: []
    test_case_file_prefix:
      description:
        - finds list of test case files where file names match specified prefix.
        - must define a prefix to set/derived the test_case_id (e.g., '(prefix)(test_case_id)\.yml').
        - If child directories exist in O(test_case_base_dir), the `test_suite_id` is set to respective parent directory.
        - the 'test_suite_id' is set using the parent directory for each test case file in the O(test_case_base_dir). 
        - See examples for more details.
      required: false
      default: 'testcase_'
      type: str
    test_case_file_regex:
      description:
        - defines the pattern regex to find the list of test case var files.
        - See examples for more details.
        - if not set the derived value is set to '(test_case_file_prefix)*.yml'
      required: false
      type: str
    test_case_id_capture_regex:
      description:
        - defines the regex group capture pattern used to find the test case identifiers.
        - See examples for more details.
        - if not set the derived value is set to '(test_case_file_prefix)(.*?).yml'
      required: false
      type: str
    test_results:
      description:
        - Specifies a dictionary of test result dicts.
        - See examples where test_suites and test_cases contain dynamic keys
      aliases: ['results']
      required: false
      type: dict
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output.
        required: false
        choices: [NOTSET, DEBUG, INFO, ERROR]
        default: INFO
        type: str
"""  # NOQA

EXAMPLES = r"""
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
"""  # NOQA

RETURN = r"""
message:
    description: Status message for update
    type: str
    returned: always
    sample: "The test_junit_report_file has been created successfully at /foo/bar/junit-report.xml"
failed:
    description: True if update failed
    type: bool
    returned: always
changed:
    description: True if successful
    type: bool
    returned: always

"""

import logging
import pprint
from ansible.module_utils.basic import AnsibleModule

try:
    from module_utils.test_results_logger import TestResultsLogger
except ImportError:
    try:
        from ansible.module_utils.test_results_logger import TestResultsLogger
    except ImportError:
        # noinspection PyUnresolvedReferences
        from ansible_collections.dettonville.utils.plugins.module_utils.test_results_logger import (
            TestResultsLogger,
        )

# test_assertion_detail = dict(
#     message=dict(required=False, type="str"),
#     stdout=dict(required=False, type="str"),
#     stderr=dict(required=False, type="str"),
#     error=dict(required=False, type="bool", default=False),
#     failed=dict(required=False, type="bool", default=False),
#     skipped=dict(required=False, type="bool", default=False),
# )
#
# test_case_assertions = dict(
#     test_assertion_id=dict(required=True, type="str"),
#     test_assertion_item=dict(required=True, type="dict", options=test_assertion_detail),
# )
#
# test_case_detail = dict(
#     properties=dict(required=False, type="dict"),
#     assertions=dict(required=True, type="dict", options=test_case_assertions),
#     error=dict(required=False, type="bool", default=False),
#     failed=dict(required=False, type="bool", default=False),
#     skipped=dict(required=False, type="bool", default=False),
# )
#
# test_cases = dict(
#     test_case_id=dict(required=True, type="str"),
#     test_case_item=dict(required=True, type="dict", options=test_case_detail),
# )
#
# test_suite_detail = dict(
#     properties=dict(required=False, type="dict"),
#     test_cases=dict(required=False, type="dict", options=test_cases),
# )
#
# test_suite = dict(
#     test_suite_id=dict(required=True, type="str"),
#     test_suite_item=dict(required=True, type="dict", options=test_suite_detail),
# )

# test_suites = dict(
#     required=False,
#     type="dict",
#     options=dict(
#         name=dict(required=True, type="str"), value=dict(required=True, type="dict")
#     ),
# )

# define available arguments/parameters a user can pass to the module
argument_spec = dict(
    test_results_dir=dict(required=True, type="path"),
    test_case_base_dir=dict(required=True, type="path"),
    test_case_file_prefix=dict(required=False, type="str", default="testcase_"),
    test_case_file_regex=dict(required=False, type="str"),
    test_case_id_capture_regex=dict(required=False, type="str"),
    test_results_file=dict(
        required=False, type="path", default="test-logger-results.yml"
    ),
    test_junit_report_file=dict(
        required=False, type="path", default="junit-report.xml"
    ),
    test_suite_list=dict(required=False, type="list", elements="str", default=list()),
    test_results=dict(type="dict", aliases=["results"], required=False),
    logging_level=dict(
        type="str", choices=["NOTSET", "DEBUG", "INFO", "ERROR"], default="INFO"
    ),
)


# ref: https://docs.ansible.com/ansible/latest/dev_guide/testing_units_modules.html#restructuring-modules-to-enable-testing-module-set-up-and-other-processes
def setup_module_object():
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    return module


def run_module():
    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(changed=False, message="")

    module = setup_module_object()

    # ref: https://stackoverflow.com/questions/678236/how-do-i-get-the-filename-without-the-extension-from-a-path-in-python
    # module_filename = os.path.splitext(os.path.basename(os.path.realpath(__file__)))[0]
    # log_prefix = "%s():" % module_filename

    module_name = module._name
    log_prefix = "%s():" % module_name
    # module_fqcn = module_name.rsplit('.', 1)[0]
    # log_prefix = "%s():" % module_fqcn

    loglevel = module.params.get("logging_level")
    logging.basicConfig(level=loglevel)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    test_results_logger = TestResultsLogger(module)

    test_results = module.params.get("test_results")

    logging.debug("%s test_results_logger.update_test_results()", log_prefix)
    result.update(test_results_logger.update_test_results(test_results))

    logging.debug("%s test_results_logger.dump_junit()", log_prefix)
    result.update(test_results_logger.dump_junit())

    logging.info("%s result => %s", log_prefix, pprint.pformat(result))
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
