from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes
from unittest.mock import Mock


def set_module_args(args):
    """prepare arguments so that they will be picked up during module creation"""
    args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
    basic._ANSIBLE_ARGS = to_bytes(args)


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""

    pass


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""

    pass


# Mock the Ansible module utils
class MockAnsibleModule:
    def __init__(self, argument_spec=None, supports_check_mode=False):
        self.params = {}
        self.check_mode = False
        self.exit_json = Mock()
        self.fail_json = Mock()

    def set_params(self, **params):
        self.params = params


def exit_json(*args, **kwargs):
    """function to patch over exit_json; package return data into an exception"""
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """function to patch over fail_json; package return data into an exception"""
    kwargs["failed"] = True
    raise AnsibleFailJson(kwargs)
