from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import shutil
import json
import tempfile
import contextlib
import pytest
import unittest
from unittest.mock import MagicMock, Mock, patch

from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes

TEST_MODULES_IMPORT_PATH = "dettonville.utils"


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""


def exit_json(*args, **kwargs):
    """
    Mock replacement for AnsibleModule.exit_json() that raises AnsibleExitJson.
    """
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """
    Mock replacement for AnsibleModule.fail_json() that raises AnsibleFailJson.
    """
    kwargs["failed"] = True
    raise AnsibleFailJson(kwargs)


# Main module execution wrapper (for testing)
def _run_module_with_args(args):
    with patch(
        "ansible.module_utils.basic.AnsibleModule",
        side_effect=lambda **kwargs: MockAnsibleModule(params=args, **kwargs),
    ) as MockModule:
        try:
            run_module(args)
        except AnsibleExitJson as e:
            return e.args[0]
        except AnsibleFailJson as e:
            return e.args[0]


def run_module(module_entry, module_args=None, expect_success=True):
    """
    Run the (mock) module and expect Ansible to exit without an error
    """
    raises = AnsibleExitJson if expect_success else AnsibleFailJson

    if module_args is None:
        module_args = {}

    with pytest.raises(raises) as c, set_module_args(module_args):
        module_entry()

    return c.value.args[0]


@contextlib.contextmanager
def set_module_args(args):
    if "_ansible_remote_tmp" not in args:
        args["_ansible_remote_tmp"] = "/tmp"
    if "_ansible_keep_remote_files" not in args:
        args["_ansible_keep_remote_files"] = False

    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:
        # Before data tagging support was merged, this was the way to go:
        serialized_args = to_bytes(json.dumps({'ANSIBLE_MODULE_ARGS': args}))
        with patch.object(basic, '_ANSIBLE_ARGS', serialized_args):
            yield
    else:
        # With data tagging support, we have a new helper for this:
        with patch_module_args(args):
            yield


# Mock the Ansible module utils
class MockAnsibleModule:
    def __init__(self, argument_spec=None,
                 supports_check_mode=False, **kwargs):
        self.argument_spec = argument_spec
        self.supports_check_mode = supports_check_mode
        self.params = kwargs.get("params", {})
        self.check_mode = kwargs.get("check_mode", False)
        self.exit_json_called = False
        self.fail_json_called = False
        self.exit_json = Mock()
        self.fail_json = Mock()
        self.bin_path_map = {}  # Used to mock get_bin_path
        self.tmpdir = tempfile.mkdtemp()  # Simulate temporary directory for module
        self.add_cleanup_action = MagicMock()  # Mock cleanup action

    def set_params(self, **params):
        self.params = params

    def get_bin_path(self, executable, required=False):
        """Simulates AnsibleModule.get_bin_path."""
        if executable in self.bin_path_map:
            return self.bin_path_map[executable]
        if required:
            self.fail_json(msg=f"Executable '{executable}' not found")
        return None

    def backup_local(self, path):
        # Simulate backup behavior
        # backup_path = f"{path}.bak.{os.urandom(8).hex()}"
        backup_path = f"{path}.{os.urandom(8).hex()}~"
        if os.path.exists(path):
            shutil.copyfile(path, backup_path)
        return backup_path

    def atomic_move(self, src, dst):
        if os.path.exists(src):
            shutil.move(src, dst)

    def atomic_write(self, dest, content, **kwargs):
        # Simulate atomic write
        with open(dest, "w") as f:
            f.write(content)
        return True  # Indicate success


class ModuleTestCase(unittest.TestCase):
    """
    Provides some infrastructure for using unittest.TestCase.

    Note that unittest.TestCase is not the recommended way of writing Ansible unit tests, but there
    still are a lot of existing tests in this form.
    """

    def setUp(self):
        self.mock_module = patch.multiple(
            basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module.start()
        self.mock_sleep = patch("time.sleep")
        self.mock_sleep.start()
        self.addCleanup(self.mock_module.stop)
        self.addCleanup(self.mock_sleep.stop)
