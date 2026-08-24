"""
Unit tests for the git_pacp Ansible module.

This test suite covers the actual implementation of the export_dicts module
which exports lists of dictionaries to CSV or Markdown format files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pprint
import unittest
from unittest.mock import Mock, patch

# from unittest.mock import Mock, patch, MagicMock, call
# noinspection PyPackageRequirements
from ansible.module_utils.basic import AnsibleModule

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.module_utils.git_actions import (  # noqa: E501
    Git,
)

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.modules import (
    git_pacp,
)

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.modules.git_pacp import (
    main as module_main,
)

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.modules.git_pacp import (
    setup_module_object,
)

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.tests.unit.plugins.modules.utils import (  # noqa: E501
    MODULE_UTILS_IMPORT_PATH,
    MODULES_IMPORT_PATH,
    AnsibleFailJson,
    ModuleTestCase,
    make_absolute,
    set_module_args,
)


# noinspection PyPep8Naming
class TestGitPacpModule(ModuleTestCase):
    """Test cases for the git_pacp ansible module"""

    def setUp(self):
        """Set up test fixtures"""
        super(TestGitPacpModule, self).setUp()
        self.module = git_pacp
        self.mock_module = Mock(spec=AnsibleModule)
        self.mock_module.check_mode = False

        self.mock_module.params = {
            "url": "https://github.com/test/repo.git",
            "path": "/tmp/test_repo",
            "action": "pacp",
            "comment": "test commit",
            "add": ["."],
            "user": "testuser",
            "token": "testtoken",
            "branch": "main",
            "push_option": None,
            "mode": "https",
            "remote": "origin",
            "user_name": "Test User",
            "user_email": "test@example.com",
            "ssh_params": None,
            "executable": None,
            "logging_level": "DEBUG",
        }

        self.setup_module_object = setup_module_object
        self.main = module_main

        self.mock_module.tmpdir = "/tmp/ansible_test_tmp"
        self.mock_module.run_command_environ_update = {}
        self.mock_module.get_bin_path.return_value = "/usr/bin/git"
        self.mock_module.run_command.return_value = (0, "", "")
        self.mock_module.add_cleanup_file = Mock()
        self.mock_module.debug = Mock()
        self.mock_module.warn = Mock()
        self.mock_module.fail_json = Mock(side_effect=AnsibleFailJson)
        self.mock_module.exit_json = Mock()

    def tearDown(self):
        pass

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    def test_setup_module_object(self, mock_ansible_module):
        """Test module object setup."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module

        self.setup_module_object()

        # Verify AnsibleModule was called with correct parameters
        mock_ansible_module.assert_called_once()
        args, kwargs = mock_ansible_module.call_args

        # Check that argument_spec is properly defined
        self.assertIn("argument_spec", kwargs)
        arg_spec = kwargs["argument_spec"]

        # Verify required parameters
        self.assertIn("url", arg_spec)
        self.assertIn("path", arg_spec)
        self.assertEqual(arg_spec["url"]["required"], True)
        self.assertEqual(arg_spec["path"]["required"], True)

        # Verify optional parameters
        self.assertIn("action", arg_spec)
        self.assertIn("executable", arg_spec)
        self.assertIn("comment", arg_spec)
        self.assertIn("add", arg_spec)
        self.assertIn("ssh_params", arg_spec)
        self.assertIn("branch", arg_spec)
        self.assertIn("user_name", arg_spec)
        self.assertIn("user_email", arg_spec)
        self.assertIn("logging_level", arg_spec)

        # Verify choices
        self.assertEqual(
            arg_spec["action"]["choices"], ["acp", "pacp", "pull", "clone"]
        )
        self.assertEqual(
            arg_spec["mode"]["choices"], ["ssh", "https", "local"]
        )
        self.assertEqual(
            arg_spec["logging_level"]["choices"],
            ["NOTSET", "DEBUG", "INFO", "ERROR"],
        )

        # Verify defaults
        self.assertEqual(arg_spec["action"]["default"], "pacp")
        self.assertEqual(arg_spec["mode"]["default"], None)
        self.assertEqual(arg_spec["logging_level"]["default"], "INFO")

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_pacp_action_with_changes(
        self, mock_git_class, mock_ansible_module
    ):
        """Test main function with pacp action when there are changes"""
        self.setUp()
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        # Mock git methods
        mock_git_instance.status.return_value = {"file1.txt"}
        mock_git_instance.check_uncommitted_changes.return_value = False
        mock_git_instance.set_user_config.return_value = {"changed": True}
        mock_git_instance.pull.return_value = {
            "changed": True,
            "message": "pulled",
        }
        mock_git_instance.add.return_value = {
            "changed": True,
            "message": "added",
        }
        mock_git_instance.commit.return_value = {
            "changed": True,
            "message": "committed",
        }
        mock_git_instance.push.return_value = {
            "changed": True,
            "message": "pushed",
        }

        self.main()

        # Verify git operations were called in correct order
        mock_git_instance.status.assert_called_once()
        mock_git_instance.pull.assert_called_once()
        mock_git_instance.add.assert_called_once()
        mock_git_instance.commit.assert_called_once_with("test commit")
        mock_git_instance.push.assert_called_once()

        # Verify module exit
        self.mock_module.exit_json.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_acp_action_with_changes(
        self, mock_git_class, mock_ansible_module
    ):
        """Test main function with acp action when there are changes"""
        self.mock_module.params["action"] = "acp"
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        # Mock git methods
        mock_git_instance.status.return_value = {"file1.txt"}
        mock_git_instance.set_user_config.return_value = {"changed": True}
        mock_git_instance.add.return_value = {
            "changed": True,
            "message": "added",
        }
        mock_git_instance.commit.return_value = {
            "changed": True,
            "message": "committed",
        }
        mock_git_instance.push.return_value = {
            "changed": True,
            "message": "pushed",
        }

        self.main()

        # Verify git operations were called in correct order (no pull for acp)
        mock_git_instance.status.assert_called_once()
        # Should not be called for acp
        mock_git_instance.pull.assert_not_called()
        mock_git_instance.add.assert_called_once()
        mock_git_instance.commit.assert_called_once_with("test commit")
        mock_git_instance.push.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_no_changes(self, mock_git_class, mock_ansible_module):
        """Test main function when there are no changes"""
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        # Mock no changes
        mock_git_instance.status.return_value = set()

        self.main()

        # Verify only status was called
        mock_git_instance.status.assert_called_once()
        mock_git_instance.set_user_config.assert_not_called()
        mock_git_instance.pull.assert_not_called()
        mock_git_instance.add.assert_not_called()
        mock_git_instance.commit.assert_not_called()
        mock_git_instance.push.assert_not_called()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_clone_action(self, mock_git_class, mock_ansible_module):
        """Test main function with clone action"""
        self.mock_module.params["action"] = "clone"
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        mock_git_instance.clone.return_value = {
            "changed": True,
            "message": "cloned",
        }

        self.main()

        # Verify only clone was called
        mock_git_instance.clone.assert_called_once()
        mock_git_instance.status.assert_not_called()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_pull_action(self, mock_git_class, mock_ansible_module):
        """Test main function with pull action"""
        self.mock_module.params["action"] = "pull"
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        mock_git_instance.pull.return_value = {
            "changed": True,
            "message": "pulled",
        }

        self.main()

        # Verify only pull was called
        mock_git_instance.pull.assert_called_once()
        mock_git_instance.status.assert_not_called()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_validation_https_mode(self, mock_git_class):
        """Test main function parameter validation for HTTPS mode"""
        module_args = self.mock_module.params
        module_args.update(
            {"url": "git@github.com:test/repo.git", "mode": "https"}
        )

        with set_module_args(module_args):
            with self.assertRaises(AnsibleFailJson) as exc:
                self.module.main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))

        # Should fail with appropriate message
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"],
            "HTTPS mode selected but url (git@github.com:test/repo.git) "
            'not starting with "https"',
        )

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_validation_ssh_mode(self, mock_git_class):
        """Test main function parameter validation for SSH mode"""
        module_args = self.mock_module.params
        module_args.update(
            {"url": "https://github.com/test/repo.git", "mode": "ssh"}
        )

        with set_module_args(module_args):
            with self.assertRaises(AnsibleFailJson) as exc:
                self.module.main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))

        # Should fail with appropriate message
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"],
            "SSH mode selected but url (https://github.com/test/repo.git) "
            'not starting with "git" or "ssh://git"',
        )

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    def test_setup_module_object_ssh_params_keys(self, mock_ansible_module):
        """Test ssh_params option definition for key and key_file."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module

        # noinspection PyUnresolvedReferences
        self.setup_module_object()
        _args, kwargs = mock_ansible_module.call_args
        ssh_options = kwargs["argument_spec"]["ssh_params"]["options"]

        self.assertIn("key", ssh_options)
        self.assertIn("key_file", ssh_options)
        self.assertEqual(ssh_options["key"]["type"], "str")
        self.assertEqual(ssh_options["key_file"]["type"], "path")

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_validation_mutually_exclusive_ssh_keys(self, mock_git_class):
        """Test that supplying both key and key_file fails validation."""
        module_args = self.mock_module.params.copy()
        module_args.update(
            {
                "mode": "ssh",
                "url": "git@github.com:test/repo.git",
                "ssh_params": {
                    "key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest",
                    "key_file": "/path/to/id_rsa",
                },
            }
        )

        with set_module_args(module_args):
            with self.assertRaises(AnsibleFailJson) as exc:
                self.main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertIn("mutually exclusive", result["msg"].lower())


class TestGitActions(unittest.TestCase):
    """Test cases for the Git class in git_actions module"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_module = Mock(spec=AnsibleModule)
        self.mock_module.check_mode = False
        self.mock_module.tmpdir = "/tmp/ansible_test_tmp"
        self.mock_module.params = {"logging_level": "DEBUG"}
        self.mock_module.get_bin_path.return_value = "/usr/bin/git"
        self.mock_module.run_command.return_value = (0, "", "")
        self.mock_module.add_cleanup_file = Mock()
        self.mock_module.fail_json = Mock()

        # This should correctly reflect the repo_config as passed to Git
        self.repo_config = {
            "repo_url": "https://github.com/test/repo.git",
            "repo_dir": "/tmp/test_repo",
            "repo_branch": "main",
            "user": "testuser",
            "token": "testtoken",
        }

    def tearDown(self):
        pass

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    @patch(
        make_absolute(
            MODULE_UTILS_IMPORT_PATH, "git_actions.Git.execute_git_command"
        )
    )
    @patch(
        make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.environ"),
        new_callable=dict,
    )
    def test_add(
        self,
        mock_environ,
        mock_execute_git_command,
        mock_chmod,
        mock_stat,
        mock_fdopen,
    ):
        """Test add method"""
        self.setUp()  # Ensure setup is called for each test method

        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        # Ensure execute_git_command returns a successful tuple
        mock_execute_git_command.return_value = (
            0,
            "Mocked stdout for add",
            "Mocked stderr for add",
        )

        git = Git(self.mock_module, self.repo_config)

        # Call add
        result = git.add()

        print("result =>", pprint.pformat(result))

        # Assertions
        mock_execute_git_command.assert_called_once_with(
            ["add", "--all", "."],
            cwd="/tmp/test_repo",
            check_rc=True,
        )

        # Check that no fail_json was called (implicitly) if the command
        # succeeded as mocked
        self.mock_module.fail_json.assert_not_called()

    # Add a test case for an SSH clone scenario to fully test the new logic
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    @patch(
        make_absolute(
            MODULE_UTILS_IMPORT_PATH, "git_actions.Git.execute_git_command"
        )
    )
    @patch(
        make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.environ"),
        new_callable=dict,
    )
    def test_ssh_clone_accept_hostkey(
        self,
        mock_environ,
        mock_execute_git_command,
        mock_chmod,
        mock_stat,
        mock_fdopen,
    ):
        """Test SSH clone with accept_hostkey=True"""
        self.setUp()

        repo_config = self.repo_config

        # noinspection PyTypeChecker
        repo_config.update(
            {
                "repo_url": "git@github.com:test/repo.git",
                "ssh_params": {
                    "accept_hostkey": True,
                    "key_file": "/some/path/ansible_repo.key",
                    "ssh_opts": "-o UserKnownHostsFile=/dev/null",
                },
            }
        )

        # Ensure execute_git_command returns a successful tuple
        mock_execute_git_command.return_value = (0, "Cloning...", "")

        git = Git(self.mock_module, repo_config)

        # Assert that the GIT_SSH_COMMAND is correctly formed
        expected_ssh_command = (
            "ssh -i /some/path/ansible_repo.key -o IdentitiesOnly=yes"
        )
        expected_ssh_command += (
            " -o BatchMode=yes -o UserKnownHostsFile=/dev/null"
            " -o StrictHostKeyChecking=no"
        )

        # Assert that the correct GIT_SSH_COMMAND is set correctly
        self.assertIn("GIT_SSH_COMMAND", git.module.run_command_environ_update)
        self.assertEqual(
            git.module.run_command_environ_update["GIT_SSH_COMMAND"],
            expected_ssh_command,
        )

        result = git.clone()

        print("result =>", pprint.pformat(result))

        mock_execute_git_command.assert_called_once_with(
            [
                "clone",
                "--single-branch",
                "--branch",
                "main",
                "--depth=1",
                "--origin",
                "origin",
                "git@github.com:test/repo.git",
                "/tmp/test_repo",
            ],
            check_rc=True,
            cwd="/tmp/test_repo",
        )

        self.assertTrue(result["changed"])
        self.assertEqual(result["message"], "Cloning...")

        self.mock_module.fail_json.assert_not_called()

        # Clean up mock environment after the test
        mock_environ.clear()

    @patch(
        make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp")
    )
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_ssh_key_value_creates_tempfile(
        self, mock_chmod, mock_fdopen, mock_mkstemp
    ):
        """Test handling of raw private key string parameter."""
        mock_mkstemp.return_value = (10, "/tmp/git_key_12345")
        mock_file = Mock()
        mock_fdopen.return_value.__enter__.return_value = mock_file

        repo_config = self.repo_config.copy()
        # noinspection PyTypeChecker
        repo_config.update(
            {
                "repo_scheme": "ssh",
                "ssh_params": {
                    "key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",  # noqa: E501
                    "accept_hostkey": True,
                },
            }
        )

        git = Git(self.mock_module, repo_config)

        mock_mkstemp.assert_called_once()
        mock_file.write.assert_called_once_with(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"  # noqa: E501
        )  # noqa: E501
        mock_chmod.assert_called_once_with("/tmp/git_key_12345", 0o600)
        self.mock_module.add_cleanup_file.assert_called_once_with(
            "/tmp/git_key_12345"
        )
        # noinspection PyTypeChecker
        self.assertIn("/tmp/git_key_12345", git.git_ssh_command)
