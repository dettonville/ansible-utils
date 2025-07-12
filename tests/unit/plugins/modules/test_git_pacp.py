"""
Unit tests for the export_dicts Ansible module.

This test suite covers the actual implementation of the export_dicts module
which exports lists of dictionaries to CSV or Markdown format files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import unittest
from unittest.mock import Mock, patch

# from unittest.mock import Mock, patch, MagicMock, call

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.dettonville.utils.plugins.modules.git_pacp import (
    main as module_main,
    setup_module_object,
)

from ansible_collections.dettonville.utils.plugins.module_utils.git_actions import Git

MODULES_IMPORT_PATH = "ansible_collections.dettonville.utils.plugins.modules"
MODULE_UTILS_IMPORT_PATH = "ansible_collections.dettonville.utils.plugins.module_utils"


def make_absolute(base_path, name):
    return ".".join([base_path, name])


class TestGitPacpModule(unittest.TestCase):
    """Test cases for the git_pacp ansible module"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_module = Mock(spec=AnsibleModule)

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
            "logging_level": "INFO",
        }

        self.setup_module_object = setup_module_object
        self.main = module_main

        self.mock_module.tmpdir = "/tmp/ansible"
        self.mock_module.run_command_environ_update = {}
        self.mock_module.get_bin_path.return_value = "/usr/bin/git"
        self.mock_module.run_command.return_value = (0, "", "")
        self.mock_module.add_cleanup_file = Mock()
        self.mock_module.debug = Mock()
        self.mock_module.warn = Mock()
        self.mock_module.fail_json = Mock()
        self.mock_module.exit_json = Mock()

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
        self.assertEqual(arg_spec["action"]["choices"], ["acp", "pacp", "pull", "clone"])
        self.assertEqual(arg_spec["mode"]["choices"], ["ssh", "https", "local"])
        self.assertEqual(
            arg_spec["logging_level"]["choices"], ["NOTSET", "DEBUG", "INFO", "ERROR"]
        )

        # Verify defaults
        self.assertEqual(arg_spec["action"]["default"], "pacp")
        self.assertEqual(arg_spec["mode"]["default"], None)
        self.assertEqual(arg_spec["logging_level"]["default"], "INFO")

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_pacp_action_with_changes(
            self, mock_git_class, mock_ansible_module):
        """Test main function with pacp action when there are changes"""
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        # Mock git methods
        mock_git_instance.status.return_value = {"file1.txt", "file2.txt"}
        mock_git_instance.set_user_config.return_value = {"changed": True}
        mock_git_instance.pull.return_value = {
            "changed": True, "message": "pulled"}
        mock_git_instance.add.return_value = {
            "changed": True, "message": "added"}
        mock_git_instance.commit.return_value = {
            "changed": True,
            "message": "committed",
        }
        mock_git_instance.push.return_value = {
            "changed": True, "message": "pushed"}

        self.main()

        # Verify git operations were called in correct order
        mock_git_instance.status.assert_called_once()
        mock_git_instance.set_user_config.assert_called_once()
        mock_git_instance.pull.assert_called_once()
        mock_git_instance.add.assert_called_once()
        mock_git_instance.commit.assert_called_once_with("test commit")
        mock_git_instance.push.assert_called_once()

        # Verify module exit
        self.mock_module.exit_json.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.Git"))
    def test_main_acp_action_with_changes(
            self, mock_git_class, mock_ansible_module):
        """Test main function with acp action when there are changes"""
        self.mock_module.params["action"] = "acp"
        mock_ansible_module.return_value = self.mock_module
        mock_git_instance = Mock()
        mock_git_class.return_value = mock_git_instance

        # Mock git methods
        mock_git_instance.status.return_value = {"file1.txt"}
        mock_git_instance.set_user_config.return_value = {"changed": True}
        mock_git_instance.add.return_value = {
            "changed": True, "message": "added"}
        mock_git_instance.commit.return_value = {
            "changed": True,
            "message": "committed",
        }
        mock_git_instance.push.return_value = {
            "changed": True, "message": "pushed"}

        self.main()

        # Verify git operations were called in correct order (no pull for acp)
        mock_git_instance.status.assert_called_once()
        mock_git_instance.set_user_config.assert_called_once()
        mock_git_instance.pull.assert_not_called()  # Should not be called for acp
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
            "changed": True, "message": "cloned"}

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
            "changed": True, "message": "pulled"}

        self.main()

        # Verify only pull was called
        mock_git_instance.pull.assert_called_once()
        mock_git_instance.status.assert_not_called()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    def test_main_validation_https_mode(self, mock_ansible_module):
        """Test main function parameter validation for HTTPS mode"""
        mock_ansible_module.return_value = self.mock_module

        # Test with non-https URL but https mode
        self.mock_module.params["url"] = "git@github.com:test/repo.git"
        self.mock_module.params["mode"] = "https"

        self.main()

        # Should fail with appropriate message
        self.mock_module.fail_json.assert_called()

    @patch(make_absolute(MODULES_IMPORT_PATH, "git_pacp.AnsibleModule"))
    def test_main_validation_ssh_mode(self, mock_ansible_module):
        """Test main function parameter validation for SSH mode"""
        mock_ansible_module.return_value = self.mock_module

        # Test with https URL but ssh mode
        self.mock_module.params["url"] = "https://github.com/test/repo.git"
        self.mock_module.params["mode"] = "ssh"

        self.main()

        # Should fail with appropriate message
        self.mock_module.fail_json.assert_called()


class TestGitActions(unittest.TestCase):
    """Test cases for the Git class in git_actions module"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_module = Mock(spec=AnsibleModule)
        self.mock_module.params = {"executable": None, "logging_level": "INFO"}
        self.mock_module.tmpdir = "/tmp/ansible"
        self.mock_module.get_bin_path.return_value = "/usr/bin/git"
        self.mock_module.run_command.return_value = (0, "", "")
        self.mock_module.add_cleanup_file = Mock()
        self.mock_module.fail_json = Mock()

        self.repo_config = {
            "repo_url": "https://github.com/test/repo.git",
            "repo_dir": "/tmp/test_repo",
            "repo_scheme": "https",
            "repo_branch": "main",
            "remote": "origin",
            "push_option": None,
            "user": "testuser",
            "token": "testtoken",
            "ssh_params": None,
        }

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_git_init(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test Git class initialization"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        self.assertEqual(git.repo_url, "https://github.com/test/repo.git")
        self.assertEqual(git.repo_dir, "/tmp/test_repo")
        self.assertEqual(git.repo_scheme, "https")
        self.assertEqual(git.repo_branch, "main")
        self.assertEqual(git.remote, "origin")

    def test_get_url_scheme_https(self):
        """Test get_url_scheme method with HTTPS URL"""
        result = Git.get_url_scheme("https://github.com/test/repo.git")
        self.assertEqual(result, "https")

    def test_get_url_scheme_ssh(self):
        """Test get_url_scheme method with SSH URL"""
        result = Git.get_url_scheme("git@github.com:test/repo.git")
        self.assertEqual(result, "ssh")

    def test_get_url_scheme_local(self):
        """Test get_url_scheme method with local path"""
        result = Git.get_url_scheme("/path/to/repo.git")
        self.assertEqual(result, "local")

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_clone(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test clone method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        self.mock_module.run_command.return_value = (
            0, "Cloning into repo...", "")

        result = git.clone()

        self.assertTrue(result["changed"])
        self.assertIn("message", result)
        self.mock_module.run_command.assert_called()

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_pull(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test pull method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        self.mock_module.run_command.return_value = (
            0, "Already up to date.", "")

        result = git.pull()

        self.assertTrue(result["changed"])
        self.assertIn("message", result)

        # Check that correct command was called
        expected_command = ["/usr/bin/git", "pull", "origin", "main"]
        self.mock_module.run_command.assert_called_with(
            expected_command, check_rc=True, cwd="/tmp/test_repo"
        )

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_add(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test add method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        self.mock_module.run_command.return_value = (0, "", "")

        git.add()

        # Check that correct command was called
        expected_command = ["/usr/bin/git", "add", "--all", "."]
        self.mock_module.run_command.assert_called_with(
            expected_command, cwd="/tmp/test_repo"
        )

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_status(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test status method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git status output
        status_output = " M file1.txt\n A file2.txt\n?? file3.txt\n"
        self.mock_module.run_command.return_value = (0, status_output, "")

        result = git.status()

        self.assertIsInstance(result, set)
        self.assertIn("file1.txt", result)
        self.assertIn("file2.txt", result)
        self.assertIn("file3.txt", result)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_commit(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test commit method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        commit_output = "[main abc123] test commit\n 1 file changed, 1 insertion(+)"
        self.mock_module.run_command.return_value = (0, commit_output, "")

        result = git.commit("test commit")

        self.assertTrue(result["changed"])
        self.assertIn("message", result)

        # Check that correct command was called
        expected_command = ["/usr/bin/git", "commit", "-m", "test commit"]
        self.mock_module.run_command.assert_called_with(
            expected_command, cwd="/tmp/test_repo"
        )

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_push(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test push method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock successful remote get-url (remote already exists)
        self.mock_module.run_command.side_effect = [
            (0, "https://github.com/test/repo.git", ""),  # remote get-url
            (0, "Everything up-to-date", ""),  # push command
        ]

        result = git.push()

        self.assertTrue(result["changed"])
        self.assertIn("message", result)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_push_with_new_remote(
        self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp
    ):
        """Test push method when remote doesn't exist"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock remote get-url failure (remote doesn't exist) then successful
        # remote add and push
        self.mock_module.run_command.side_effect = [
            (128, "", "fatal: No such remote"),  # remote get-url fails
            (0, "", ""),  # remote add
            (0, "Everything up-to-date", ""),  # push command
        ]

        result = git.push()

        self.assertTrue(result["changed"])
        self.assertIn("message", result)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_set_user_config(self, mock_chmod, mock_stat,
                             mock_fdopen, mock_mkstemp):
        """Test set_user_config method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git config commands
        self.mock_module.run_command.side_effect = [
            (0, "old_name", ""),  # get current name
            (0, "", ""),  # set new name
            (0, "old_email", ""),  # get current email
            (0, "", ""),  # set new email
        ]

        user_config = {"name": "New Name", "email": "new@example.com"}

        result = git.set_user_config(user_config)

        self.assertTrue(result["changed"])

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_ssh_params_initialization(
        self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp
    ):
        """Test Git initialization with SSH parameters"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        ssh_params = {
            "key_file": "~/.ssh/id_rsa",
            "accept_hostkey": True,
            "ssh_opts": "-o UserKnownHostsFile=/dev/null",
        }

        repo_config = self.repo_config.copy()
        repo_config["ssh_params"] = ssh_params

        git = Git(self.mock_module, repo_config)

        self.assertEqual(git.ssh_key_file, "~/.ssh/id_rsa")
        self.assertTrue(git.ssh_accept_hostkey)
        self.assertIn("StrictHostKeyChecking=no", git.ssh_opts)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_git_version(self, mock_chmod, mock_stat,
                         mock_fdopen, mock_mkstemp):
        """Test git_version method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git --version output
        self.mock_module.run_command.return_value = (
            0, "git version 2.34.1", "")

        with patch(
            make_absolute(
                MODULE_UTILS_IMPORT_PATH, "git_actions.PACKAGING_VERSION_IMPORT_ERROR"
            ),
            None,
        ):
            version = git.git_version()
            self.assertIsNotNone(version)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_get_branches(self, mock_chmod, mock_stat,
                          mock_fdopen, mock_mkstemp):
        """Test get_branches method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git branch output
        branch_output = (
            "* main\n  develop\n  remotes/origin/main\n  remotes/origin/develop\n"
        )
        self.mock_module.run_command.return_value = (0, branch_output, "")

        branches = git.get_branches("/tmp/test_repo")

        self.assertIn("* main", branches)
        self.assertIn("develop", branches)
        self.assertIn("remotes/origin/main", branches)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_get_annotated_tags(
            self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test get_annotated_tags method"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git for-each-ref output
        tag_output = "tag:v1.0.0\ncommit:v1.0.1\ntag:v2.0.0\n"
        self.mock_module.run_command.return_value = (0, tag_output, "")

        tags = git.get_annotated_tags("/tmp/test_repo")

        self.assertIn("v1.0.0", tags)
        self.assertIn("v2.0.0", tags)
        self.assertNotIn("v1.0.1", tags)  # This is a commit, not a tag

    def test_write_ssh_wrapper_content(self):
        """Test that SSH wrapper script contains expected content"""
        with patch(
            make_absolute(
                MODULE_UTILS_IMPORT_PATH,
                "git_actions.tempfile.mkstemp")
        ) as mock_mkstemp:
            with patch(
                make_absolute(
                    MODULE_UTILS_IMPORT_PATH,
                    "git_actions.os.fdopen")
            ) as mock_fdopen:
                with patch(
                    make_absolute(
                        MODULE_UTILS_IMPORT_PATH,
                        "git_actions.os.stat")
                ) as mock_stat:
                    with patch(
                        make_absolute(
                            MODULE_UTILS_IMPORT_PATH,
                            "git_actions.os.chmod")
                    ) as mock_chmod:
                        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
                        mock_fh = Mock()
                        mock_fdopen.return_value = mock_fh
                        mock_stat.return_value = Mock(st_mode=0o644)

                        Git(self.mock_module, self.repo_config)

                        # Check that the wrapper script was written
                        mock_fh.write.assert_called_once()
                        written_content = mock_fh.write.call_args[0][0]

                        # Verify script contains expected elements
                        self.assertIn(b"#!/bin/sh", written_content)
                        self.assertIn(b"GIT_SSH_OPTS", written_content)
                        self.assertIn(b"GIT_KEY", written_content)
                        self.assertIn(b"BatchMode=yes", written_content)


class TestGitActionsErrorHandling(unittest.TestCase):
    """Test error handling in Git class"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_module = Mock(spec=AnsibleModule)
        self.mock_module.params = {
            'executable': None,
            'logging_level': 'DEBUG'
        }
        self.mock_module.tmpdir = '/tmp/ansible'
        self.mock_module.get_bin_path.return_value = '/usr/bin/git'
        self.mock_module.add_cleanup_file = Mock()
        self.mock_module.fail_json = Mock()
        self.mock_module.run_command.return_value = (0, "", "")

        self.repo_config = {
            'repo_url': 'https://github.com/test/repo.git',
            'repo_dir': '/tmp/test_repo',
            'repo_scheme': 'https',
            'repo_branch': 'main',
            'remote': 'origin',
            'push_option': None,
            'user': 'testuser',
            'token': 'testtoken',
            'ssh_params': None,
        }

    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_git_executable_not_found(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when git executable is not found"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     # Mock get_bin_path to return None (executable not found)
    #     self.mock_module.get_bin_path.return_value = None
    #
    #     with self.assertRaises(Exception):
    #         Git(self.mock_module, self.repo_config)
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_clone_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when clone command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock clone command failure
    #     self.mock_module.run_command.return_value = (128, "", "fatal: repository not found")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_pull_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when pull command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock pull command failure
    #     self.mock_module.run_command.return_value = (1, "", "fatal: not a git repository")
    #
    #     with self.assertRaises(Exception):
    #         git.pull()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_add_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when add command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock add command failure
    #     self.mock_module.run_command.return_value = (128, "", "fatal: pathspec did not match any files")
    #
    #     with self.assertRaises(Exception):
    #         git.add()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_commit_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when commit command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock commit command failure
    #     self.mock_module.run_command.return_value = (1, "", "nothing to commit, working tree clean")
    #
    #     with self.assertRaises(Exception):
    #         git.commit("test commit")
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_push_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when push command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock successful remote get-url, then push failure
    #     self.mock_module.run_command.side_effect = [
    #         (0, "https://github.com/test/repo.git", ""),  # remote get-url success
    #         (1, "", "fatal: authentication failed"),  # push failure
    #     ]
    #
    #     with self.assertRaises(Exception):
    #         git.push()

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_push_remote_add_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test error handling when remote add fails during push"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock remote get-url failure, then remote add failure
        self.mock_module.run_command.side_effect = [
            (128, "", "fatal: No such remote"),  # remote get-url fails
            (128, "", "fatal: remote origin already exists"),  # remote add fails
        ]

        with self.assertRaises(Exception):
            git.push()

    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_status_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when status command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock status command failure
    #     self.mock_module.run_command.return_value = (128, "", "fatal: not a git repository")
    #
    #     with self.assertRaises(Exception):
    #         git.status()

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_set_user_config_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test error handling when setting user config fails"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        git = Git(self.mock_module, self.repo_config)

        # Mock git config command failure
        self.mock_module.run_command.side_effect = [
            (0, "old_name", ""),  # get current name success
            (1, "", "error: could not lock config file"),  # set name failure
        ]

        user_config = {"name": "New Name", "email": "new@example.com"}

        with self.assertRaises(Exception):
            git.set_user_config(user_config)

    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_git_version_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when git version command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock git version command failure
    #     self.mock_module.run_command.return_value = (127, "", "command not found")
    #
    #     with self.assertRaises(Exception):
    #         git.git_version()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_get_branches_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when get branches command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock git branch command failure
    #     self.mock_module.run_command.return_value = (128, "", "fatal: not a git repository")
    #
    #     with self.assertRaises(Exception):
    #         git.get_branches("/tmp/test_repo")
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_get_annotated_tags_command_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling when get annotated tags command fails"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock git for-each-ref command failure
    #     self.mock_module.run_command.return_value = (128, "", "fatal: not a git repository")
    #
    #     with self.assertRaises(Exception):
    #         git.get_annotated_tags("/tmp/test_repo")

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_ssh_wrapper_creation_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test error handling when SSH wrapper creation fails"""
        # Mock tempfile.mkstemp to raise an exception
        mock_mkstemp.side_effect = OSError("Unable to create temporary file")

        with self.assertRaises(OSError):
            Git(self.mock_module, self.repo_config)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_ssh_wrapper_write_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test error handling when SSH wrapper write fails"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        # Mock file write to raise an exception
        mock_fh.write.side_effect = IOError("Unable to write to file")

        with self.assertRaises(IOError):
            Git(self.mock_module, self.repo_config)

    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    def test_ssh_wrapper_chmod_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
        """Test error handling when SSH wrapper chmod fails"""
        mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
        mock_fh = Mock()
        mock_fdopen.return_value = mock_fh
        mock_stat.return_value = Mock(st_mode=0o644)

        # Mock chmod to raise an exception
        mock_chmod.side_effect = OSError("Permission denied")

        with self.assertRaises(OSError):
            Git(self.mock_module, self.repo_config)

    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_invalid_url_scheme(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for invalid URL schemes"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     # Test with invalid URL scheme
    #     invalid_config = self.repo_config.copy()
    #     invalid_config['repo_url'] = 'ftp://example.com/repo.git'
    #     invalid_config['repo_scheme'] = 'ftp'
    #
    #     git = Git(self.mock_module, invalid_config)
    #
    #     # The get_url_scheme method should handle this gracefully
    #     # but operations like clone might fail
    #     self.mock_module.run_command.return_value = (128, "", "fatal: unsupported protocol")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_network_connection_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for network connection failures"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock network connection failure
    #     self.mock_module.run_command.return_value = (
    #     128, "", "fatal: unable to access 'https://github.com/test/repo.git/': Could not resolve host")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_authentication_failure(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for authentication failures"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock authentication failure
    #     self.mock_module.run_command.return_value = (
    #     128, "", "fatal: Authentication failed for 'https://github.com/test/repo.git/'")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_permission_denied_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for permission denied errors"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock permission denied error
    #     self.mock_module.run_command.return_value = (
    #     128, "", "fatal: could not create work tree dir '/tmp/test_repo': Permission denied")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_disk_space_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for disk space errors"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock disk space error
    #     self.mock_module.run_command.return_value = (128, "", "fatal: write error: No space left on device")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_merge_conflict_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for merge conflict errors"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock merge conflict error
    #     self.mock_module.run_command.return_value = (1, "", "CONFLICT (content): Merge conflict in file.txt")
    #
    #     with self.assertRaises(Exception):
    #         git.pull()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_empty_commit_message_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for empty commit message"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock empty commit message error
    #     self.mock_module.run_command.return_value = (1, "", "Aborting commit due to empty commit message.")
    #
    #     with self.assertRaises(Exception):
    #         git.commit("")
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_branch_not_found_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for branch not found errors"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     # Set up config with non-existent branch
    #     config_with_bad_branch = self.repo_config.copy()
    #     config_with_bad_branch['repo_branch'] = 'nonexistent-branch'
    #
    #     git = Git(self.mock_module, config_with_bad_branch)
    #
    #     # Mock branch not found error
    #     self.mock_module.run_command.return_value = (
    #     128, "", "fatal: couldn't find remote ref refs/heads/nonexistent-branch")
    #
    #     with self.assertRaises(Exception):
    #         git.pull()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.stat"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.chmod"))
    # def test_timeout_error(self, mock_chmod, mock_stat, mock_fdopen, mock_mkstemp):
    #     """Test error handling for timeout errors"""
    #     mock_mkstemp.return_value = (1, "/tmp/ssh_wrapper")
    #     mock_fh = Mock()
    #     mock_fdopen.return_value = mock_fh
    #     mock_stat.return_value = Mock(st_mode=0o644)
    #
    #     git = Git(self.mock_module, self.repo_config)
    #
    #     # Mock timeout error
    #     self.mock_module.run_command.return_value = (128, "", "fatal: The remote end hung up unexpectedly")
    #
    #     with self.assertRaises(Exception):
    #         git.clone()
    #
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.tempfile.mkstemp"))
    # @patch(make_absolute(MODULE_UTILS_IMPORT_PATH, "git_actions.os.fdopen"))
