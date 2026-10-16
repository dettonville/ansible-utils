# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, mock_open, patch

from ansible_collections.dettonville.utils.plugins.modules import (
    git_update_content,
)


class TestGitUpdateContentModule:
    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.Git'
    )
    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.AnsibleModule'
    )
    def test_git_update_content_overwrite(
        self, mock_ansible_module, mock_git_class
    ):
        module_instance = MagicMock()
        module_instance.params = {
            "git_repo_url": "ssh://git@repo.example.org:2222/ansible/demo.git",
            "git_repo_branch": "main",
            "branch_name": "feature/test",
            "content": {"vars/test.yml": {"key": "value"}},
            "state": "overwrite",
            "git_comment_prefix": "TEST",
            "post_gitea_pr": False,
            "gitea_api_token": None,
            "ssh_params": {},
            "logging_level": "INFO",
        }
        mock_ansible_module.return_value = module_instance

        git_instance = mock_git_class.return_value
        git_instance.path = "/tmp/mock_repo"

        # Use mock_open with valid string content to prevent parser
        # recursion/hanging
        m_open = mock_open(read_data="key: old_value\n")

        with patch('os.path.exists', return_value=True), patch(
            'builtins.open', m_open
        ), patch('os.makedirs'):
            manager = git_update_content.GitUpdateContentManager(
                module_instance
            )
            manager.run()

        git_instance.clone.assert_called_once()
        git_instance.push.assert_called_once()
        module_instance.exit_json.assert_called_once()

    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.Git'
    )
    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.AnsibleModule'
    )
    def test_git_update_content_merge(
        self, mock_ansible_module, mock_git_class
    ):
        module_instance = MagicMock()
        module_instance.params = {
            "git_repo_url": "ssh://git@repo.example.org:2222/ansible/demo.git",
            "git_repo_branch": "main",
            "branch_name": "feature/test-merge",
            "content": {"vars/test.yml": {"new_key": "new_value"}},
            "state": "merge",
            "git_comment_prefix": "TEST",
            "post_gitea_pr": False,
            "gitea_api_token": None,
            "ssh_params": {},
            "logging_level": "INFO",
        }
        mock_ansible_module.return_value = module_instance

        git_instance = mock_git_class.return_value
        git_instance.path = "/tmp/mock_repo"

        m_open = mock_open(read_data="existing_key: old_value\n")

        with patch('os.path.exists', return_value=True), patch(
            'builtins.open', m_open
        ), patch('os.makedirs'):
            manager = git_update_content.GitUpdateContentManager(
                module_instance
            )
            manager.run()

        git_instance.clone.assert_called_once()
        git_instance.push.assert_called_once()
        module_instance.exit_json.assert_called_once()

    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.Git'
    )
    @patch(
        'ansible_collections.dettonville.utils.plugins.modules.git_update_content.AnsibleModule'
    )
    def test_git_update_content_absent(
        self, mock_ansible_module, mock_git_class
    ):
        module_instance = MagicMock()
        module_instance.params = {
            "git_repo_url": "ssh://git@repo.example.org:2222/ansible/demo.git",
            "git_repo_branch": "main",
            "branch_name": "feature/test-absent",
            "content": {"vars/test.yml": {}},
            "state": "absent",
            "git_comment_prefix": "TEST",
            "post_gitea_pr": False,
            "gitea_api_token": None,
            "ssh_params": {},
            "logging_level": "INFO",
        }
        mock_ansible_module.return_value = module_instance

        git_instance = mock_git_class.return_value
        git_instance.path = "/tmp/mock_repo"

        with patch('os.path.exists', return_value=True), patch(
            'os.remove'
        ) as mock_remove, patch('os.makedirs'):
            manager = git_update_content.GitUpdateContentManager(
                module_instance
            )
            manager.run()

        mock_remove.assert_called_once()
        git_instance.push.assert_called_once()
        module_instance.exit_json.assert_called_once()
