# -*- coding: utf-8 -*-

import pytest
from unittest.mock import MagicMock
from ansible_collections.dettonville.utils.plugins.action.debug_sanitized import ActionModule


class MockTemplar:
    def template(self, data):
        # Simplistic templar mock helper that returns data directly or unpacks mock variables
        if isinstance(data, str) and data.startswith("{{ ") and data.endswith(" }}"):
            var_name = data[3:-3].strip()
            if var_name == "my_secret_dict":
                return {"username": "lee", "password": "dont-log-me"}
        return data


@pytest.fixture
def action_module():
    # Construct a flexible MockTask using MagicMock so it satisfies internal Ansible base attribute checks
    task = MagicMock()
    task.args = {}
    task.async_val = None

    connection = MagicMock()
    play_context = MagicMock()
    loader = MagicMock()
    templar = MockTemplar()
    shared_loader_obj = MagicMock()

    # ActionModule constructor syntax: (task, connection, play_context, loader, templar, shared_loader_obj)
    plugin = ActionModule(task, connection, play_context, loader, templar, shared_loader_obj)
    return plugin


def test_debug_sanitized_msg_default(action_module):
    """Verify that default messages fall back to empty string cleanly when no options exist."""
    action_module._task.args = {}
    result = action_module.run(task_vars={})
    assert result['msg'] == ""


def test_debug_sanitized_mutually_exclusive(action_module):
    """Verify that passing both msg and var breaks early with a failed status message."""
    action_module._task.args = {"msg": "test", "var": "some_var"}
    result = action_module.run(task_vars={})
    assert result['failed'] is True
    assert "mutually exclusive" in result['msg']


def test_debug_sanitized_var_resolution(action_module):
    """Verify that dynamic complex dictionary lookups get completely redacted via key lookups."""
    action_module._task.args = {"var": "my_secret_dict"}

    result = action_module.run(task_vars={})

    assert "my_secret_dict" in result
    sanitized_output = result["my_secret_dict"]
    assert sanitized_output["username"] == "lee"
    assert sanitized_output["password"] == "<redacted_password>"


def test_debug_sanitized_with_custom_additional_patterns(action_module):
    """Verify that specifying additional key patterns redacts unexpected custom domain metadata."""
    secret_payload = {"account_identifier": "id-1", "custom_secret_field": "sensitive-data"}

    action_module._task.args = {
        "var": secret_payload,
        "additional_key_patterns": ["(?i).*secret.*"]
    }

    result = action_module.run(task_vars={})
    sanitized_output = result["var"]
    assert sanitized_output["account_identifier"] == "id-1"
    assert sanitized_output["custom_secret_field"] == "<redacted_custom_secret_field>"
