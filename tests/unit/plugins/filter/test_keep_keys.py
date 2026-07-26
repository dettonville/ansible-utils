# -*- coding: utf-8 -*-
"""
Unit tests for the keep_keys filter.
"""

import pytest
from ansible.errors import AnsibleFilterError
from ansible_collections.dettonville.utils.plugins.filter.keep_keys import (
    FilterModule,
)


@pytest.fixture
def filter_module():
    return FilterModule()


def test_keep_keys_flat_dict(filter_module):
    """Test keeping specific keys on a single flat dictionary (default non-recursive)."""
    input_dict = {
        "username": "admin",
        "password": "secret123",
        "email": "admin@example.com",
    }
    # Keep only username and email
    result = filter_module.keep_keys(input_dict, ["username", "email"])
    assert "username" in result
    assert "email" in result
    assert "password" not in result
    assert result["username"] == "admin"


def test_keep_keys_non_recursive_default(filter_module):
    """Test recursive=False retains all nested child nodes if top-level key matches."""
    input_dict = {
        "user": {
            "name": "admin",
            "credentials": {"password": "secret", "api_key": "key123"},
        },
        "other_key": "value",
    }
    # Using default behavior (recursive=False)
    result = filter_module.keep_keys(input_dict, ["user"])
    assert "user" in result
    assert "other_key" not in result
    assert "password" in result["user"]["credentials"]
    assert result["user"]["name"] == "admin"


def test_keep_keys_recursive(filter_module):
    """Test recursive=True filters out nested elements that don't match patterns."""
    input_dict = {
        "user": {
            "name": "admin",
            "password": "secret_password",
            "profile": {"name": "Administrator", "token": "token123"},
        },
        "settings": {"name": "global_config", "debug": True},
    }
    result = filter_module.keep_keys(input_dict, ["name"], recursive=True)

    assert "user" in result
    assert result["user"]["name"] == "admin"
    assert "password" not in result["user"]
    assert "profile" in result["user"]
    assert result["user"]["profile"]["name"] == "Administrator"
    assert "token" not in result["user"]["profile"]
    assert "settings" in result
    assert result["settings"]["name"] == "global_config"
    assert "debug" not in result["settings"]


def test_keep_keys_regex_patterns(filter_module):
    """Test keeping keys based on regex patterns (e.g., case insensitivity)."""
    input_dict = {"account_id": 111, "UserID": 222, "name": "test_user", "token": "abc"}
    # Match any key containing 'id' case-insensitively, plus 'name'
    patterns = ["(?i).*id.*", "name"]
    result = filter_module.keep_keys(input_dict, patterns)

    assert "account_id" in result
    assert "UserID" in result
    assert "name" in result
    assert "token" not in result


def test_keep_keys_list_of_dicts(filter_module):
    """Test filtering an array containing dictionaries."""
    input_list = [
        {"id": 1, "name": "app1", "env": "prod"},
        {"id": 2, "name": "app2", "env": "dev"},
    ]
    result = filter_module.keep_keys(input_list, ["id", "name"])

    assert isinstance(result, list)
    assert len(result) == 2
    assert "id" in result[0] and "name" in result[0]
    assert "env" not in result[0]


def test_empty_and_primitive_inputs(filter_module):
    """Test safe handling of empty inputs and un-filterable types."""
    assert filter_module.keep_keys({}, ["name"]) == {}
    assert filter_module.keep_keys([], ["name"]) == []
    assert filter_module.keep_keys("string_input", ["name"]) == "string_input"


def test_invalid_pattern_exception(filter_module):
    """Test that invalid regex patterns throw an AnsibleFilterError."""
    with pytest.raises(AnsibleFilterError, match="Invalid regex pattern"):
        filter_module.keep_keys({"name": "test"}, ["*[invalid-regex"])

    with pytest.raises(AnsibleFilterError, match="must be a list"):
        filter_module.keep_keys({"name": "test"}, "not-a-list")
