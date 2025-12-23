# -*- coding: utf-8 -*-
"""
Unit tests for the remove_sensitive_keys filter.
"""

import pytest
from ansible_collections.dettonville.utils.plugins.filter.remove_sensitive_keys import (
    FilterModule,
)  # Adjust import path as needed

# Assuming the FilterModule is in the correct path; adjust if necessary


@pytest.fixture
def filter_module():
    return FilterModule()


@pytest.fixture
def default_patterns():
    return [
        "(?i).*vault.*",
        "(?i).*token.*",
        "(?i).*password.*",
        "(?i).*key.*",
        "(?i).*ssh.*",
    ]


def test_remove_single_dict_password(filter_module):
    """Test removing a password key from a simple dict."""
    input_dict = {
        "username": "admin",
        "password": "secret123"
    }
    result = filter_module.remove_sensitive_keys(input_dict)
    assert "username" in result
    assert result["username"] == "admin"
    assert "password" not in result


def test_remove_nested_dict(filter_module):
    """Test removing in nested dicts."""
    input_dict = {
        "user": {
            "name": "admin",
            "credentials": {
                "password": "secret",
                "api_key": "key123"
            }
        },
        "other": "value"
    }
    result = filter_module.remove_sensitive_keys(input_dict)
    assert result["user"]["name"] == "admin"
    assert "password" not in result["user"]["credentials"]
    assert "api_key" not in result["user"]["credentials"]
    assert result["other"] == "value"


def test_remove_list_of_dicts(filter_module):
    """Test removing in a list of dicts."""
    input_list = [
        {"username": "user1", "password": "pass1"},
        {"username": "user2", "password": "pass2"}
    ]
    result = filter_module.remove_sensitive_keys(input_list)
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["username"] == "user1"
    assert "password" not in result[0]
    assert result[1]["username"] == "user2"
    assert "password" not in result[1]


def test_remove_mixed_structure(filter_module):
    """Test removing in mixed dict/list structure."""
    input_obj = {
        "accounts": [
            {"id": 1, "password": "pass1"},
            {"id": 2, "credentials": {"token": "token1"}}
        ],
        "settings": {"vault_password": "vaultpass"}
    }
    result = filter_module.remove_sensitive_keys(input_obj)
    assert result["accounts"][0]["id"] == 1
    assert "password" not in result["accounts"][0]
    assert result["accounts"][1]["id"] == 2
    assert "token" not in result["accounts"][1]["credentials"]
    assert "vault_password" not in result["settings"]


def test_custom_patterns(filter_module):
    """Test with custom key patterns."""
    custom_patterns = ["(?i).*secret.*"]
    input_dict = {
        "secret_key": "mysecret",
        "normal_key": "normal"
    }
    result = filter_module.remove_sensitive_keys(input_dict, key_patterns=custom_patterns)
    assert "normal_key" in result
    assert result["normal_key"] == "normal"
    assert "secret_key" not in result


def test_additional_patterns(filter_module):
    """Test with additional key patterns."""
    input_dict = {
        "password": "pass",
        "ssh_key": "sshkey"
    }
    result = filter_module.remove_sensitive_keys(
        input_dict,
        additional_key_patterns=["(?i).*ssh.*"]
    )
    assert "password" not in result
    assert "ssh_key" not in result


def test_no_patterns(filter_module):
    """Test with empty patterns (uses default)."""
    input_dict = {"password": "pass"}
    result = filter_module.remove_sensitive_keys(input_dict, key_patterns=[])
    assert "password" not in result


def test_non_matching_keys(filter_module):
    """Test that non-matching keys are unchanged."""
    input_dict = {
        "username": "admin",
        "description": "some desc",
        "password": "secret"
    }
    result = filter_module.remove_sensitive_keys(input_dict)
    assert result["username"] == "admin"
    assert result["description"] == "some desc"
    assert "password" not in result


def test_empty_input(filter_module):
    """Test with empty dict or list."""
    empty_dict = {}
    result_dict = filter_module.remove_sensitive_keys(empty_dict)
    assert result_dict == {}

    empty_list = []
    result_list = filter_module.remove_sensitive_keys(empty_list)
    assert result_list == []


def test_primitive_values(filter_module):
    """Test that primitive values (non-container) are handled correctly (only if key matches)."""
    input_dict = {"password": "secret", "number": 123, "bool": True}
    result = filter_module.remove_sensitive_keys(input_dict)
    assert "password" not in result
    assert "number" in result
    assert result["number"] == 123
    assert "bool" in result
    assert result["bool"] is True


def test_case_insensitive_patterns(filter_module):
    """Test case-insensitive matching."""
    input_dict = {"PASSWORD": "secret", "ApiKey": "key123"}
    result = filter_module.remove_sensitive_keys(input_dict)
    assert "PASSWORD" not in result
    assert "ApiKey" not in result


def test_nested_list_removal(filter_module):
    """Test removal in deeply nested lists and dicts."""
    input_obj = {
        "top": [
            {"level1": {"password": "secret"}},
            "string",
            [{"nested_password": "nested"}],
        ]
    }
    result = filter_module.remove_sensitive_keys(input_obj)
    assert "password" not in result["top"][0]["level1"]
    assert result["top"][1] == "string"
    assert "nested_password" not in result["top"][2][0]
