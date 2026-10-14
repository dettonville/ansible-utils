# -*- coding: utf-8 -*-
"""
Unit tests for the redact_sensitive_values filter.
"""

# noinspection PyPackageRequirements
import pytest

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.filter.redact_sensitive_values import (  # noqa: E501
    FilterModule,
)

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


def test_redact_single_dict_password(filter_module, default_patterns):
    """Test redacting a password in a simple dict."""
    input_dict = {"username": "admin", "password": "secret123"}
    result = filter_module.redact_sensitive_values(input_dict)
    assert result["username"] == "admin"
    assert result["password"] == "<redacted>"


def test_redact_nested_dict(filter_module):
    """Test redacting in nested dicts."""
    input_dict = {
        "user": {
            "name": "admin",
            "credentials": {"password": "secret", "api_key": "key123"},
        },
        "other": "value",
    }
    result = filter_module.redact_sensitive_values(input_dict)
    assert result["user"]["name"] == "admin"
    assert result["user"]["credentials"]["password"] == "<redacted>"
    assert result["user"]["credentials"]["api_key"] == "<redacted>"
    assert result["other"] == "value"


def test_redact_list_of_dicts(filter_module):
    """Test redacting in a list of dicts."""
    input_list = [
        {"username": "user1", "password": "pass1"},
        {"username": "user2", "password": "pass2"},
    ]
    result = filter_module.redact_sensitive_values(input_list)
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["username"] == "user1"
    assert result[0]["password"] == "<redacted>"
    assert result[1]["username"] == "user2"
    assert result[1]["password"] == "<redacted>"


def test_redact_mixed_structure(filter_module):
    """Test redacting in mixed dict/list structure."""
    input_obj = {
        "accounts": [
            {"id": 1, "password": "pass1"},
            {"id": 2, "credentials": {"token": "token1"}},
        ],
        "settings": {"vault_password": "vaultpass"},
    }
    result = filter_module.redact_sensitive_values(input_obj)
    assert result["accounts"][0]["id"] == 1
    assert result["accounts"][0]["password"] == "<redacted>"
    assert result["accounts"][1]["id"] == 2
    assert result["accounts"][1]["credentials"]["token"] == "<redacted>"
    assert result["settings"]["vault_password"] == "<redacted>"


def test_custom_patterns(filter_module):
    """Test with custom key patterns."""
    custom_patterns = ["(?i).*secret.*"]
    input_dict = {"secret_key": "mysecret", "normal_key": "normal"}
    result = filter_module.redact_sensitive_values(
        input_dict, key_patterns=custom_patterns
    )
    assert result["normal_key"] == "normal"
    assert result["secret_key"] == "<redacted>"


def test_additional_patterns(filter_module):
    """Test with additional key patterns."""
    input_dict = {"password": "pass", "ssh_key": "sshkey"}
    result = filter_module.redact_sensitive_values(
        input_dict, additional_key_patterns=["(?i).*ssh.*"]
    )
    assert result["password"] == "<redacted>"
    assert result["ssh_key"] == "<redacted>"


def test_no_patterns(filter_module):
    """Test with empty patterns (uses default)."""
    input_dict = {"password": "pass"}
    result = filter_module.redact_sensitive_values(input_dict, key_patterns=[])
    assert result["password"] == "<redacted>"


def test_non_matching_keys(filter_module):
    """Test that non-matching keys are unchanged."""
    input_dict = {
        "username": "admin",
        "keycloak": "foobar",
        "description": "some desc",
        "password": "secret",
    }
    result = filter_module.redact_sensitive_values(input_dict)
    assert result["username"] == "admin"
    assert result["keycloak"] == "foobar"
    assert result["description"] == "some desc"
    assert result["password"] == "<redacted>"


def test_empty_input(filter_module):
    """Test with empty dict or list."""
    empty_dict = {}
    result_dict = filter_module.redact_sensitive_values(empty_dict)
    assert result_dict == {}

    empty_list = []
    result_list = filter_module.redact_sensitive_values(empty_list)
    assert result_list == []


def test_primitive_values(filter_module):
    """Test that primitive values (non-container) are handled
    correctly (only if key matches)."""
    input_dict = {"password": "secret", "number": 123, "bool": True}
    result = filter_module.redact_sensitive_values(input_dict)
    assert result["password"] == "<redacted>"
    assert result["number"] == 123
    assert result["bool"] is True


def test_case_insensitive_patterns(filter_module):
    """Test case-insensitive matching."""
    input_dict = {"PASSWORD": "secret", "ApiKey": "key123"}
    result = filter_module.redact_sensitive_values(input_dict)
    assert result["PASSWORD"] == "<redacted>"
    assert result["ApiKey"] == "key123"


def test_redact_sensitive_values_with_peek(filter_module):
    data = {"api_key": "secret-token-xyz"}
    result = filter_module.redact_sensitive_values(
        data, peek=True, peek_chars=2
    )
    assert result["api_key"] == "<redacted:se...yz>"
