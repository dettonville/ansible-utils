# -*- coding: utf-8 -*-
"""
Unit tests for the sort_dict_keys filter.
"""

import pytest
from ansible_collections.dettonville.utils.plugins.filter.sort_dict_keys import (
    FilterModule,
)  # Adjust import path as needed


@pytest.fixture
def filter_module():
    return FilterModule()


def test_sort_simple_dict(filter_module):
    """Test sorting keys in a simple dict."""
    input_dict = {
        "c": "value_c",
        "a": "value_a",
        "b": "value_b"
    }
    result = filter_module.sort_dict_keys(input_dict)
    expected = {
        "a": "value_a",
        "b": "value_b",
        "c": "value_c"
    }
    assert result == expected


def test_sort_nested_dict(filter_module):
    """Test sorting keys in nested dicts."""
    input_dict = {
        "user": {
            "z_name": "admin",
            "credentials": {
                "y_token": "token123",
                "x_password": "secret"
            }
        },
        "other": "value"
    }
    result = filter_module.sort_dict_keys(input_dict)
    expected = {
        "other": "value",
        "user": {
            "credentials": {
                "x_password": "secret",
                "y_token": "token123"
            },
            "z_name": "admin"
        }
    }
    assert result == expected


def test_sort_list_of_dicts(filter_module):
    """Test sorting in a list of dicts."""
    input_list = [
        {"c": "c1", "a": "a1", "b": "b1"},
        {"z": "z2", "x": "x2", "y": "y2"}
    ]
    result = filter_module.sort_dict_keys(input_list)
    expected = [
        {"a": "a1", "b": "b1", "c": "c1"},
        {"x": "x2", "y": "y2", "z": "z2"}
    ]
    assert result == expected


def test_sort_mixed_structure(filter_module):
    """Test sorting in mixed dict/list structure."""
    input_obj = {
        "accounts": [
            {"id": 2, "name": "bob"},
            {"id": 1, "name": "alice"}
        ],
        "z_settings": {
            "y_vault": "vault",
            "x_token": "token"
        }
    }
    result = filter_module.sort_dict_keys(input_obj)
    expected = {
        "accounts": [
            {"id": 2, "name": "bob"},
            {"id": 1, "name": "alice"}
        ],
        "z_settings": {
            "x_token": "token",
            "y_vault": "vault"
        }
    }
    assert result == expected


def test_sort_nested_list(filter_module):
    """Test sorting in deeply nested lists and dicts."""
    input_obj = {
        "top": [
            {"level1": {"z": "z", "x": "x", "y": "y"}},
            "string",
            [{"nested": {"b": "b", "a": "a"}}]
        ]
    }
    result = filter_module.sort_dict_keys(input_obj)
    expected = {
        "top": [
            {"level1": {"x": "x", "y": "y", "z": "z"}},
            "string",
            [{"nested": {"a": "a", "b": "b"}}]
        ]
    }
    assert result == expected


def test_sort_empty_input(filter_module):
    """Test with empty dict or list."""
    empty_dict = {}
    result_dict = filter_module.sort_dict_keys(empty_dict)
    assert result_dict == {}

    empty_list = []
    result_list = filter_module.sort_dict_keys(empty_list)
    assert result_list == []


def test_sort_primitive_values(filter_module):
    """Test that primitive values (non-dict) are unchanged."""
    input_obj = {"key": "value", "number": 123, "bool": True, "list": [1, 2, 3]}
    result = filter_module.sort_dict_keys(input_obj)
    # Assuming it only sorts dict keys, leaves others intact
    assert result["key"] == "value"
    assert result["number"] == 123
    assert result["bool"] is True
    assert result["list"] == [1, 2, 3]


def test_sort_case_sensitive(filter_module):
    """Test case-sensitive sorting (default alphabetical order)."""
    input_dict = {
        "Z": "z_value",
        "a": "a_value",
        "B": "b_value"
    }
    result = filter_module.sort_dict_keys(input_dict)
    expected = {
        "B": "b_value",
        "Z": "z_value",
        "a": "a_value"
    }
    assert result == expected


def test_sort_with_reverse_option(filter_module):
    """Test with reverse sorting if the filter supports it (assuming optional param)."""
    input_dict = {
        "a": "value_a",
        "b": "value_b",
        "c": "value_c"
    }
    result = filter_module.sort_dict_keys(input_dict, reverse=True)
    expected = {
        "c": "value_c",
        "b": "value_b",
        "a": "value_a"
    }
    assert result == expected
