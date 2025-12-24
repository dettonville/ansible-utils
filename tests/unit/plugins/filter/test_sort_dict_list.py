# -*- coding: utf-8 -*-
"""
Unit tests for the sort_dict_list filter.
"""

import pytest
from ansible_collections.dettonville.utils.plugins.filter.sort_dict_list import (
    FilterModule,
)  # Adjust import path as needed


@pytest.fixture
def filter_module():
    return FilterModule()


def test_sort_simple_list_by_key(filter_module):
    """Test sorting a simple list of dicts by a key."""
    input_list = [
        {"name": "charlie", "age": 30},
        {"name": "alice", "age": 25},
        {"name": "bob", "age": 35}
    ]
    result = filter_module.sort_dict_list(input_list, "name")
    expected = [
        {"name": "alice", "age": 25},
        {"name": "bob", "age": 35},
        {"name": "charlie", "age": 30}
    ]
    assert result == expected


def test_sort_list_by_age_ascending(filter_module):
    """Test sorting by numeric key ascending."""
    input_list = [
        {"name": "charlie", "age": 30},
        {"name": "alice", "age": 25},
        {"name": "bob", "age": 35}
    ]
    result = filter_module.sort_dict_list(input_list, "age")
    expected = [
        {"name": "alice", "age": 25},
        {"name": "charlie", "age": 30},
        {"name": "bob", "age": 35}
    ]
    assert result == expected


def test_sort_list_by_multiple_keys(filter_module):
    """Test sorting by multiple keys."""
    input_list = [
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.31.25.54",
            "username": "careconlocal",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.31.25.54",
            "username": "administrator",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.21.33.8",
            "username": "careconlocal",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.21.33.8",
            "username": "administrator",
        },
    ]
    result = filter_module.sort_dict_list(
        input_list, ["platform_id", "address", "username"]
    )
    expected = [
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.21.33.8",
            "username": "administrator",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.21.33.8",
            "username": "careconlocal",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.31.25.54",
            "username": "administrator",
        },
        {
            "platform_id": "WND-Local-Managed-DMZ",
            "address": "10.31.25.54",
            "username": "careconlocal",
        },
    ]
    assert result == expected


def test_sort_nested_list_of_dicts(filter_module):
    """Test sorting nested lists of dicts."""
    users_list = [
        {"name": "zack", "age": 40},
        {"name": "xavier", "age": 30},
        {"name": "yara", "age": 35}
    ]
    result = filter_module.sort_dict_list(users_list, "name")
    expected = [
        {"name": "xavier", "age": 30},
        {"name": "yara", "age": 35},
        {"name": "zack", "age": 40}
    ]
    assert result == expected


def test_sort_mixed_structure_with_lists(filter_module):
    """Test sorting lists within a mixed structure."""
    accounts = [
        {"id": 3, "name": "charlie"},
        {"id": 1, "name": "alice"},
        {"id": 2, "name": "bob"}
    ]
    result = filter_module.sort_dict_list(accounts, "name")
    expected = [
        {"id": 1, "name": "alice"},
        {"id": 2, "name": "bob"},
        {"id": 3, "name": "charlie"}
    ]
    assert result == expected


def test_sort_empty_list(filter_module):
    """Test with empty list."""
    empty_list = []
    result = filter_module.sort_dict_list(empty_list, "name")
    assert result == []


def test_sort_list_with_missing_keys(filter_module):
    """Test sorting when some dicts miss the key (should handle gracefully, e.g., treat as None)."""
    input_list = [
        {"name": "alice"},
        {"age": 25},  # Missing name
        {"name": "bob", "age": 30}
    ]
    result = filter_module.sort_dict_list(input_list, "name")
    # Assuming missing keys are treated as None and sorted first
    expected = [
        {"age": 25},
        {"name": "alice"},
        {"name": "bob", "age": 30}
    ]
    assert result == expected


def test_sort_case_sensitive(filter_module):
    """Test case-sensitive sorting."""
    input_list = [
        {"name": "Zack"},
        {"name": "alice"},
        {"name": "Bob"}
    ]
    result = filter_module.sort_dict_list(input_list, "name")
    expected = [
        {"name": "Bob"},
        {"name": "Zack"},
        {"name": "alice"}
    ]
    assert result == expected


def test_sort_non_list_input(filter_module):
    """Test that non-list inputs raise an error or are handled."""
    input_dict = {"key": "value"}
    # Assuming it raises TypeError for non-list
    with pytest.raises(TypeError):
        filter_module.sort_dict_list(input_dict, "key")
