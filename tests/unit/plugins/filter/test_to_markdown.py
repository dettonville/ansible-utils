# -*- coding: utf-8 -*-
"""
Unit tests for the to_markdown filter.
"""

import pytest
from ansible_collections.dettonville.utils.plugins.filter.to_markdown import (
    FilterModule,
)  # Adjust import path as needed


@pytest.fixture
def filter_module():
    return FilterModule()


def test_to_markdown_simple_dict(filter_module):
    """Test converting a simple dict to Markdown."""
    input_dict = {
        "name": "Alice",
        "age": 30,
        "city": "New York"
    }
    result = filter_module.to_markdown(input_dict)
    expected = """| Key | Value |
|-----|-------|
| name | Alice |
| age | 30 |
| city | New York |"""
    assert result == expected


def test_to_markdown_list_of_dicts(filter_module):
    """Test converting a list of dicts to Markdown table."""
    input_list = [
        {"name": "Alice", "age": 30, "city": "New York"},
        {"name": "Bob", "age": 25, "city": "London"},
        {"name": "Charlie", "age": 35, "city": "Paris"}
    ]
    result = filter_module.to_markdown(input_list)
    expected = """| name | age | city |
| --- | --- | --- |
| Alice | 30 | New York |
| Bob | 25 | London |
| Charlie | 35 | Paris |"""
    assert result == expected


def test_to_markdown_nested_dict(filter_module):
    """Test converting a nested dict to Markdown (flattened)."""
    input_dict = {
        "user": {
            "name": "Alice",
            "address": {
                "street": "123 Main St",
                "city": "New York"
            }
        },
        "preferences": {"theme": "dark"}
    }
    result = filter_module.to_markdown(input_dict)
    expected = """| Key | Value |
|-----|-------|
| user.name | Alice |
| user.address.street | 123 Main St |
| user.address.city | New York |
| preferences.theme | dark |"""
    assert result == expected


def test_to_markdown_mixed_structure(filter_module):
    """Test converting mixed structure to Markdown (flattened dict with list repr)."""
    input_obj = {
        "title": "Users Report",
        "users": [
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25}
        ],
        "summary": "Two users listed."
    }
    result = filter_module.to_markdown(input_obj)
    expected = """| Key | Value |
|-----|-------|
| title | Users Report |
| users | [{'name': 'Alice', 'age': 30}, {'name': 'Bob', 'age': 25}] |
| summary | Two users listed. |"""
    assert result == expected


def test_to_markdown_empty_input(filter_module):
    """Test with empty dict or list."""
    empty_dict = {}
    result_dict = filter_module.to_markdown(empty_dict)
    assert result_dict == "| Key | Value |\n|-----|-------|"

    empty_list = []
    result_list = filter_module.to_markdown(empty_list)
    assert result_list == "|  |  |\n|---|----|"


def test_to_markdown_primitive_values(filter_module):
    """Test that primitive values are handled (e.g., converted to simple text)."""
    input_str = "Hello World"
    result_str = filter_module.to_markdown(input_str)
    assert result_str == "Hello World"

    input_num = 42
    result_num = filter_module.to_markdown(input_num)
    assert result_num == "42"


def test_to_markdown_with_flatten_option(filter_module):
    """Test with flatten_nested=False (uses non-flattened dict table)."""
    input_dict = {
        "user": {
            "name": "Alice",
            "address": {
                "street": "123 Main St",
                "city": "New York"
            }
        }
    }
    result = filter_module.to_markdown(input_dict, flatten_nested=False)
    expected = """| Key | Value |
|-----|-------|
| user | {'name': 'Alice', 'address': {'street': '123 Main St', 'city': 'New York'}} |"""
    assert result == expected


def test_to_markdown_complex_nested_list(filter_module):
    """Test deeply nested lists and dicts (flattened)."""
    input_obj = {
        "data": [
            {
                "level1": {
                    "items": [
                        {"name": "Item1"},
                        {"name": "Item2"}
                    ]
                }
            }
        ]
    }
    result = filter_module.to_markdown(input_obj)
    expected = """| Key | Value |
|-----|-------|
| data | [{'level1': {'items': [{'name': 'Item1'}, {'name': 'Item2'}]}}] |"""
    assert result == expected
