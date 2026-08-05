# -*- coding: utf-8 -*-
"""
Unit tests for the to_key_value filter.
"""

# noinspection PyPackageRequirements
import pytest

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.filter.to_key_value import (
    FilterModule,
)


@pytest.fixture
def filter_module():
    return FilterModule()


def test_to_key_value_basic(filter_module):
    """Test basic dictionary to key=value conversion"""
    data = {'DB_HOST': 'postgres', 'DB_PORT': '5432'}
    # Expected output is joined by newlines
    expected = "DB_HOST=postgres\nDB_PORT=5432"

    # We use 'to_key_value' as the filter name defined in your FilterModule
    result = filter_module.filters()['to_key_value'](data)
    assert result == expected


def test_to_key_value_custom_separator(filter_module):
    """Test using a custom separator like a colon"""
    data = {'KEY': 'VALUE'}
    expected = "KEY: VALUE"

    result = filter_module.filters()['to_key_value'](data, separator=': ')
    assert result == expected


def test_to_key_value_empty(filter_module):
    """Test that an empty dictionary returns an empty string"""
    data = {}
    result = filter_module.filters()['to_key_value'](data)
    assert result == ""


def test_to_key_value_non_dict(filter_module):
    """Test that non-dictionary input is returned as-is (graceful failure)"""
    data = "not a dict"
    result = filter_module.filters()['to_key_value'](data)
    assert result == "not a dict"


def test_to_key_value_complex_values(filter_module):
    """Test handling of values that look like lists/strings"""
    data = {'CORS_ORIGIN': "['*']", 'ENABLED': 'true'}
    expected = "CORS_ORIGIN=['*']\nENABLED=true"
    result = filter_module.filters()['to_key_value'](data)
    assert result == expected


def test_to_key_value_quoted(filter_module):
    """Test values wrapped in double quotes"""
    data = {'API_KEY': 'secret123'}
    expected = 'API_KEY="secret123"'

    result = filter_module.filters()['to_key_value'](data, quote=True)
    assert result == expected


def test_to_key_value_single_quote(filter_module):
    """Test values wrapped in custom single quotes"""
    data = {'API_KEY': 'secret123'}
    expected = "API_KEY='secret123'"

    result = filter_module.filters()['to_key_value'](
        data, quote=True, quote_char="'"
    )
    assert result == expected


def test_to_key_value_default_no_sort(filter_module):
    """Test that keys retain their dictionary/insertion order by default"""
    data = {'Z_KEY': 'last', 'A_KEY': 'first', 'M_KEY': 'middle'}
    expected = "Z_KEY=last\nA_KEY=first\nM_KEY=middle"

    result = filter_module.filters()['to_key_value'](data)
    assert result == expected


def test_to_key_value_sorted_keys(filter_module):
    """Test that keys are sorted alphanumerically when sort_keys=True"""
    data = {'Z_KEY': 'last', 'A_KEY': 'first', 'M_KEY': 'middle'}
    expected = "A_KEY=first\nM_KEY=middle\nZ_KEY=last"

    result = filter_module.filters()['to_key_value'](data, sort_keys=True)
    assert result == expected
