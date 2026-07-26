# -*- coding: utf-8 -*-
"""
Expanded unit tests for the custom ruamel-backed to_nice_yaml filter.
"""

from unittest.mock import patch
import pytest
from ansible_collections.dettonville.utils.plugins.filter.to_nice_yaml_utils import (
    FilterModule,
)


@pytest.fixture
def filter_module():
    return FilterModule()


@patch('ansible.utils.display.Display.warning')
def test_ruamel_version_warning_legacy(mock_warning, filter_module):
    """Verify that a warning is logged when a legacy version of ruamel.yaml is detected."""
    # Temporarily force the mock module layout environment to mimic an older library version
    with patch(
        'ansible_collections.dettonville.utils.plugins.filter.to_nice_yaml_utils.yaml'
    ) as mock_yaml:
        mock_yaml.__version__ = "0.16.12"
        filter_module._check_ruamel_version()
        assert mock_warning.called
        assert "Upgrading to 'ruamel.yaml>=0.17.22'" in mock_warning.call_args[0][0]


@patch('ansible.utils.display.Display.warning')
def test_ruamel_version_warning_modern(mock_warning, filter_module):
    """Verify that no warning is logged when a modern version of ruamel.yaml is detected."""
    with patch(
        'ansible_collections.dettonville.utils.plugins.filter.to_nice_yaml_utils.yaml'
    ) as mock_yaml:
        mock_yaml.__version__ = "0.18.5"
        filter_module._check_ruamel_version()
        assert not mock_warning.called


def test_custom_indentation_formatting(filter_module):
    """Verify that custom indentation formats to valid YAML containing the expected structures."""
    # Dynamically import ruamel safely inside xdist worker scope
    try:
        from ruamel import yaml
    except ImportError:
        import ruamel_yaml as yaml

    input_data = {"config": {"services": [{"name": "nginx", "port": 80}]}}

    yaml_output = filter_module.to_nice_yaml(
        input_data, mapping=4, sequence=6, offset=3
    )
    lines = yaml_output.splitlines()

    # Assert structural content invariants exist
    assert "config:" in lines[0]

    target_line = [line for line in lines if "name: nginx" in line][0]
    assert "-" in target_line
    assert "name: nginx" in target_line

    # Verify semantic integrity via a round-trip parse
    ryaml = yaml.YAML(typ='safe')
    parsed_data = ryaml.load(yaml_output)
    assert parsed_data == input_data


def test_explicit_start_option(filter_module):
    """Verify that explicit_start adds the '---' directive."""
    input_data = {"key": "value"}
    yaml_output = filter_module.to_nice_yaml(input_data, explicit_start=True)
    assert yaml_output.startswith("---")


def test_sort_keys_option(filter_module):
    """Verify that keys are alphabetically ordered when sort_keys=True."""
    input_data = {"z_key": 1, "m_key": 2, "a_key": 3}
    yaml_output = filter_module.to_nice_yaml(input_data, sort_keys=True)
    lines = [line.strip() for line in yaml_output.splitlines() if line.strip()]

    # Check execution order matches sorted values
    assert lines[0].startswith("a_key:")
    assert lines[1].startswith("m_key:")
    assert lines[2].startswith("z_key:")


def test_allow_unicode_option(filter_module):
    """Verify handling of unicode characters."""
    input_data = {"greet": "こんにちは"}
    yaml_output = filter_module.to_nice_yaml(input_data, allow_unicode=True)
    assert "こんにちは" in yaml_output


def test_lists_of_primitives(filter_module):
    """Verify that a sequence of flat scalar primitives converts correctly."""
    input_data = {"items": ["apple", "banana", "cherry"]}
    yaml_output = filter_module.to_nice_yaml(
        input_data, mapping=2, sequence=4, offset=2
    )
    lines = yaml_output.splitlines()

    assert "items:" in lines[0]
    # Check list indicator indentation properties
    assert lines[1].strip() == "- apple"


def test_deeply_nested_structures(filter_module):
    """Test alignment consistency down multiple nesting tiers."""
    input_data = {"tier1": {"tier2": {"tier3": [{"element": "value"}]}}}
    yaml_output = filter_module.to_nice_yaml(
        input_data, mapping=4, sequence=5, offset=2
    )
    assert "tier1:" in yaml_output
    assert "element: value" in yaml_output


def test_offset_greater_than_sequence_edge_case(filter_module):
    """Verify that when offset is greater than sequence, the filter automatically
    adjusts sequence to match offset to prevent layout engine format crashes.
    """
    input_data = {"items": [{"name": "test"}]}

    # Pass arguments where offset (4) exceeds sequence (2)
    yaml_output = filter_module.to_nice_yaml(input_data, sequence=2, offset=4)
    lines = yaml_output.splitlines()

    # Locate the list item line
    item_line = [line for line in lines if "- name:" in line][0]
    item_indent = len(item_line) - len(item_line.lstrip(' '))

    # Because our code adjusts sequence to equal offset (4), both ruamel variants
    # will process this consistently.
    # On environments where sequence == offset yields the hanging offset (like ruamel_yaml in CI): item_indent will be 4
    # On environments where sequence == offset falls back to flat block (like community ruamel.yaml locally): item_indent will be 0
    assert item_indent in [0, 4], (
        f"Unexpected indentation fallback for safety adjustment boundary test. Got: {item_indent}"
    )


def test_primitive_types_handling(filter_module):
    """Verify clean dumps of basic scalars."""
    assert "test_string" in filter_module.to_nice_yaml("test_string")
    assert "12345" in filter_module.to_nice_yaml(12345)


def test_empty_collection_structures(filter_module):
    """Verify empty objects return valid empty syntax blocks."""
    assert "{}" in filter_module.to_nice_yaml(
        {}
    ) or "null" in filter_module.to_nice_yaml({})
    assert "[]" in filter_module.to_nice_yaml(
        []
    ) or "null" in filter_module.to_nice_yaml([])


def test_ansible_jinja_proxy_wrapper_structures(filter_module):
    """
    Reproduce and verify handling of internal Ansible/Jinja proxy wrappers
    for both collections and custom scalar primitives (e.g., ints, bools).
    """

    # Define mock proxy structures mimicking Ansible's internal container wrappers
    class MockAnsibleMapping(dict):
        pass

    class MockAnsibleSequence(list):
        pass

    # Mimic custom proxy objects wrapping basic scalar types
    class MockAnsibleInt(int):
        pass

    class MockAnsibleBool:
        def __init__(self, val):
            self.val = val

        def __bool__(self):
            return self.val

        # If isinstance check falls back to a type checking interface
        def __index__(self):
            return 1 if self.val else 0

    # Recreate a scenario featuring structural proxies and custom wrapped primitives (like the '15' error)
    failing_payload = MockAnsibleMapping(
        {
            'attachable': True,
            'timeout': MockAnsibleInt(
                15
            ),  # Triggers the 'cannot represent an object: 15' flaw
            'ipam': MockAnsibleMapping(
                {'config': MockAnsibleSequence([{'subnet': '192.168.10.0/24'}])}
            ),
        }
    )

    yaml_output = filter_module.to_nice_yaml(failing_payload, sort_keys=True)

    assert "attachable: true" in yaml_output.lower()
    assert "timeout: 15" in yaml_output
    assert "192.168.10.0/24" in yaml_output


def test_nested_sequence_default_indentation(filter_module):
    """Verify that by default, nested lists are indented 2 spaces deeper than their parent keys."""
    input_data = {
        "deploy": {"labels": ["traefik.enable=true", "traefik.swarm.lbswarm=true"]}
    }

    yaml_output = filter_module.to_nice_yaml(input_data, sort_keys=False)
    lines = yaml_output.splitlines()

    # Locate the line index positions
    labels_idx = -1
    item_idx = -1

    for idx, line in enumerate(lines):
        if "labels:" in line:
            labels_idx = idx
        elif "traefik.enable=true" in line:
            item_idx = idx

    assert labels_idx != -1, "Could not find 'labels:' parent key in output string."
    assert item_idx != -1, "Could not find sequence item element in output string."

    # Calculate exact leading indentation characters count
    labels_indent_count = len(lines[labels_idx]) - len(lines[labels_idx].lstrip(' '))
    item_indent_count = len(lines[item_idx]) - len(lines[item_idx].lstrip(' '))

    # Confirm that the list hyphen is placed exactly 2 spaces forward from the key margin
    assert item_indent_count == labels_indent_count + 2, (
        f"Nested list indentation error: parent key indentation is {labels_indent_count}, "
        f"but list item hyphen indentation is {item_indent_count} (Expected delta of +2)."
    )


def test_nested_sequence_with_child_mappings_indentation(filter_module):
    """Verify that deeply nested dictionaries inside list item blocks are correctly shifted
    forward along with their parent list hyphen, preserving child property indentation.
    """
    # Wrap with a root service container to push 'deploy' down to a 2-space baseline margin
    input_data = {
        "services": {
            "ollama": {
                "deploy": {
                    "resources": {
                        "reservations": {
                            "generic_resources": [
                                {
                                    "discrete_resource_spec": {
                                        "kind": "NVIDIA-GPU",
                                        "value": 1,
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }

    yaml_output = filter_module.to_nice_yaml(input_data, sort_keys=False)
    lines = yaml_output.splitlines()

    # Locate the target lines and calculate their exact leading spaces
    spec_line = None
    kind_line = None
    value_line = None

    for line in lines:
        if "- discrete_resource_spec:" in line:
            spec_line = line
        elif "kind: NVIDIA-GPU" in line:
            kind_line = line
        elif "value: 1" in line:
            value_line = line

    assert spec_line is not None, (
        "Could not find list entry '- discrete_resource_spec:' in output"
    )
    assert kind_line is not None, (
        "Could not find child mapping element 'kind: NVIDIA-GPU' in output"
    )
    assert value_line is not None, (
        "Could not find child mapping element 'value: 1' in output"
    )

    spec_indent = len(spec_line) - len(spec_line.lstrip(' '))
    kind_indent = len(kind_line) - len(kind_line.lstrip(' '))
    value_indent = len(value_line) - len(value_line.lstrip(' '))

    # Verification Indentation Hierarchy Math:
    # services: (0 spaces)
    #   ollama: (2 spaces)
    #     deploy: (4 spaces)
    #       resources: (6 spaces)
    #         reservations: (8 spaces)
    #           generic_resources: (10 spaces)
    #             - discrete_resource_spec: (Expected: 12 spaces)
    #                 kind: NVIDIA-GPU (Expected: 16 spaces - child mapping indented 4 spaces forward)
    #                 value: 1 (Expected: 16 spaces - child mapping indented 4 spaces forward)

    assert spec_indent == 12, (
        f"Parent sequence element indent was {spec_indent}, expected 12"
    )
    assert kind_indent == 16, (
        f"Nested child key 'kind' indent was {kind_indent}, expected 16"
    )
    assert value_indent == 16, (
        f"Nested child key 'value' indent was {value_indent}, expected 16"
    )
