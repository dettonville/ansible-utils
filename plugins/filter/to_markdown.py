# -*- coding: utf-8 -*-
"""
to_markdown Ansible filter plugin
"""

from __future__ import (absolute_import, division, print_function)
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    to_markdown,
)

DOCUMENTATION = """
  name: to_markdown
  short_description: Convert data structures to Markdown tables or formatted text
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Convert dictionaries or lists of dictionaries to Markdown tables.
    - For simple dicts, creates a key-value table.
    - For lists of dicts, creates a table with keys as headers.
    - Primitives are returned as-is.
    - Nested structures are flattened with dot notation.
  options:
    _input:
      description: The data to convert to Markdown.
      type: any
      required: true
    flatten_nested:
      description: Whether to flatten nested dicts.
      type: bool
      default: true
      required: false
"""

EXAMPLES = """
- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_markdown }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # | Key  | Value   |
  # |------|---------|
  # | name | Alice   |
  # | age  | 30      |
  # | city | New York |

- name: Convert list of dicts to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.to_markdown }}"
  vars:
    my_list:
      - name: Alice
        age: 30
        city: New York
      - name: Bob
        age: 25
        city: London
  # Produces:
  # | name | age | city     |
  # |------|-----|----------|
  # | Alice| 30  | New York |
  # | Bob  | 25  | London   |

- name: Convert nested dict (flattened)
  ansible.builtin.debug:
    msg: "{{ my_nested | dettonville.utils.to_markdown }}"
  vars:
    my_nested:
      user:
        name: Alice
        address:
          street: 123 Main St
          city: New York
      preferences:
        theme: dark
  # Produces:
  # | Key                  | Value     |
  # |----------------------|-----------|
  # | user.name            | Alice     |
  # | user.address.street  | 123 Main St |
  # | user.address.city    | New York  |
  # | preferences.theme    | dark      |
"""

RETURN = """
  _value:
    description: Markdown formatted string representing the input data.
    type: str
"""


__metaclass__ = type


class FilterModule(object):
    """Ansible jinja2 custom filter"""

    def filters(self):
        """Filters provided by this module"""
        return {"to_markdown": self.to_markdown}

    @staticmethod
    def to_markdown(data: any, flatten_nested: bool = True) -> str:
        """Convert data to Markdown."""
        return to_markdown(data, flatten_nested)
