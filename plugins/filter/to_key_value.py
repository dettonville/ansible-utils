# -*- coding: utf-8 -*-
"""
to_markdown Ansible filter plugin
"""

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = """
  name: to_key_value
  short_description: Convert flat dictionary to key=value formatted text
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Convert flat dictionary to key=value formatted text.
  options:
    _input:
      description: The flat dictionary to convert.
      type: dict
      required: true
"""

EXAMPLES = """
- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # name=Alice
  # age=30
  # city=New York

- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=true) }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # name="Alice"
  # age="30"
  # city="New York"
"""

RETURN = """
  _value:
    description: formatted string representing the input data in key=value format.
    type: str
"""


__metaclass__ = type


def to_key_value(data, separator='=', joiner='\n', quote=False, quote_char='"'):
    """
    Converts a dictionary to a flat string of key=value pairs.
    :param quote: Boolean to enable/disable quoting values
    :param quote_char: The character to use for quoting (default: ")
    """
    if not isinstance(data, dict):
        return data

    lines = []
    for k, v in data.items():
        val = f"{quote_char}{v}{quote_char}" if quote else v
        lines.append(f"{k}{separator}{val}")

    return joiner.join(lines)


class FilterModule(object):
    def filters(self):
        return {
            'to_key_value': to_key_value
        }
