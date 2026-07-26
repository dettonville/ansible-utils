# -*- coding: utf-8 -*-
"""
to_markdown Ansible filter plugin
"""

from __future__ import absolute_import, division, print_function

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
    separator:
      description: String used to separate each key and value pair.
      type: str
      default: '='
    joiner:
      description: String used to join each formatted key-value pair line.
      type: str
      default: '\\n'
    quote:
      description: Toggle whether to wrap values in quote characters.
      type: bool
      default: false
    quote_char:
      description: The character used for quoting values when M(quote) is enabled.
      type: str
      default: '"'
    sort_keys:
      description: Toggle whether to sort keys alphanumerically instead of preserving insertion order.
      type: bool
      default: false
"""

EXAMPLES = """
- name: 1. Basic usage (default options)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value }}"
  vars:
    my_dict:
      DB_HOST: postgres
      DB_PORT: 5432
  # Output:
  # DB_HOST=postgres
  # DB_PORT=5432

- name: 2. Custom separator usage
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(separator=': ') }}"
  vars:
    my_dict:
      KEY: VALUE
  # Output:
  # KEY: VALUE

- name: 3. Quoted values (Double quotes)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=True) }}"
  vars:
    my_dict:
      API_KEY: secret123
  # Output:
  # API_KEY="secret123"

- name: 4. Quoted values (Single quotes)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=True, quote_char=\\"'\\") }}"
  vars:
    my_dict:
      API_KEY: secret123
  # Output:
  # API_KEY='secret123'

- name: 5. Sorted keys
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(sort_keys=True) }}"
  vars:
    my_dict:
      Z_KEY: last
      A_KEY: first
      M_KEY: middle
  # Output:
  # A_KEY=first
  # M_KEY=middle
  # Z_KEY=last
"""


__metaclass__ = type


def to_key_value(
    data, separator='=', joiner='\n', quote=False, quote_char='"', sort_keys=False
):
    """
    Converts a dictionary to a flat string of key=value pairs.
    :param separator: String used to separate key and value (default: '=')
    :param joiner: String used to join lines (default: '\n')
    :param quote: Boolean to enable/disable quoting values
    :param quote_char: The character to use for quoting (default: ")
    :param sort_keys: Boolean to sort keys in alphanumeric order (default: False)
    """
    if not isinstance(data, dict):
        return data

    # Use sorted keys if sort_keys is True, otherwise use standard dictionary ordering
    keys = sorted(data.keys()) if sort_keys else data.keys()

    lines = []
    for k in keys:
        v = data[k]
        val = f"{quote_char}{v}{quote_char}" if quote else v
        lines.append(f"{k}{separator}{val}")

    return joiner.join(lines)


class FilterModule(object):
    def filters(self):
        return {'to_key_value': to_key_value}
