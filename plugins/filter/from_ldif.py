# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

from typing import Any, Dict

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    from_ldif,
)

__metaclass__ = type

DOCUMENTATION = """
  name: from_ldif
  short_description: Parse LDIF text back into a dictionary
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Parses a single LDIF record and returns a Python dictionary.
    - Automatically decodes base64-encoded values (C(::) notation).
    - Converts repeated attributes into lists (multi-valued support).
    - Handles line folding.
  options:
    _input:
      description: LDIF formatted string to be parsed into a dictionary.
      type: str
      required: true
"""

EXAMPLES = """
- name: Parse LDIF back to dict
  ansible.builtin.set_fact:
    ldap_entry: "{{ ldif_content | dettonville.utils.from_ldif }}"

- name: Example with base64
  ansible.builtin.debug:
    msg: "{{ ldif_data | dettonville.utils.from_ldif }}"
  vars:
    ldif_data: |
      dn: cn=search,dc=example,dc=com
      description:: TERBUCBSZWFkIE9ubHkgVXNlcg==
"""

RETURN = """
  _value:
    description: Dictionary representing the parsed LDAP entry.
    type: dict
"""


class FilterModule(object):
    def filters(self):
        return {"from_ldif": self.from_ldif}

    @staticmethod
    def from_ldif(ldif_str: str) -> Dict[str, Any]:
        return from_ldif(ldif_str)
