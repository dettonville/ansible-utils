# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

from typing import Any, Dict

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    to_ldif,
)

__metaclass__ = type

DOCUMENTATION = """
  name: to_ldif
  short_description: Convert a dictionary to LDIF format
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - >-
      Converts a dictionary representing an LDAP entry into a properly
      formatted, RFC 2849-compliant LDIF record string (with line folding
      at 76 characters).
    - >-
      Supports multi-valued attributes, automatic base64 encoding for
      unsafe values, and explicit base64 via C(::) suffix notation.
    - Preserves ordering (dn and changetype appear first when present).
  options:
    _input:
      description: Dictionary containing the LDAP entry attributes.
      type: dict
      required: true
"""

EXAMPLES = """
- name: Convert dict to LDIF
  ansible.builtin.debug:
    msg: "{{ my_entry | dettonville.utils.to_ldif }}"
  vars:
    my_entry:
      dn: "cn=admins,ou=groups,dc=example,dc=com"
      objectClass: ["top", "posixGroup"]
      cn: "admins"
      gidNumber: 2000

- name: Add entry with changetype
  ansible.builtin.debug:
    msg: "{{ entry | dettonville.utils.to_ldif }}"
  vars:
    entry:
      dn: "cn=testuser,ou=people,dc=example,dc=com"
      changetype: "add"
      objectClass: ["inetOrgPerson", "posixAccount"]
      uid: "testuser"
      userPassword:: "e1NTSEF9cGFzc3dvcmQ="   # explicit base64

- name: Use in template
  ansible.builtin.template:
    src: template.ldif.j2
    dest: /tmp/entry.ldif
  vars:
    ldap_entry: "{{ my_dict | dettonville.utils.to_ldif }}"
"""

RETURN = """
  _value:
    description: >-
      LDIF formatted string ready to be written to a file or
      used with ldapmodify.
    type: str
"""


class FilterModule(object):
    def filters(self):
        return {"to_ldif": self.to_ldif}

    @staticmethod
    def to_ldif(entry: Dict[str, Any]) -> str:
        return to_ldif(entry)
