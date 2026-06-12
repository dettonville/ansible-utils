# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import base64


DOCUMENTATION = """
  name: to_ldif
  short_description: Convert a dictionary to LDIF format
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Converts a dictionary representing an LDAP entry into a properly formatted, RFC 2849-compliant LDIF record string (with line folding at 76 characters).
    - Converts properly formatted LDIF records back into native Python dictionaries, automatically handling line continuations.
    - Supports multi-valued attributes, automatic base64 encoding for unsafe values, and explicit base64 via C(::) suffix notation.
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
    description: LDIF formatted string ready to be written to a file or used with ldapmodify.
    type: str
"""


DOCUMENTATION_from = """
  name: from_ldif
  short_description: Parse LDIF text back into a dictionary
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Parses a single LDIF record and returns a Python dictionary.
    - Automatically decodes base64-encoded values (C(::) notation).
    - Converts repeated attributes into lists (multi-valued support).
    - Handles line folding.
"""

EXAMPLES_from = """
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

RETURN_from = """
  _value:
    description: Dictionary representing the parsed LDAP entry.
    type: dict
"""


def _fold_line(line, width=76):
    """
    Strict RFC 2849 line folding implementation.
    Folds any line exceeding `width` characters and prepends a single
    space to continuation lines.
    """
    if len(line) <= width:
        return line

    chunks = []
    chunks.append(line[:width])

    remaining = line[width:]
    chunk_size = width - 1

    for i in range(0, len(remaining), chunk_size):
        chunks.append(" " + remaining[i:i + chunk_size])

    return "\n".join(chunks)


def to_ldif(entry):
    """
    Converts a dictionary representing an LDAP entry into an LDIF record string.
    Ensures safe handling of base64-encoded values, list/multi-valued attributes,
    applies RFC 2849 line folding, and returns a clean format terminated by a newline.
    """
    if not isinstance(entry, dict):
        raise ValueError("to_ldif requires a dictionary representing an LDAP entry.")

    ldif_lines = []

    # 1. Enforce order of structural markers for standard parsing
    # dn and changetype must always lead if they exist in the entry map
    ordered_keys = []
    if 'dn' in entry:
        ordered_keys.append('dn')
    if 'changetype' in entry:
        ordered_keys.append('changetype')

    for k in entry.keys():
        if k not in ordered_keys:
            ordered_keys.append(k)

    for key in ordered_keys:
        value = entry[key]
        if value is None:
            continue

        # Normalize values into an iterable list to handle multi-valued keys seamlessly
        if isinstance(value, list):
            values = value
        elif isinstance(value, (set, tuple)):
            values = list(value)
        else:
            values = [value]

        for val in values:
            if val is None:
                continue

            val_str = str(val)

            # Determine if this key explicitly requires double-colon base64 notation
            if key.endswith('::'):
                attr_name = key[:-2].strip()
                b64_val = base64.b64encode(val_str.encode('utf-8')).decode('utf-8')
                line_content = "{0}:: {1}".format(attr_name, b64_val)
            else:
                # Auto-encode unsafe string elements if they contain non-printable or non-ASCII characters
                if any(ord(c) < 32 or ord(c) > 126 for c in val_str) or val_str.startswith((':', ' ')):
                    b64_val = base64.b64encode(val_str.encode('utf-8')).decode('utf-8')
                    line_content = "{0}:: {1}".format(key, b64_val)
                else:
                    line_content = "{0}: {1}".format(key, val_str)

            # Wrap line using RFC-compliant folding rule before extending content blocks
            ldif_lines.append(_fold_line(line_content))

    return "\n".join(ldif_lines) + "\n"


def from_ldif(ldif_str):
    """
    Converts a standard raw string LDIF block record back into a Python dictionary object.
    Handles unfolding of continuous lines starting with leading spaces or tabs gracefully.
    """
    if not isinstance(ldif_str, str):
        raise ValueError("from_ldif requires a string argument representing an LDIF record.")

    entry = {}
    lines = ldif_str.splitlines()
    unfolded_lines = []

    # 1. Unfold lines wrapped by strict line-length limitations (lines starting with a space/tab)
    for line in lines:
        if not line.strip() or line.startswith('#'):
            continue
        if line.startswith(' ') or line.startswith('\t'):
            if unfolded_lines:
                unfolded_lines[-1] += line[1:]
        else:
            unfolded_lines.append(line)

    # 2. Parse attributes out of the unfolded strings
    for line in unfolded_lines:
        if ':' not in line:
            continue

        # Split exactly once at the first colon separator
        key, rest = line.split(':', 1)
        key = key.strip()

        # Check if the remaining part starts with a second colon (indicating base64 encoding)
        if rest.startswith(':'):
            is_base64 = True
            raw_val = rest[1:].strip()
        else:
            is_base64 = False
            raw_val = rest.strip()

        # Handle base64 parsing values safely
        if is_base64:
            try:
                val = base64.b64decode(raw_val.encode('utf-8')).decode('utf-8')
            except Exception as e:
                # Log the issue in a real Ansible filter if possible
                # For now, fallback gracefully
                val = raw_val
                # Optionally: import warnings; warnings.warn(f"Base64 decode failed for {key}: {e}")
        else:
            val = raw_val

        # 3. Assemble and normalize single vs multi-valued properties
        if key in entry:
            if isinstance(entry[key], list):
                entry[key].append(val)
            else:
                entry[key] = [entry[key], val]
        else:
            entry[key] = val

    return entry


class FilterModule(object):
    def filters(self):
        return {
            'to_ldif': to_ldif,
            'from_ldif': from_ldif
        }
