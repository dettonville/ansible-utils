#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Lee Johnson (@lj020326)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: debug_sanitized
short_description: >-
  Print sanitized debug statements with
  automated regex redactions
version_added: "2.20.0"
author: Lee Johnson (@lj020326)
description:
  - Extends the core behavior of the standard
    C(ansible.builtin.debug) module by applying
    automated sanitization filters prior to rendering.
  - Intercepts output keys matching predefined safety
    patterns and redacts their parameters locally on
    the control node.
options:
  msg:
    description: >-
      A customized string message to print out.
      Mutually exclusive with the C(var) option.
    type: str
    default: "Hello world!"
  var:
    description: >-
      A variable name string or complex data structure
      to evaluate and print out. Mutually exclusive
      with the C(msg) option.
    type: raw
  verbosity:
    description: >-
      A number that controls when the debug module
      will run based on the defined verbosity level
      configurations.
    type: int
    default: 0
  key_patterns:
    description: >-
      List of regular expressions used to identify
      and redact sensitive keys.
    type: list
    elements: str
    default:
      - '(?i).*vault.*'
      - '(?i).*token.*'
      - '(?i).*password.*'
      - '(?i).*key.*'
      - '(?i).*ssh.*'
  additional_key_patterns:
    description: >-
      Additional collection of regular expressions
      to append to the default evaluation arrays.
    type: list
    elements: str
"""

EXAMPLES = """
- name: >-
    Only display this sanitized payload when
    running with -vv or higher
  dettonville.utils.debug_sanitized:
    var: sensitive_service_payload
    verbosity: 2

- name: >-
    Print a sanitized message block containing
    text strings
  dettonville.utils.debug_sanitized:
    msg: >-
      System connection established with
      password hidden inside payload

- name: >-
    Render an entire complex dictionary with
    keys securely hidden
  dettonville.utils.debug_sanitized:
    var: my_database_connection_dict
  vars:
    my_database_connection_dict:
      host: "db.johnson.int"
      username: "admin"
      password: "SuperSecretPassword123!"
      api_key: "am49gnsk301nasd"

- name: >-
    Apply additional custom pattern match
    fields to the debug output
  dettonville.utils.debug_sanitized:
    var: dynamic_inventory_payload
    additional_key_patterns:
      - '(?i).*secret.*'
      - '(?i).*credit.*'
"""

RETURN = """
msg:
  description: >-
    The sanitized string output message when
    using the msg option.
  type: str
  returned: always
var:
  description: >-
    The sanitized dictionary object block
    structure when using the var option.
  type: raw
  returned: when var is specified
failed:
  description: >-
    Tracking status flag checking execution
    runtime issues.
  type: bool
  returned: always
"""

# noinspection PyPackageRequirements
from ansible.module_utils.basic import AnsibleModule


def main():
    default_patterns = [
        '(?i).*vault.*',
        '(?i).*token.*',
        '(?i).*password.*',
        '(?i).*key.*',
        '(?i).*ssh.*',
    ]

    module = AnsibleModule(
        argument_spec=dict(
            msg=dict(type='str', default='Hello world!'),
            var=dict(type='raw'),
            verbosity=dict(type='int', default=0),
            key_patterns=dict(
                type='list',
                elements='str',
                default=default_patterns,
                no_log=True,
            ),
            additional_key_patterns=dict(
                type='list', elements='str', no_log=True
            ),
        ),
        mutually_exclusive=[['msg', 'var']],
        supports_check_mode=True,
    )

    module.exit_json(
        changed=False,
        msg="Bypassed by action plugin framework.",
    )


if __name__ == '__main__':
    main()
