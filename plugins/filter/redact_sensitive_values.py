# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    redact_sensitive_values_from_object,
)

__metaclass__ = type

DOCUMENTATION = """
  name: redact_sensitive_values
  short_description: Redact sensitive values with specified list of regex patterns from nested dict/array
  version_added: "2025.12.0"
  author: Lee Johnson (@lj020326)
  description:
    - Redact values for key(s) with specified list of regex patterns from nested dict/array by replacing them with a redacted tag.
  positional: key_patterns
  options:
    _input:
      description: dictionary or list of dictionaries
      type: any
      elements: dictionary
      required: true
    key_patterns:
      description: List of key patterns to use to redact values.
      type: list
      default: ['(?i).*vault.*', '(?i).*token.*', '(?i).*password.*', '(?i).*key.*', '(?i).*ssh.*']
      required: false
    additional_key_patterns:
      description: List of additional key patterns to use to redact values.
      type: list
      required: false
"""

EXAMPLES = """
- name: Redact sensitive values from dictionaries
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values }}"
  vars:
    my_dict:
      administrator-10.21.33.8:
        address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        groups:
          - Administrators
        local_admin_username: administrator
        managed: true
        platform_account_type: platform
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: Windows-Server-Local-Admin
        username: administrator
        password: 39infsVSRk
      administrator-10.31.25.54:
        address: 10.31.25.54
        automatic_management_enabled: true
        domain_type: local
        groups:
          - Administrators
        local_admin_username: administrator
        managed: true
        platform_account_type: platform
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.31.25.54
        platform_notes: WINANSD1S4.example.int
        safe: Windows-Server-Local-Admin
        username: administrator
        password: 39infsVSRk
      careconlocal-10.21.33.8:
        address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: 39infsVSRk
      careconlocal-10.31.25.54:
        address: 10.31.25.54
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.31.25.54
        platform_notes: WINANSD1S4.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: 39infsVSRk
  # Produces the dict:
  #
  #  my_dict:
  #    administrator-10.21.33.8:
  #      address: 10.21.33.8
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      platform_account_type: platform
  #      platform_id: WND-Local-Managed-DMZ
  #      platform_logon_domain: 10.21.33.8
  #      platform_notes: WINANSD1S1.example.int
  #      safe: Windows-Server-Local-Admin
  #      username: administrator
  #      password: <redacted_password>
  #    administrator-10.31.25.54:
  #      address: 10.31.25.54
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      platform_account_type: platform
  #      platform_id: WND-Local-Managed-DMZ
  #      platform_logon_domain: 10.31.25.54
  #      platform_notes: WINANSD1S4.example.int
  #      safe: Windows-Server-Local-Admin
  #      username: administrator
  #      password: <redacted_password>
  #    careconlocal-10.21.33.8:
  #      address: 10.21.33.8
  #      automatic_management_enabled: true
  #      domain_type: local
  #      platform_account_type: recon
  #      platform_id: WND-Local-Managed-DMZ
  #      platform_logon_domain: 10.21.33.8
  #      platform_notes: WINANSD1S1.example.int
  #      safe: A-T-careconlocal
  #      username: careconlocal
  #      password: <redacted_password>
  #    careconlocal-10.31.25.54:
  #      address: 10.31.25.54
  #      automatic_management_enabled: true
  #      domain_type: local
  #      platform_account_type: recon
  #      platform_id: WND-Local-Managed-DMZ
  #      platform_logon_domain: 10.31.25.54
  #      platform_notes: WINANSD1S4.example.int
  #      safe: A-T-careconlocal
  #      username: careconlocal
  #      password: <redacted_password>

- name: Redact sensitive values from list of dictionaries
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.redact_sensitive_values }}"
  vars:
    my_list:
      - address: 10.31.25.54
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.31.25.54
        platform_notes: WINANSD1S4.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: 39infsVSRk
      - address: 10.31.25.54
        automatic_management_enabled: true
        domain_type: local
        groups:
          - Administrators
        local_admin_username: administrator
        managed: true
        platform_account_type: platform
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.31.25.54
        platform_notes: WINANSD1S4.example.int
        safe: Windows-Server-Local-Admin
        username: administrator
        password: 39infsVSRk
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: 39infsVSRk
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        groups:
          - Administrators
        local_admin_username: administrator
        managed: true
        platform_account_type: platform
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: Windows-Server-Local-Admin
        username: administrator
        password: 39infsVSRk
  # Produces the list:
  #
  #  my_list:
  #  - address: 10.31.25.54
  #    automatic_management_enabled: true
  #    domain_type: local
  #    platform_account_type: recon
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.31.25.54
  #    platform_notes: WINANSD1S4.example.int
  #    safe: A-T-careconlocal
  #    username: careconlocal
  #    password: <redacted_password>
  #  - address: 10.31.25.54
  #    automatic_management_enabled: true
  #    domain_type: local
  #    groups:
  #    - Administrators
  #    local_admin_username: administrator
  #    managed: true
  #    platform_account_type: platform
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.31.25.54
  #    platform_notes: WINANSD1S4.example.int
  #    safe: Windows-Server-Local-Admin
  #    username: administrator
  #    password: <redacted_password>
  #  - address: 10.21.33.8
  #    automatic_management_enabled: true
  #    domain_type: local
  #    platform_account_type: recon
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.21.33.8
  #    platform_notes: WINANSD1S1.example.int
  #    safe: A-T-careconlocal
  #    username: careconlocal
  #    password: <redacted_password>
  #  - address: 10.21.33.8
  #    automatic_management_enabled: true
  #    domain_type: local
  #    groups:
  #    - Administrators
  #    local_admin_username: administrator
  #    managed: true
  #    platform_account_type: platform
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.21.33.8
  #    platform_notes: WINANSD1S1.example.int
  #    safe: Windows-Server-Local-Admin
  #    username: administrator
  #    password: <redacted_password>
  #
"""

RETURN = """
  _value:
    description: A dict or list containing the results of redacting the specified key values.
    type: any
"""

_SENSITIVE_KEYS_DEFAULT: list = [
    "(?i).*vault.*",
    "(?i).*token.*",
    "(?i).*password.*",
    "(?i).*key.*",
    "(?i).*ssh.*",
]


class FilterModule(object):
    def filters(self):
        return {"redact_sensitive_values": self.redact_sensitive_values}

    @staticmethod
    def redact_sensitive_values(
        input_object: any,
        key_patterns: list = None,
        additional_key_patterns: list = None,
        log_level: str = "INFO",
    ) -> any:
        if key_patterns is None:
            key_patterns = []

        if additional_key_patterns is None:
            additional_key_patterns = []

        if not key_patterns:
            key_patterns = _SENSITIVE_KEYS_DEFAULT

        if additional_key_patterns:
            key_patterns.extend(additional_key_patterns)

        redact_sensitive_values_from_object(input_object, key_patterns, log_level)
        return input_object
