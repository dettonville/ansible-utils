# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

from typing import Any

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    redact_sensitive_values_from_object,
)

__metaclass__ = type

DOCUMENTATION = """
  name: redact_sensitive_values
  short_description: >-
    Redact sensitive values with specified list of regex patterns from nested
    dict/array
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - >-
      Redact values for key(s) with specified list of regex patterns from
      nested dict/array by replacing them with a redacted tag.
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
      default:
        - key
        - password
        - passwd
        - pwd
        - secret
        - token
      required: false
    additional_key_patterns:
      description: List of additional key patterns to use to redact values.
      type: list
      required: false
    match_type:
      description: >-
        Type of key matching algorithm to use ('boundary', 'exact',
        or 'substring').
      type: str
      default: boundary
      required: false
    case_sensitive:
      description: Enable case-sensitive key matching evaluation.
      type: bool
      default: false
      required: false
    peek:
      description: >-
        Enable peeking at the first and last N characters of sensitive values.
      type: bool
      default: false
      required: false
    peek_chars:
      description: >-
        Number of prefix and suffix characters to display when peek is enabled.
      type: int
      default: 2
      required: false
"""

EXAMPLES = """
- name: >-
    Redact sensitive values from dictionaries using default boundary matching
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values }}"
  vars:
    my_dict:
      api_key: "secret-token-123"
      keycloak_user: "admin"
  # Produces:
  #  my_dict:
  #    api_key: "<redacted>"
  #    keycloak_user: "admin"

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
        password: passw0rd
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
        password: passw0rd

- name: Redact sensitive values using exact match type
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values(
        key_patterns=['password'], match_type='exact') }}"
  vars:
    my_dict:
      password: "SuperSecretPassword123!"
      user_password: "not_matched_with_exact"

- name: Redact sensitive values using case-sensitive matching
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values(
        key_patterns=['Password'], case_sensitive=True) }}"
  vars:
    my_dict:
      Password: "SecretValue"
      password: "LeftAlone"

- name: Redact sensitive values using custom regular expression patterns
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values(
        key_patterns=[r'.*secret.*']) }}"
  vars:
    my_dict:
      db_secret_key: "value123"
      public_info: "visible"
"""

RETURN = """
  _value:
    description: >-
        A dict or list containing the results of redacting the specified
        key values.
    type: any
"""

_SENSITIVE_KEYS_DEFAULT: list = [
    "key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
]


class FilterModule(object):
    def filters(self):
        return {"redact_sensitive_values": self.redact_sensitive_values}

    @staticmethod
    def redact_sensitive_values(
        input_object: Any,
        key_patterns: list = None,
        additional_key_patterns: list = None,
        match_type: str = "boundary",
        case_sensitive: bool = False,
        peek: bool = False,
        peek_chars: int = 2,
        log_level: str = "INFO",
    ) -> Any:
        if key_patterns is None:
            key_patterns = []

        if additional_key_patterns is None:
            additional_key_patterns = []

        if not key_patterns:
            key_patterns = _SENSITIVE_KEYS_DEFAULT

        if additional_key_patterns:
            key_patterns.extend(additional_key_patterns)

        redact_sensitive_values_from_object(
            input_object,
            key_patterns,
            log_level,
            match_type=match_type,
            case_sensitive=case_sensitive,
            peek=peek,
            peek_chars=peek_chars,
        )
        return input_object
