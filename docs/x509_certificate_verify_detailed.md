# Motivational Case for x509_certificate_verify Module

## Overview

The `x509_certificate_verify` module in the `dettonville.utils` collection provides a streamlined way to verify X.509 certificate properties and signatures. It checks attributes such as common name, organization, key algorithm, key size, expiration, and cryptographic signature against an issuer. This module is particularly useful in PKI (Public Key Infrastructure) management playbooks, where validating existing certificates is crucial for deciding whether to regenerate them.

This document contrasts the "before" approach—using multi-task plays with assertions and external modules—against the "after" benefits of the single-module method. It illustrates this with two use cases: validating a root CA certificate and an intermediate CA certificate to determine if regeneration is needed.

## Before: Multi-Task Validation with Assertions

Prior to the `x509_certificate_verify` module, certificate validation often relied on plays like the one in `validate_cert.yml`. This involved multiple tasks using modules from other collections (e.g., `community.crypto.x509_certificate_info` and `community.crypto.openssl_signature_info`) combined with Ansible assertions. Here's an excerpt from `validate_cert.yml`:

```yaml
- name: "Validate certificate properties"
  block:
    - name: "Get properties of existing certificate"
      community.crypto.x509_certificate_info:
        path: "{{ _validate_cert_input.cert_path }}"
      register: __cert_info

    - name: "Assert certificate common name matches configuration"
      ansible.builtin.assert:
        that:
          - __cert_info.subject.commonName | d('') == _validate_cert_input.cert_configs.common_name
        msg: "Certificate common name mismatch. Expected '{{ _validate_cert_input.cert_configs.common_name }}', found '{{ __cert_info.subject.commonName }}'."

    - name: "Set expected key types based on configured algorithm"
      ansible.builtin.set_fact:
        __expected_key_types: >-
          {{ ['ecc', 'ecdsa'] if _validate_cert_input.cert_configs.key_algo | lower == 'ecdsa' else [_validate_cert_input.cert_configs.key_algo | lower] }}

    - name: "Assert certificate key algorithm matches configuration"
      ansible.builtin.assert:
        that:
          - __cert_info.public_key_type | d('') | lower in __expected_key_types
        msg: "Certificate key algorithm mismatch. Expected '{{ _validate_cert_input.cert_configs.key_algo }}', found '{{ __cert_info.public_key_type }}'."

    # Additional assertions for key size, signature, and expiration...
  rescue:
    - name: "A validation failed, set fact to recreate the certificate"
      ansible.builtin.set_fact:
        __create_new_cert: true
```

### Pitfalls of the "Before" Approach
- **Complexity and Verbosity**: Validation requires a block of multiple tasks (e.g., gathering info, setting facts, multiple assertions), making playbooks longer and harder to read/maintain.
- **Error-Prone Assertions**: Custom assertions can lead to inconsistent error messages and handling. Failures might not provide detailed diagnostics, and edge cases (e.g., key algorithm aliases like 'ecdsa' vs. 'ec') need manual workarounds.
- **Dependencies on External Collections**: Relies on `community.crypto` modules, introducing additional dependencies and potential version conflicts.
- **Limited Flexibility**: Handling advanced validations (e.g., signature verification with issuer, proximity to expiration via `checkend`) requires even more custom logic.
- **Performance Overhead**: Multiple module calls increase execution time, especially in large playbooks.
- **Maintenance Burden**: Updating validation logic (e.g., adding new checks) requires modifying the entire play, risking regressions.

This approach was commonly included via `ansible.builtin.include_tasks` in main playbooks, as seen in `create_root_ca.yml` and `openbao_intermediate_ca.yml`, adding indirection and potential for variable scoping issues.

## After: Single-Module Validation

With the `x509_certificate_verify` module, validation consolidates into a single task. It handles all checks internally using the `cryptography` and `pyopenssl` libraries, providing a clear result with details. Here's how it simplifies the process:

### Benefits of the "After" Approach
- **Simplicity**: Reduces a multi-task block to one module call, improving playbook readability.
- **Comprehensive Validation**: Built-in support for common name, organization, OU, key algorithm/size, expiration, checkend threshold, and signature verification—all in one place.
- **Better Error Handling**: Returns structured output with `valid`, `failed`, `msg`, and `details` for easy debugging and conditional logic.
- **No External Collection Dependencies**: Only requires `cryptography` and `pyopenssl` (as specified in the collection's `requirements.txt`), minimizing bloat.
- **Efficiency**: Single execution reduces overhead; idempotent and supports check mode.
- **Easier Maintenance**: Updates to validation logic are centralized in the module, with unit/integration tests ensuring reliability.
- **Flexibility**: Handles PEM/DER formats, optional parameters, and normalizes common mismatches (e.g., 'ecdsa' to 'ec' via playbook facts if needed).

The module's output can directly drive decisions, like setting facts for regeneration, without complex rescues or assertions.

## Use Case Examples

### Use Case 1: Validating Root CA to Determine Regeneration

In `create_root_ca.yml`, the root CA certificate is validated to check if it matches expected properties (e.g., common name, key algo/size) and hasn't expired. If invalid, the playbook backs up and regenerates it using `cfssl`.

**Before (Multi-Task)**:
```yaml
- name: "Validate existing Root CA properties"
  ansible.builtin.include_tasks: validate_cert.yml
  when: __root_ca_pem_stat.stat.exists
  vars:
    _validate_cert_input:
      cert_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"
      cert_configs: "{{ bootstrap_pki__root_ca_configs }}"

- name: "Create or update Root CA"
  when: __create_new_cert | d(True) | bool
  block:
    # Backup and regeneration tasks...
```

**After (Single-Module)**:
```yaml
- name: "Normalize key_algo for Root CA"
  ansible.builtin.set_fact:
    __normalized_key_algo: "{{ bootstrap_pki__root_ca_configs.key_algo | replace('ecdsa', 'ec') }}"

- name: "Validate existing Root CA properties"
  when: __root_ca_pem_stat.stat.exists
  ignore_errors: true
  dettonville.utils.x509_certificate_verify:
    path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"
    common_name: "{{ bootstrap_pki__root_ca_configs.common_name }}"
    organization: "{{ bootstrap_pki__root_ca_configs.organization | d(omit) }}"
    organizational_unit: "{{ bootstrap_pki__root_ca_configs.organizational_unit | d(omit) }}"
    key_algo: "{{ __normalized_key_algo }}"
    key_size: "{{ bootstrap_pki__root_ca_configs.key_size }}"
    validate_expired: true
  register: __cert_verify_result

- name: "Create or update Root CA"
  when: __cert_verify_result.failed | d(True) | bool
  block:
    # Backup and regeneration tasks...
```

This simplifies the playbook while providing detailed results in `__cert_verify_result` for debugging.

### Use Case 2: Validating Intermediate CA to Determine Regeneration

In `openbao_intermediate_ca.yml`, the intermediate CA (managed by OpenBao) is validated against the root issuer, including signature checks, to decide on regeneration and upload to OpenBao.

**Before (Multi-Task)**:
```yaml
- name: "Validate existing Intermediate CA properties"
  ansible.builtin.include_tasks: validate_cert.yml
  when: __intermediate_ca_pem_stat.stat.exists
  vars:
    _validate_cert_input:
      cert_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__openbao_cert_configs.output_basename }}.pem"
      cert_configs: "{{ bootstrap_pki__openbao_cert_configs }}"
      cert_issuer_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"

- name: "Create or update Intermediate CA"
  when: __create_new_cert | d(True) | bool
  block:
    # Backup, generation, signing, and OpenBao upload tasks...
```

**After (Single-Module)**:
```yaml
- name: "Normalize key_algo for Intermediate CA"
  ansible.builtin.set_fact:
    __normalized_key_algo: "{{ bootstrap_pki__openbao_cert_configs.key_algo | replace('ecdsa', 'ec') }}"

- name: "Validate existing Intermediate CA properties"
  when: __intermediate_ca_pem_stat.stat.exists
  ignore_errors: true
  dettonville.utils.x509_certificate_verify:
    path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__openbao_cert_configs.output_basename }}.pem"
    issuer_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"
    common_name: "{{ bootstrap_pki__openbao_cert_configs.common_name }}"
    organization: "{{ bootstrap_pki__openbao_cert_configs.organization | d(omit) }}"
    organizational_unit: "{{ bootstrap_pki__openbao_cert_configs.organizational_unit | d(omit) }}"
    key_algo: "{{ __normalized_key_algo }}"
    key_size: "{{ bootstrap_pki__openbao_cert_configs.key_size }}"
    validate_expired: true
  register: __cert_verify_result

- name: "Create or update Intermediate CA"
  when: __cert_verify_result.failed | d(True) | bool
  block:
    # Backup, generation, signing, and OpenBao upload tasks...
```

The module's `issuer_path` parameter enables direct signature validation, eliminating the need for separate `openssl_signature_info` tasks.

## Conclusion

By adopting `x509_certificate_verify`, playbooks like those in the `dettonville.utils` collection become more concise, reliable, and easier to maintain. This module encapsulates complex logic, reduces dependencies, and provides actionable outputs—ultimately speeding up PKI management workflows. For more details on the module, refer to its [documentation in the collection README](../README.md#included-content).
