# Motivational Case for x509_certificate_verify Module

## Overview

The `x509_certificate_verify` module in the `dettonville.utils` collection provides a streamlined way to verify X.509 certificate properties and signatures. It checks attributes such as common name, organization, key algorithm, key size, expiration, and cryptographic signature against an issuer. This module is particularly useful in PKI (Public Key Infrastructure) management playbooks, where validating existing certificates is crucial for deciding whether to regenerate them.

This document contrasts the "before" approach—using multi-task plays with assertions and external modules—against the "after" benefits of the single-module method. It illustrates this with two use cases: validating a root CA certificate and an intermediate CA certificate to determine if regeneration is needed.

## Before: Multi-Task Validation with Assertions

Prior to the `x509_certificate_verify` module, certificate validation often relied on plays like the one in the following `validate_cert.yml`. This involved multiple tasks using modules from other collections (e.g., `community.crypto.x509_certificate_info` and `community.crypto.openssl_signature_info`) combined with Ansible assertions. Here's an excerpt from `validate_cert.yml`:

validate_cert.yml:
```yaml
---
## cert_configs dictionary expected for validation
##   cert_configs:
##     cert_path:
##     common_name:
##     cert_type:
##     issuer_common_name:
##     issuer_cert_chain_path:
##     key_type:
##     key_type
##     key_size
- name: "Display cert_configs"
  ansible.builtin.debug:
    var: cert_configs

- name: "Initialize certificate validation results"
  ansible.builtin.set_fact:
    __cert_validation_results:
      failed: false
      exceptions: []
      missing_cert: false
      missing_key: false
      expiration_check_failed: false
      info_check_failed: false
      signature_check_failed: false

- name: "Validate certificate info for {{ cert_configs.cert_path }}"
  ansible.builtin.debug:
    msg: "Perform validations for {{ cert_configs.cert_path }}"

- name: "Check if certificate file exists"
  ansible.builtin.stat:
    path: "{{ cert_configs.cert_path }}"
  register: __cert_file_stat

- name: "Check if private key file exists"
  ansible.builtin.stat:
    path: "{{ __key_file_path }}"
  register: __key_file_stat

# 1) Check for CA cert existence
- name: "Set validation failed if certificate is missing"
  when: not __cert_file_stat.stat.exists
  ansible.builtin.set_fact:
    __cert_validation_results: "{{ __cert_validation_results | d({})
      | combine({'failed': true,
        'missing_cert': true,
        'exceptions': (__cert_validation_results.exceptions | d([]))
          + ['cert file ' + cert_configs.cert_path + ' does not exist']}) }}"

# 2) Check for CA key existence
- name: "Set validation failed if key is missing"
  when: not __key_file_stat.stat.exists
  ansible.builtin.set_fact:
    __cert_validation_results: "{{ __cert_validation_results | d({})
      | combine({'failed': true,
        'missing_key': true,
        'exceptions': (__cert_validation_results.exceptions | d([]))
          + ['key file ' + __key_file_path + ' does not exist']}) }}"

- name: "Display __cert_validation_results #1/2"
  ansible.builtin.debug:
    var: __cert_validation_results

# 3) Check if certificate expiration within defined threshold
- name: "Check certificate expiration date for {{ cert_configs.common_name }}"
  when:
    - __cert_file_stat.stat.exists | d(False)
    - not __cert_validation_results.failed
  block:
    - name: "Run openssl checkend command"
      changed_when: false
      failed_when: false
      ansible.builtin.command: >
        openssl x509 -checkend {{ ca_cert_expiration_panic_threshold }}
          -noout -in {{ cert_configs.cert_path }}
      register: __cert_validity_exp_date_check_result

    - name: "Display __cert_validity_exp_date_check_result"
      ansible.builtin.debug:
        var: __cert_validity_exp_date_check_result

    - name: "Set expiration check result"
      when: __cert_validity_exp_date_check_result.failed | d(True)
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'expiration_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + ['certificate expires soon (within panic threshold)']}) }}"

    - name: "Display __cert_validation_results #3"
      ansible.builtin.debug:
        var: __cert_validation_results

# 4) Check if CA cert info is valid (using community.crypto.x509_certificate_info)
# Ensure community.crypto collection is installed: ansible-galaxy collection install community.crypto
- name: "Get certificate info for {{ cert_configs.common_name }}"
  when:
    - __cert_file_stat.stat.exists | d(False)
    - not __cert_validation_results.failed
  community.crypto.x509_certificate_info:
    path: "{{ cert_configs.cert_path }}"
  register: cacert_result
  ignore_errors: true

- name: "Display cacert_result (debug)"
  when: display_cacert_result | bool
  ansible.builtin.debug:
    var: cacert_result

- name: "Assert cert info is valid and not expired"
  when:
    - not cacert_result.failed | d(True)
    - not cacert_result.skipped | d(False)
    - not __cert_validation_results.failed
  block:

    - name: "Assert certificate subject common name matches expected"
      ansible.builtin.assert:
        that:
          - cacert_result.subject.commonName == cert_configs.common_name
        fail_msg: "Certificate subject common name mismatch: Expected '{{
          cert_configs.common_name }}', Got '{{ cacert_result.subject.commonName }}'"
        quiet: true
      register: __assert_subject_cn
      ignore_errors: true

    - name: "Set __cert_validation_results.failed if subject CN mismatch"
      when: __assert_subject_cn.failed | d(False) | bool
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'info_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + [__assert_subject_cn.msg]}) }}"

    - name: "Assert certificate not expired"
      ansible.builtin.assert:
        that: not cacert_result.expired
        fail_msg: "Certificate '{{ cert_configs.common_name }}' is expired according to x509_certificate_info."
        quiet: true
      register: __assert_expired
      ignore_errors: true

    - name: "Set __cert_validation_results.failed if certificate is expired"
      when: __assert_expired.failed | d(False) | bool
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'info_check_failed': true,
            'expiration_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + [__assert_expired.msg]}) }}"

    # Note: Checking issuer details requires knowing the expected issuer based on signerName.
    # This example asserts if it's not a root CA and a signer is specified.
    - name: "Assert certificate issuer common name matches signer (if not root)"
      when:
        - cert_configs.cert_type != "root"
        - cert_configs.issuer_common_name is defined and cert_configs.issuer_common_name | d('') | length > 0
      ansible.builtin.assert:
        that:
          - cacert_result.issuer.commonName == cert_configs.issuer_common_name
        fail_msg: "Certificate issuer common name mismatch: Expected '{{
          cert_configs.issuer_common_name }}', Got '{{ cacert_result.issuer.commonName }}'"
        quiet: true
      register: __assert_issuer_cn
      ignore_errors: true

    - name: "Set __cert_validation_results.failed if issuer CN mismatch"
      when: __assert_issuer_cn.failed | d(False) | bool
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'info_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + [__assert_issuer_cn.msg]}) }}"

    - name: "Assert certificate key_type matches expected"
      ansible.builtin.assert:
        that:
          - cacert_result.public_key_type|lower == cert_configs.key_type|lower
        fail_msg: "Certificate key type mismatch: Expected '{{
          cert_configs.key_type }}', Got '{{ cacert_result.public_key_type }}'"
        quiet: true
      register: __assert_key_type
      ignore_errors: true

    - name: "Set __cert_validation_results.failed if key_size mismatch"
      when: __assert_key_type.failed | d(False) | bool
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'info_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + [__assert_key_type.msg]}) }}"

    - name: "Assert certificate key_type matches expected"
      ansible.builtin.assert:
        that:
          - cacert_result.public_key_data.size == cert_configs.key_size
        fail_msg: "Certificate key size mismatch: Expected '{{
          cert_configs.key_size }}', Got '{{ cacert_result.public_key_data.size }}'"
        quiet: true
      register: __assert_key_type
      ignore_errors: true

    - name: "Set __cert_validation_results.failed if key_type mismatch"
      when: __assert_key_type.failed | d(False) | bool
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'info_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + [__assert_key_type.msg]}) }}"

    - name: "Display __cert_validation_results #4"
      ansible.builtin.debug:
        var: __cert_validation_results

- name: "Display __cert_validation_results"
  ansible.builtin.debug:
    var: __cert_validation_results

# 5) Check if CA cert signature is valid
- name: "Check if CA cert signature is valid for {{
    cert_configs.common_name }}"
  when:
    - cert_configs.cert_type | d('') != "root"
    - __cert_file_stat.stat.exists | d(False)
    - cert_configs.issuer_cert_chain_path | d('') | length > 0
    - not __cert_validation_results.failed
  block:
    - name: "Validate signed by ca signer certs using openssl verify"
      changed_when: false
      failed_when: false
      ansible.builtin.command: >
        openssl verify -CAfile
        {{ cert_configs.issuer_cert_chain_path }}
        {{ cert_configs.cert_path }}
      register: __cert_validity_signer

    - name: "Display __cert_validity_signer (debug)"
      ansible.builtin.debug:
        var: __cert_validity_signer

    - name: "Set signature check result"
      when: __cert_validity_signer.failed
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true,
            'signature_check_failed': true,
            'exceptions': (__cert_validation_results.exceptions | d([]))
              + ['invalid certificate signature']}) }}"

  # Ensure __cert_validation_results.signature_check_failed is explicitly set to true if block is skipped due to missing cert_configs.issuer_cert_chain_path
  always:
    - name: "Set signature_check_failed to true if conditions not met for signature validation"
      when:
        - cert_configs.cert_type | d('') != "root"
        - (not __cert_file_stat.stat.exists | d(False) or cert_configs.issuer_cert_chain_path | d('') | length == 0)
      ansible.builtin.set_fact:
        __cert_validation_results: "{{ __cert_validation_results | d({})
          | combine({'failed': true, 'signature_check_failed': true}) }}"

# Final determination if certificate needs to be created/recreated
- name: "Set __create_new_cert"
  ansible.builtin.set_fact:
    __create_new_cert: __cert_validation_results.failed

- name: "Display final __missing_or_invalid_cert status"
  ansible.builtin.debug:
    msg: "Final status for '{{ cert_configs.common_name
      }}' - Needs creation/recreation: {{ __create_new_cert }} (Reasons: {{
      __cert_validation_results.exceptions | join(', ') }})"

```

### Pitfalls of the "Before" Approach
- **Complexity and Verbosity**: Validation requires a block of multiple tasks (e.g., gathering info, setting facts, multiple assertions), making playbooks longer and harder to read/maintain.
- **Error-Prone Assertions**: Custom assertions can lead to inconsistent error messages and handling. Failures might not provide detailed diagnostics, and edge cases (e.g., key algorithm aliases like 'ecdsa' vs. 'ec') need manual workarounds.
- **Dependencies on External Collections**: Relies on `community.crypto` modules, introducing additional dependencies and potential version conflicts.
- **Limited Flexibility**: Handling advanced validations (e.g., signature verification with issuer, proximity to expiration via `checkend`) requires even more custom logic.
- **Performance Overhead**: Multiple module calls increase execution time, especially in large playbooks.
- **Maintenance Burden**: Updating validation logic (e.g., adding new checks) requires modifying the entire play, risking regressions.

This approach was commonly included via `ansible.builtin.include_tasks` in main playbooks adding indirection and potential for variable scoping issues.

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
  when: __root_ca_pem_stat.stat.exists
  ansible.builtin.include_tasks: validate_cert.yml
  vars:
    cert_configs: "{{ bootstrap_pki__root_ca_configs }}"

- name: "Create or update Root CA"
  when: __create_new_cert | d(True) | bool
  block:
    # Backup and regeneration tasks...
```

**After (Single-Module)**:
```yaml
- name: "Normalize key_type for Root CA"
  ## since the "key_type" is specified for cfssl implementation/usage -> convert/normalize to openssl format for openssl validations
  ansible.builtin.set_fact:
    __openssl_key_type: "{{ bootstrap_pki__root_ca_configs.key_type | replace('ecdsa', 'ec') }}"

- name: "Validate existing Root CA properties"
  when: __root_ca_pem_stat.stat.exists
  dettonville.utils.x509_certificate_verify:
    path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"
    common_name: "{{ bootstrap_pki__root_ca_configs.common_name }}"
    organization: "{{ bootstrap_pki__root_ca_configs.organization | d(omit) }}"
    organizational_unit: "{{ bootstrap_pki__root_ca_configs.organizational_unit | d(omit) }}"
    key_type: "{{ __openssl_key_type }}"
    key_size: "{{ bootstrap_pki__root_ca_configs.key_size }}"
    validate_expired: true
  register: __cert_verify_result

- name: "Create or update Root CA"
  when: __cert_verify_result.verify_failed | d(True) | bool
  block:
    # Backup and regeneration tasks...
```

This simplifies the playbook while providing detailed results in `__cert_verify_result` for debugging.

### Use Case 2: Validating Intermediate CA to Determine Regeneration

In `vault_intermediate_ca.yml`, the intermediate CA (managed by Vault/Openbao) is validated against the root issuer, including signature checks, to decide on regeneration and upload to Vault/Openbao.

**Before (Multi-Task)**:
```yaml
- name: "Validate existing Intermediate CA properties"
  ansible.builtin.include_tasks: validate_cert.yml
  when: __intermediate_ca_pem_stat.stat.exists
  vars:
    _validate_cert_input:
      cert_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__vault_cert_configs.output_basename }}.pem"
      cert_configs: "{{ bootstrap_pki__vault_cert_configs }}"
      cert_issuer_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"

- name: "Create or update Intermediate CA"
  when: __create_new_cert | d(True) | bool
  block:
    # Backup, generation, signing, and Vault/Openbao upload tasks...
```

**After (Single-Module)**:
```yaml
- name: "Normalize key_type for Intermediate CA"
  ansible.builtin.set_fact:
    __openssl_key_type: "{{ bootstrap_pki__vault_cert_configs.key_type | replace('ecdsa', 'ec') }}"

- name: "Validate existing Intermediate CA properties"
  when: __intermediate_ca_pem_stat.stat.exists
  dettonville.utils.x509_certificate_verify:
    path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__vault_cert_configs.output_basename }}.pem"
    issuer_path: "{{ bootstrap_pki__pki_ca_dir }}/{{ bootstrap_pki__root_ca_configs.output_basename }}.pem"
    common_name: "{{ bootstrap_pki__vault_cert_configs.common_name }}"
    organization: "{{ bootstrap_pki__vault_cert_configs.organization | d(omit) }}"
    organizational_unit: "{{ bootstrap_pki__vault_cert_configs.organizational_unit | d(omit) }}"
    key_type: "{{ __openssl_key_type }}"
    key_size: "{{ bootstrap_pki__vault_cert_configs.key_size }}"
    validate_expired: true
  register: __cert_verify_result

- name: "Create or update Intermediate CA"
  when: __cert_verify_result.verify_failed | d(True) | bool
  block:
    # Backup, generation, signing, and Vault/Openbao upload tasks...
```

The module's `issuer_path` parameter enables direct signature validation, eliminating the need for separate `openssl_signature_info` tasks.

## Conclusion

By adopting `x509_certificate_verify`, playbooks like those in the `dettonville.utils` collection become more concise, reliable, and easier to maintain. This module encapsulates complex logic, reduces dependencies, and provides actionable outputs—ultimately speeding up PKI management workflows. For more details on the module, refer to its [documentation in the collection README](../README.md#included-content).
