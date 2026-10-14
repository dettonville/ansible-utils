## module > redact_sensitive_values

> **Note:** The compiled HTML documentation for this filter is available at: [https://dettonville.github.io/ansible-utils/redact_sensitive_values_filter.html](https://dettonville.github.io/ansible-utils/redact_sensitive_values_filter.html)

Redact sensitive values with specified list of regex patterns from nested dict/array

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Redact values for key(s) with specified list of regex patterns from nested dict/array by replacing them with a redacted tag.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **_input**<br>`any / elements=dictionary / **required**` |  | dictionary or list of dictionaries |
| **additional_key_patterns**<br>`list` |  | List of additional key patterns to use to redact values. |
| **case_sensitive**<br>`bool` | Default: `false` | Enable case-sensitive key matching evaluation. |
| **key_patterns**<br>`list` | Default: `["key", "password", "passwd", "pwd", "secret", "token"]` | List of key patterns to use to redact values. |
| **match_type**<br>`str` | Default: `"boundary"` | Type of key matching algorithm to use ('boundary', 'exact', or 'substring'). |
| **peek**<br>`bool` | Default: `false` | Enable peeking at the first and last N characters of sensitive values. |
| **peek_chars**<br>`int` | Default: `2` | Number of prefix and suffix characters to display when peek is enabled. |

## Examples

```yaml
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
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **_value**<br>`(any)` | always | A dict or list containing the results of redacting the specified key values. |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.3]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_4t1ffy0t
  executable location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.redact_sensitive_values | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/redact_sensitive_values.md
> FILTER dettonville.utils.redact_sensitive_values (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_4t1ffy0t/ansible_collections/dettonville/utils/plugins/filter/redact_sensitive_values.py)

  Redact values for key(s) with specified list of regex patterns from
  nested dict/array by replacing them with a redacted tag.

OPTIONS (= indicates it is required):

= _input  dictionary or list of dictionaries
        elements: dictionary
        type: any

- additional_key_patterns  List of additional key patterns to use to
                            redact values.
        default: null
        type: list

- case_sensitive  Enable case-sensitive key matching evaluation.
        default: false
        type: bool

- key_patterns  List of key patterns to use to redact values.
        default: [key, password, passwd, pwd, secret, token]
        type: list

- match_type  Type of key matching algorithm to use ('boundary',
               'exact', or 'substring').
        default: boundary
        type: str

- peek    Enable peeking at the first and last N characters of
           sensitive values.
        default: false
        type: bool

- peek_chars  Number of prefix and suffix characters to display when
               peek is enabled.
        default: 2
        type: int

AUTHOR: Lee Johnson (@lj020326)

NAME: redact_sensitive_values

POSITIONAL: key_patterns

EXAMPLES:
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

RETURN VALUES:

- _value  A dict or list containing the results of redacting the
           specified key values.
        type: any
```
