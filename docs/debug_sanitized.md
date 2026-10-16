## module > debug_sanitized

> **Note:** The compiled HTML documentation for this module is available at: [https://dettonville.github.io/ansible-utils/debug_sanitized_module.html](https://dettonville.github.io/ansible-utils/debug_sanitized_module.html)

Print sanitized debug statements with automated regex redactions

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Extends the core behavior of the standard C(ansible.builtin.debug) module by applying automated sanitization filters prior to rendering.
- Intercepts output keys matching predefined safety patterns and redacts their parameters locally on the control node.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **additional_key_patterns**<br>`list / elements=str` |  | Additional collection of regular expressions to append to the default evaluation arrays. |
| **case_sensitive**<br>`bool` | Default: `false` | Enable case-sensitive key matching evaluation. |
| **key_patterns**<br>`list / elements=str` | Default: `["(?i).*vault.*", "(?i).*token.*", "(?i).*password.*", "(?i).*key.*", "(?i).*ssh.*"]` | List of regular expressions used to identify and redact sensitive keys. |
| **match_type**<br>`str` | Default: `"boundary"`<br>Choices:<br>&bull; `boundary`<br>&bull; `exact`<br>&bull; `substring` | Type of key matching algorithm to use ('boundary', 'exact', or 'substring'). |
| **msg**<br>`str` | Default: `"Hello world!"` | A customized string message to print out. Mutually exclusive with the C(var) option. |
| **var**<br>`raw` |  | A variable name string or complex data structure to evaluate and print out. Mutually exclusive with the C(msg) option. |
| **verbosity**<br>`int` | Default: `0` | A number that controls when the debug module will run based on the defined verbosity level configurations. |

## Examples

```yaml
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

- name: Print sanitized debug with exact match type and case sensitivity
  dettonville.utils.debug_sanitized:
    var: secure_payload
    match_type: "exact"
    case_sensitive: true
  vars:
    secure_payload:
      SecretKey: "RedactedValue"
      secretkey: "NotRedacted"
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **failed**<br>`(bool)` | always | Tracking status flag checking execution runtime issues. |
| **msg**<br>`(str)` | always | The sanitized string output message when using the msg option. |
| **var**<br>`(raw)` | when var is specified | The sanitized dictionary object block structure when using the var option. |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.3]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_ty1_f29j
  executable location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.debug_sanitized | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/debug_sanitized.md
> MODULE dettonville.utils.debug_sanitized (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_ty1_f29j/ansible_collections/dettonville/utils/plugins/modules/debug_sanitized.py)

  Extends the core behavior of the standard `ansible.builtin.debug'
  module by applying automated sanitization filters prior to
  rendering.
  Intercepts output keys matching predefined safety patterns and
  redacts their parameters locally on the control node.

  * note: This module has a corresponding action plugin.

OPTIONS (= indicates it is required):

- additional_key_patterns  Additional collection of regular
                            expressions to append to the default
                            evaluation arrays.
        default: null
        elements: str
        type: list

- case_sensitive  Enable case-sensitive key matching evaluation.
        default: false
        type: bool

- key_patterns  List of regular expressions used to identify and
                 redact sensitive keys.
        default: ['(?i).*vault.*', '(?i).*token.*', '(?i).*password.*', '(?i).*key.*', '(?i).*ssh.*']
        elements: str
        type: list

- match_type  Type of key matching algorithm to use ('boundary',
               'exact', or 'substring').
        choices: [boundary, exact, substring]
        default: boundary
        type: str

- msg     A customized string message to print out. Mutually
           exclusive with the `var' option.
        default: Hello world!
        type: str

- var     A variable name string or complex data structure to
           evaluate and print out. Mutually exclusive with the `msg'
           option.
        default: null
        type: raw

- verbosity  A number that controls when the debug module will run
              based on the defined verbosity level configurations.
        default: 0
        type: int

AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
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

- name: Print sanitized debug with exact match type and case sensitivity
  dettonville.utils.debug_sanitized:
    var: secure_payload
    match_type: "exact"
    case_sensitive: true
  vars:
    secure_payload:
      SecretKey: "RedactedValue"
      secretkey: "NotRedacted"

RETURN VALUES:

- failed  Tracking status flag checking execution runtime issues.
        returned: always
        type: bool

- msg     The sanitized string output message when using the msg
           option.
        returned: always
        type: str

- var     The sanitized dictionary object block structure when using
           the var option.
        returned: when var is specified
        type: raw
```
