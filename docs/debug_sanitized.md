

```shell
$ ansible --version
ansible [core 2.20.1]
  config file = None
  configured module search path = [/Users/ljohnson/.ansible/plugins/modules, /usr/share/ansible/plugins/modules]
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /Users/ljohnson/.ansible/collections:/usr/share/ansible/collections
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.2 (with libyaml v0.2.5)
$
$ REPO_DIR="$( git rev-parse --show-toplevel )"
$ cd ${REPO_DIR}
$
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.debug_sanitized | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/debug_sanitized.md
> MODULE dettonville.utils.debug_sanitized (/Users/ljohnson/tmp/_waNGu4/ansible_collections/dettonville/utils/plugins/modules/debug_sanitized.py)

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

- key_patterns  List of regular expressions used to identify and
                 redact sensitive keys.
        default: ['(?i).*vault.*', '(?i).*token.*', '(?i).*password.*', '(?i).*key.*', '(?i).*ssh.*']
        elements: str
        type: list

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
- name: Only display this sanitized payload when running with -vv or higher
  dettonville.utils.debug_sanitized:
    var: sensitive_service_payload
    verbosity: 2

- name: Print a sanitized message block containing text strings
  dettonville.utils.debug_sanitized:
    msg: "System connection established with password hidden inside payload"

- name: Render an entire complex dictionary with keys securely hidden
  dettonville.utils.debug_sanitized:
    var: my_database_connection_dict
  vars:
    my_database_connection_dict:
      host: "db.johnson.int"
      username: "admin"
      password: "SuperSecretPassword123!"
      api_key: "am49gnsk301nasd"

- name: Apply additional custom pattern match fields to the debug output
  dettonville.utils.debug_sanitized:
    var: dynamic_inventory_payload
    additional_key_patterns:
      - '(?i).*secret.*'
      - '(?i).*credit.*'

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
