## module > from_ldif

Parse LDIF text back into a dictionary

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Parses a single LDIF record and returns a Python dictionary.
- Automatically decodes base64-encoded values (C(::) notation).
- Converts repeated attributes into lists (multi-valued support).
- Handles line folding.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **_input**<br>`str / **required**` |  | LDIF formatted string to be parsed into a dictionary. |

## Examples

```yaml
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
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **_value**<br>`(dict)` | always | Dictionary representing the parsed LDAP entry. |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_v8vnagfk
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.from_ldif | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/from_ldif.md
> FILTER dettonville.utils.from_ldif (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_v8vnagfk/ansible_collections/dettonville/utils/plugins/filter/from_ldif.py)

  Parses a single LDIF record and returns a Python dictionary.
  Automatically decodes base64-encoded values (`::' notation).
  Converts repeated attributes into lists (multi-valued support).
  Handles line folding.

OPTIONS (= indicates it is required):

= _input  LDIF formatted string to be parsed into a dictionary.
        type: str

AUTHOR: Lee Johnson (@lj020326)

NAME: from_ldif

EXAMPLES:
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

RETURN VALUES:

- _value  Dictionary representing the parsed LDAP entry.
        type: dict
```
