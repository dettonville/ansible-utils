## module > to_ldif

> **Note:** The compiled HTML documentation for this filter is available at: [https://dettonville.github.io/ansible-utils/to_ldif_filter.html](https://dettonville.github.io/ansible-utils/to_ldif_filter.html)

Convert a dictionary to LDIF format

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Converts a dictionary representing an LDAP entry into a properly formatted, RFC 2849-compliant LDIF record string (with line folding at 76 characters).
- Supports multi-valued attributes, automatic base64 encoding for unsafe values, and explicit base64 via C(::) suffix notation.
- Preserves ordering (dn and changetype appear first when present).

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **_input**<br>`dict / **required**` |  | Dictionary containing the LDAP entry attributes. |

## Examples

```yaml
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
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **_value**<br>`(str)` | always | LDIF formatted string ready to be written to a file or used with ldapmodify. |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_5lnnyiz3
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.to_ldif | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/to_ldif.md
> FILTER dettonville.utils.to_ldif (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_5lnnyiz3/ansible_collections/dettonville/utils/plugins/filter/to_ldif.py)

  Converts a dictionary representing an LDAP entry into a properly
  formatted, RFC 2849-compliant LDIF record string (with line folding
  at 76 characters).
  Supports multi-valued attributes, automatic base64 encoding for
  unsafe values, and explicit base64 via `::' suffix notation.
  Preserves ordering (dn and changetype appear first when present).

OPTIONS (= indicates it is required):

= _input  Dictionary containing the LDAP entry attributes.
        type: dict

AUTHOR: Lee Johnson (@lj020326)

NAME: to_ldif

EXAMPLES:
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

RETURN VALUES:

- _value  LDIF formatted string ready to be written to a file or used
           with ldapmodify.
        type: str
```
