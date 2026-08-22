## module > remove_dict_keys

Remove key(s) with specified list of regex patterns from nested dict/array

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Remove key(s) with specified list of regex patterns from nested dict/array.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **_input**<br>`any / elements=dictionary / **required**` |  | dictionary or list of dictionaries |
| **key_patterns**<br>`list / **required**` |  | List of key patterns to use to remove keys. |

## Examples

```yaml
- name: >-
    Remove keys from list of dictionaries based on a single specified key
    to be removed
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_dict_keys('foo') }}"
  vars:
    my_list:
      - name: value
        foo: bar
      - name: other_value
        baz: bar
  # Produces the derived list of dicts with keys removed:
  #
  #  my_list:
  #    - name: other_value
  #    - name: value
  #      baz: bar

- name: Remove multiple keys from dictionary
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_dict_keys(key_patterns) }}"
  vars:
    key_patterns:
      - platform.*
      - address
      - username
    my_dict:
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
  # Produces the dictionary:
  #
  #  my_dict:
  #    administrator-10.21.33.8:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      safe: Windows-Server-Local-Admin
  #    administrator-10.31.25.54:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      safe: Windows-Server-Local-Admin
  #    careconlocal-10.21.33.8:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      safe: A-T-careconlocal
  #    careconlocal-10.31.25.54:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      safe: A-T-careconlocal

- name: Produce a list of dictionaries based on multiple keys to be removed
  ansible.builtin.debug:
    msg: "{{ my_list| dettonville.utils.remove_dict_keys(
        ['platform_id','address','username']) }}"
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
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
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
  # Produces the sorted list:
  #
  #  my_list:
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: Windows-Server-Local-Admin
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: A-T-careconlocal
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: Windows-Server-Local-Admin
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: A-T-careconlocal
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **_value**<br>`(any)` | always | A dict or list containing the results of removing the specified key patterns. |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_cowvjbd9
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.remove_dict_keys | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/remove_dict_keys.md
> FILTER dettonville.utils.remove_dict_keys (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_cowvjbd9/ansible_collections/dettonville/utils/plugins/filter/remove_dict_keys.py)

  Remove key(s) with specified list of regex patterns from nested
  dict/array.

OPTIONS (= indicates it is required):

= _input  dictionary or list of dictionaries
        elements: dictionary
        type: any

= key_patterns  List of key patterns to use to remove keys.
        type: list

AUTHOR: Lee Johnson (@lj020326)

NAME: remove_dict_keys

POSITIONAL: key_patterns

EXAMPLES:
- name: >-
    Remove keys from list of dictionaries based on a single specified key
    to be removed
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_dict_keys('foo') }}"
  vars:
    my_list:
      - name: value
        foo: bar
      - name: other_value
        baz: bar
  # Produces the derived list of dicts with keys removed:
  #
  #  my_list:
  #    - name: other_value
  #    - name: value
  #      baz: bar

- name: Remove multiple keys from dictionary
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_dict_keys(key_patterns) }}"
  vars:
    key_patterns:
      - platform.*
      - address
      - username
    my_dict:
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
  # Produces the dictionary:
  #
  #  my_dict:
  #    administrator-10.21.33.8:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      safe: Windows-Server-Local-Admin
  #    administrator-10.31.25.54:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      groups:
  #      - Administrators
  #      local_admin_username: administrator
  #      managed: true
  #      safe: Windows-Server-Local-Admin
  #    careconlocal-10.21.33.8:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      safe: A-T-careconlocal
  #    careconlocal-10.31.25.54:
  #      automatic_management_enabled: true
  #      domain_type: local
  #      safe: A-T-careconlocal

- name: Produce a list of dictionaries based on multiple keys to be removed
  ansible.builtin.debug:
    msg: "{{ my_list| dettonville.utils.remove_dict_keys(
        ['platform_id','address','username']) }}"
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
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
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
  # Produces the sorted list:
  #
  #  my_list:
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: Windows-Server-Local-Admin
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: A-T-careconlocal
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: Windows-Server-Local-Admin
  #   - automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: A-T-careconlocal

RETURN VALUES:

- _value  A dict or list containing the results of removing the
           specified key patterns.
        type: any
```
