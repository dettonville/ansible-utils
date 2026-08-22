## module > remove_sensitive_keys

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
| **additional_key_patterns**<br>`list` |  | List of additional key patterns to use to remove keys. |
| **key_patterns**<br>`list` | Default: `["(?i).*vault.*", "(?i).*token.*", "(?i).*password.*", "(?i).*key.*", "(?i).*ssh.*"]` | List of key patterns to use to remove keys. |

## Examples

```yaml
- name: Remove sensitive keys from dictionaries
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.remove_sensitive_keys }}"
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
        password: passw0rd
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
        password: passw0rd
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
        password: passw0rd
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
        password: passw0rd
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

- name: Remove sensitive keys from list of dictionaries
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_sensitive_keys }}"
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
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: passw0rd
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
        password: passw0rd
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
  #  - address: 10.21.33.8
  #    automatic_management_enabled: true
  #    domain_type: local
  #    platform_account_type: recon
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.21.33.8
  #    platform_notes: WINANSD1S1.example.int
  #    safe: A-T-careconlocal
  #    username: careconlocal
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
  #
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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.remove_sensitive_keys | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/remove_sensitive_keys.md
> FILTER dettonville.utils.remove_sensitive_keys (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_cowvjbd9/ansible_collections/dettonville/utils/plugins/filter/remove_sensitive_keys.py)

  Remove key(s) with specified list of regex patterns from nested
  dict/array.

OPTIONS (= indicates it is required):

= _input  dictionary or list of dictionaries
        elements: dictionary
        type: any

- additional_key_patterns  List of additional key patterns to use to
                            remove keys.
        default: null
        type: list

- key_patterns  List of key patterns to use to remove keys.
        default: ['(?i).*vault.*', '(?i).*token.*', '(?i).*password.*', '(?i).*key.*', '(?i).*ssh.*']
        type: list

AUTHOR: Lee Johnson (@lj020326)

NAME: remove_sensitive_keys

POSITIONAL: key_patterns

EXAMPLES:
- name: Remove sensitive keys from dictionaries
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.remove_sensitive_keys }}"
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
        password: passw0rd
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
        password: passw0rd
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
        password: passw0rd
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
        password: passw0rd
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

- name: Remove sensitive keys from list of dictionaries
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.remove_sensitive_keys }}"
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
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: passw0rd
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
        password: passw0rd
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
  #  - address: 10.21.33.8
  #    automatic_management_enabled: true
  #    domain_type: local
  #    platform_account_type: recon
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.21.33.8
  #    platform_notes: WINANSD1S1.example.int
  #    safe: A-T-careconlocal
  #    username: careconlocal
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
  #

RETURN VALUES:

- _value  A dict or list containing the results of removing the
           specified key patterns.
        type: any
```
