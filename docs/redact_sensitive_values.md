

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.redact_sensitive_values | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/redact_sensitive_values.md
> FILTER dettonville.utils.redact_sensitive_values (/Users/ljohnson/tmp/_GYmjq8/ansible_collections/dettonville/utils/plugins/filter/redact_sensitive_values.py)

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

- key_patterns  List of key patterns to use to redact values.
        default: ['(?i).*vault.*', '(?i).*token.*', '(?i).*password.*', '(?i).*key.*', '(?i).*ssh.*']
        type: list

AUTHOR: Lee Johnson (@lj020326)

NAME: redact_sensitive_values

POSITIONAL: key_patterns

EXAMPLES:
- name: Redact sensitive values from dictionaries
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.redact_sensitive_values }}"
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
        password: 39infsVSRk
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
        password: 39infsVSRk
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
        password: 39infsVSRk
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
        password: 39infsVSRk
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
  #      password: <redacted_password>
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
  #      password: <redacted_password>
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
  #      password: <redacted_password>
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
  #      password: <redacted_password>

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
        password: 39infsVSRk
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
        password: 39infsVSRk
      - address: 10.21.33.8
        automatic_management_enabled: true
        domain_type: local
        platform_account_type: recon
        platform_id: WND-Local-Managed-DMZ
        platform_logon_domain: 10.21.33.8
        platform_notes: WINANSD1S1.example.int
        safe: A-T-careconlocal
        username: careconlocal
        password: 39infsVSRk
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
        password: 39infsVSRk
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
  #    password: <redacted_password>
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
  #    password: <redacted_password>
  #  - address: 10.21.33.8
  #    automatic_management_enabled: true
  #    domain_type: local
  #    platform_account_type: recon
  #    platform_id: WND-Local-Managed-DMZ
  #    platform_logon_domain: 10.21.33.8
  #    platform_notes: WINANSD1S1.example.int
  #    safe: A-T-careconlocal
  #    username: careconlocal
  #    password: <redacted_password>
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
  #    password: <redacted_password>
  #

RETURN VALUES:

- _value  A dict or list containing the results of redacting the
           specified key values.
        type: any

```
