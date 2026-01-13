

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.sort_dict_list | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/sort_dict_list.md
> FILTER dettonville.utils.sort_dict_list (/Users/ljohnson/tmp/_1BEe4c/ansible_collections/dettonville/utils/plugins/filter/sort_dict_list.py)

  Sort list of dictionaries by a specified key(s).

OPTIONS (= indicates it is required):

= _input  A list of dictionaries
        elements: dictionary
        type: list

= sort_keys  The attributes to use as the sort keys.
        type: list

AUTHOR: Lee Johnson (@lj020326)

NAME: sort_dict_list

POSITIONAL: sort_keys

EXAMPLES:
- name: Sort a list of dictionaries based on single key sort
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.sort_dict_list('name') }}"
  vars:
    my_list:
      - name: value
        foo: bar
      - name: other_value
        baz: bar
  # Produces the sorted list:
  #
  #  my_list:
  #    - name: other_value
  #      baz: bar
  #    - name: value
  #      foo: bar

- name: Sort a list of dictionaries based on multiple key sort
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.sort_dict_list(['platform_id','address','username']) }}"
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
  #   - address: 10.21.33.8
  #     automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_id: WND-Local-Managed-DMZ
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: Windows-Server-Local-Admin
  #     username: administrator
  #   - address: 10.21.33.8
  #     automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_id: WND-Local-Managed-DMZ
  #     platform_logon_domain: 10.21.33.8
  #     platform_notes: WINANSD1S1.example.int
  #     safe: A-T-careconlocal
  #     username: careconlocal
  #   - address: 10.31.25.54
  #     automatic_management_enabled: true
  #     domain_type: local
  #     groups:
  #     - Administrators
  #     local_admin_username: administrator
  #     managed: true
  #     platform_account_type: platform
  #     platform_id: WND-Local-Managed-DMZ
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: Windows-Server-Local-Admin
  #     username: administrator
  #   - address: 10.31.25.54
  #     automatic_management_enabled: true
  #     domain_type: local
  #     platform_account_type: recon
  #     platform_id: WND-Local-Managed-DMZ
  #     platform_logon_domain: 10.31.25.54
  #     platform_notes: WINANSD1S4.example.int
  #     safe: A-T-careconlocal
  #     username: careconlocal

RETURN VALUES:

- _value  A sorted list containing the dictionaries from the original
           list.
        type: list

```
