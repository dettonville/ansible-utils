

```shell
$ ansible --version
ansible [core 2.18.4]
  config file = /Users/ljohnson/repos/ansible/ansible_collections/dettonville.utils/ansible.cfg
  configured module search path = [/Users/ljohnson/.ansible/plugins/modules, /usr/share/ansible/plugins/modules]
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.12.3/lib/python3.12/site-packages/ansible
  ansible collection location = /Users/ljohnson/.ansible/collections:/usr/share/ansible/collections:/Users/ljohnson/repos/ansible/ansible_collections/dettonville.utils/collections
  executable location = /Users/ljohnson/.pyenv/versions/3.12.3/bin/ansible
  python version = 3.12.3 (main, Oct 16 2024, 14:24:42) [Clang 15.0.0 (clang-1500.0.40.1)] (/Users/ljohnson/.pyenv/versions/3.12.3/bin/python3.12)
  jinja version = 3.1.4
  libyaml = True
$
$ PROJECT_DIR="$( git rev-parse --show-toplevel )"
$ cd ${PROJECT_DIR}
$
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.sort_dict_keys | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/sort_dict_keys.md
> FILTER dettonville.utils.sort_dict_keys (/Users/ljohnson/tmp/_br9sbp/ansible_collections/dettonville/utils/plugins/filter/sort_dict_keys.py)

  Sort dictionary keys.

OPTIONS (= indicates it is required):

= _input  A list of dictionaries
        elements: dictionary
        type: list

- reverse  Set reverse=True to sort keys in descending order.
        default: false
        type: list

AUTHOR: Lee Johnson (@lj020326)

NAME: sort_dict_keys

POSITIONAL: reverse

EXAMPLES:
- name: Sort dictionary keys
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.sort_dict_keys }}"
  vars:
    my_dict:
      hosts.yml:
        all:
          children:
            app_abc123_qa:
              hosts:
                test123.qa.site1.example.int: {}
            app_abc123_prod:
              hosts:
                test123.prod.site1.example.int: {}
      group_vars/xenv_groups.yml:
        all:
          children:
            app_abc123:
              children:
                app_abc123_qa: {}
                app_abc123_sandbox: {}
                app_abc123_dev: {}
                app_abc123_prod: {}
            ansible_localhost:
              children:
                ansible_localhost_iam: {}
                ansible_controller_iam: {}
  # Produces the sorted dict:
  #
  #  my_dict:
  #    group_vars/xenv_groups.yml:
  #      all:
  #        children:
  #          ansible_localhost:
  #            children:
  #              ansible_controller_iam: {}
  #              ansible_localhost_iam: {}
  #          app_abc123:
  #            children:
  #              app_abc123_dev: {}
  #              app_abc123_prod: {}
  #              app_abc123_qa: {}
  #              app_abc123_sandbox: {}
  #    hosts.yml:
  #      all:
  #        children:
  #          app_abc123_prod:
  #            hosts:
  #              test123.prod.site1.example.int: {}
  #          app_abc123_qa:
  #            hosts:
  #              test123.qa.site1.example.int: {}

RETURN VALUES:

- _value  A sorted list containing the dictionaries from the original list.
        type: list

```
