## module > sort_dict_keys

Sort dictionary keys

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Sort dictionary keys.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **_input**<br>`list / elements=dictionary / **required**` |  | A list of dictionaries |
| **reverse**<br>`list` | Default: `false` | Set reverse=True to sort keys in descending order. |

## Examples

```yaml
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
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **_value**<br>`(list)` | always | A sorted list containing the dictionaries from the original list. |

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.sort_dict_keys | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/sort_dict_keys.md
> FILTER dettonville.utils.sort_dict_keys (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_v8vnagfk/ansible_collections/dettonville/utils/plugins/filter/sort_dict_keys.py)

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

- _value  A sorted list containing the dictionaries from the original
           list.
        type: list
```
