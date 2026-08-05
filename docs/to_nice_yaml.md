
```shell
$ ansible --version
ansible [core 2.21.2]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /Users/ljohnson/tmp/_2CyVPv:/Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
$ cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.to_nice_yaml | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/to_nice_yaml.md
> FILTER dettonville.utils.to_nice_yaml (/Users/ljohnson/tmp/_2CyVPv/ansible_collections/dettonville/utils/plugins/filter/to_nice_yaml_utils.py)

  Serializes an input data object down to a cleanly formatted YAML
  string representation.
  Exposes configuration control for explicit mapping spaces, sequence
  blocks, and indicator offsets.
  Supports common serialization flags such as key sorting, unicode
  preservation, and explicit document boundaries.

OPTIONS (= indicates it is required):

= _input  The data object (dict, list, etc.) to serialize.
        type: any

- allow_unicode  Whether to allow unicode characters directly instead
                  of escaping them to ASCII.
        default: true
        type: boolean

- explicit_start  Whether to include an explicit document start
                   marker (---).
        default: false
        type: boolean

- mapping  Number of spaces for mapping indentations.
        default: 2
        type: integer

- offset  Number of spaces to offset the sequence dash indicator
           token inside the block.
        default: 2
        type: integer

- sequence  Number of spaces for sequence indentations (including
             prefix spacing).
        default: 4
        type: integer

- sort_keys  Whether to sort dictionary keys alphabetically.
        default: false
        type: boolean

- width   Maximum line width limit for wrapped lines.
        default: 120
        type: integer

AUTHOR: Lee Johnson (@lj020326)

NAME: to_nice_yaml

POSITIONAL: mapping, sequence, offset

EXAMPLES:
- name: Format nested configurations with custom structural spacing
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_nice_yaml(
        mapping=4, sequence=6, offset=3) }}"
  vars:
    my_dict:
      config:
        services:
          - name: nginx
            port: 80

- name: Enforce alphabetized dictionary keys and document start directives
  ansible.builtin.debug:
    msg: >-
      {{ my_dict | dettonville.utils.to_nice_yaml(
          explicit_start=true,
          sort_keys=true,
          width=80
      ) }}
  vars:
    my_dict:
      z_environment: production
      b_region: us-east-1
      a_cluster_id: k8s-01

- name: Preserve native Unicode text configurations without escaping
  ansible.builtin.debug:
    msg: "{{ item | dettonville.utils.to_nice_yaml(allow_unicode=true) }}"
  vars:
    item:
      description: "Automated deployment configuration for Tokyo datacenter"
      tags: ["東京", "本番"]

RETURN VALUES:

- _value  Customized formatted YAML text block string representation.
        type: string

```
