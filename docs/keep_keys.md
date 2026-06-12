

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.keep_keys | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/keep_keys.md
> FILTER dettonville.utils.keep_keys (/Users/ljohnson/tmp/_DcjK8N/ansible_collections/dettonville/utils/plugins/filter/keep_keys.py)

  Traverses a dictionary or a list of dictionaries and retains only
  the keys that match the provided list of regex patterns.
  Can operate recursively or only on the first level of the data
  structure.

OPTIONS (= indicates it is required):

= _input  Dictionary or list of dictionaries to filter.
        type: any

= key_patterns  List of regex patterns representing the keys to keep.
        type: list

- recursive  Whether to apply the filter recursively to nested
              dictionaries.
        default: false
        type: boolean

AUTHOR: Lee Johnson (@lj020326)

NAME: keep_keys

POSITIONAL: key_patterns

EXAMPLES:
- name: Keep only specific keys at the top level (Default behavior)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.keep_keys(['name', 'status']) }}"
  vars:
    my_dict:
      name: production-cluster
      status: active
      credentials:
        token: secret123
        ssh_key: private_key

- name: Keep keys recursively using regex matching
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.keep_keys(['(?i).*id.*', 'name'], recursive=true) }}"
  vars:
    my_list:
      - account_id: 12345
        name: main
        meta: some_meta
      - user_id: 67890
        name: admin
        roles: ['admin', 'user']

RETURN VALUES:

- _value  A dict or list containing only the retained keys.
        type: any

```
