

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.to_key_value | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/to_key_value.md
> FILTER dettonville.utils.to_key_value (/Users/ljohnson/tmp/_8SFdIF/ansible_collections/dettonville/utils/plugins/filter/to_key_value.py)

  Convert flat dictionary to key=value formatted text.

OPTIONS (= indicates it is required):

= _input  The flat dictionary to convert.
        type: dict

AUTHOR: Lee Johnson (@lj020326)

NAME: to_key_value

EXAMPLES:
- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # name=Alice
  # age=30
  # city=New York

- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=true) }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # name="Alice"
  # age="30"
  # city="New York"

RETURN VALUES:

- _value  formatted string representing the input data in key=value
           format.
        type: str

```
