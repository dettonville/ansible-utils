

```shell
$ ansible --version
ansible [core 2.19.2]
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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.to_markdown | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/to_markdown.md
> FILTER dettonville.utils.to_markdown (/Users/ljohnson/tmp/_lRlHig/ansible_collections/dettonville/utils/plugins/filter/to_markdown.py)

  Converts a list of flat dictionaries to markdown format.

OPTIONS (= indicates it is required):

= _input  The list of dictionaries that should be converted to the
           markdown format.
        type: list

AUTHOR: Lee Johnson

NAME: to_markdown

EXAMPLES:
- name: Define a list of dictionaries
  ansible.builtin.set_fact:
    export_list:
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: Write dictionary to markdown
  ansible.builtin.copy:
    dest: /tmp/test.md
    content: '{{ export_list | dettonville.utils.to_markdown }}'

# Produces the markdown:
# | key1 | key2 | key3 | key4 |
# | --- | --- | --- | --- |
# | value11 | value12 | value13 | value14 |
# | value21 | value22 | value23 | value24 |
# | value31 | value32 | value33 | value34 |
# | value41 | value42 | value43 | value44 |

RETURN VALUES:

- _value  A string formatted as markdown.
        type: string

```
