

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t filter dettonville.utils.to_markdown | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/to_markdown.md
> FILTER dettonville.utils.to_markdown (/Users/ljohnson/tmp/_F3kJWP/ansible_collections/dettonville/utils/plugins/filter/to_markdown.py)

  Convert dictionaries or lists of dictionaries to Markdown tables.
  For simple dicts, creates a key-value table.
  For lists of dicts, creates a table with keys as headers.
  Primitives are returned as-is.
  Nested structures are flattened with dot notation.

OPTIONS (= indicates it is required):

= _input  The data to convert to Markdown.
        type: any

- flatten_nested  Whether to flatten nested dicts.
        default: true
        type: bool

AUTHOR: Lee Johnson (@lj020326)

NAME: to_markdown

EXAMPLES:
- name: Convert simple dict to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_markdown }}"
  vars:
    my_dict:
      name: Alice
      age: 30
      city: New York
  # Produces:
  # | Key  | Value   |
  # |------|---------|
  # | name | Alice   |
  # | age  | 30      |
  # | city | New York |

- name: Convert list of dicts to Markdown table
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.to_markdown }}"
  vars:
    my_list:
      - name: Alice
        age: 30
        city: New York
      - name: Bob
        age: 25
        city: London
  # Produces:
  # | name | age | city     |
  # |------|-----|----------|
  # | Alice| 30  | New York |
  # | Bob  | 25  | London   |

- name: Convert nested dict (flattened)
  ansible.builtin.debug:
    msg: "{{ my_nested | dettonville.utils.to_markdown }}"
  vars:
    my_nested:
      user:
        name: Alice
        address:
          street: 123 Main St
          city: New York
      preferences:
        theme: dark
  # Produces:
  # | Key                  | Value     |
  # |----------------------|-----------|
  # | user.name            | Alice     |
  # | user.address.street  | 123 Main St |
  # | user.address.city    | New York  |
  # | preferences.theme    | dark      |

RETURN VALUES:

- _value  Markdown formatted string representing the input data.
        type: str

```
