

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
> FILTER dettonville.utils.to_key_value (/Users/ljohnson/tmp/_DcjK8N/ansible_collections/dettonville/utils/plugins/filter/to_key_value.py)

  Convert flat dictionary to key=value formatted text.

OPTIONS (= indicates it is required):

= _input  The flat dictionary to convert.
        type: dict

- joiner  String used to join each formatted key-value pair line.
        default: \n
        type: str

- quote   Toggle whether to wrap values in quote characters.
        default: false
        type: bool

- quote_char  The character used for quoting values when [quote] is
               enabled.
        default: '"'
        type: str

- separator  String used to separate each key and value pair.
        default: '='
        type: str

- sort_keys  Toggle whether to sort keys alphanumerically instead of
              preserving insertion order.
        default: false
        type: bool

AUTHOR: Lee Johnson (@lj020326)

NAME: to_key_value

EXAMPLES:
- name: 1. Basic usage (default options)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value }}"
  vars:
    my_dict:
      DB_HOST: postgres
      DB_PORT: 5432
  # Output:
  # DB_HOST=postgres
  # DB_PORT=5432

- name: 2. Custom separator usage
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(separator=': ') }}"
  vars:
    my_dict:
      KEY: VALUE
  # Output:
  # KEY: VALUE

- name: 3. Quoted values (Double quotes)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=True) }}"
  vars:
    my_dict:
      API_KEY: secret123
  # Output:
  # API_KEY="secret123"

- name: 4. Quoted values (Single quotes)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(quote=True, quote_char=\"'\") }}"
  vars:
    my_dict:
      API_KEY: secret123
  # Output:
  # API_KEY='secret123'

- name: 5. Sorted keys
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_key_value(sort_keys=True) }}"
  vars:
    my_dict:
      Z_KEY: last
      A_KEY: first
      M_KEY: middle
  # Output:
  # A_KEY=first
  # M_KEY=middle
  # Z_KEY=last

```
