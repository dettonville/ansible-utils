

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.export_dicts | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/export_dicts.md
> MODULE dettonville.utils.export_dicts (/Users/ljohnson/tmp/_br9sbp/ansible_collections/dettonville/utils/plugins/modules/export_dicts.py)

  Write a list of flat dictionaries (a dictionary mapping fieldnames
  to strings or numbers) to a flat file using a specified format
  choice (csv or markdown) from a list of provided column names,
  headers and column list order.

OPTIONS (= indicates it is required):

- column_list  List of column dictionary specifications for each column in the
                file. Each column element should contain a dict
                specifying values for the 'name' and 'header' keys. If
                the 'column_list' is not specified, it will be derived
                from the keys of the first row in the export_list.
        aliases: [columns]
        default: []
        elements: dict
        type: list

= export_list  Specifies a list of dicts to write to flat file.
        aliases: [list]
        elements: dict
        type: list

= file    File path where file will be written/saved.
        type: path

- format  `csv' write to csv formatted file. `md'  write to markdown formatted
           file. If the 'format' is not specified, it will be derived
           from the file extension (e.g., *.md, *.csv).
        choices: [csv, md]
        default: null
        type: str

- logging_level  Parameter used to define the level of troubleshooting output.
        choices: [NOTSET, DEBUG, INFO, ERROR]
        default: INFO
        type: str

AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
- name: csv | Write file1.csv
  dettonville.utils.export_dicts:
    file: /tmp/test-exports/file1.csv
    format: csv
    export_list:
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: md | Write markdown export_dicts.md
  dettonville.utils.export_dicts:
    file: /tmp/test-exports/export_dicts.md
    format: md
    export_list:
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: csv with headers | Write file1.csv
  dettonville.utils.export_dicts:
    file: /tmp/test-exports/file1.csv
    format: csv
    columns:
      - { "name": "key1", "header": "Key #1" }
      - { "name": "key2", "header": "Key #2" }
      - { "name": "key3", "header": "Key #3" }
      - { "name": "key4", "header": "Key #4" }
    export_list:
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: md with headers | Write markdown export_dicts.md
  dettonville.utils.export_dicts:
    file: /tmp/test-exports/export_dicts.md
    format: md
    columns:
      - { "name": "key1", "header": "Key #1" }
      - { "name": "key2", "header": "Key #2" }
      - { "name": "key3", "header": "Key #3" }
      - { "name": "key4", "header": "Key #4" }
    export_list:
      - { key1: "båz", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "ﬀöø", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "ḃâŗ", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "ﬀöø", key4: "båz" }

RETURN VALUES:

- changed  True if successful
        returned: always
        type: bool

- failed  True if export failed
        returned: always
        type: bool

- message  Status message for export
        returned: always
        sample: The markdown file has been created successfully at /foo/bar/test.md
        type: str

```
