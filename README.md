# dettonville.utils

`dettonville.utils` includes an Ansible module 'export_dicts' that can be used to export a list of dictionaries to a specified file in either a 'csv' or 'markdown' format.


## Plugins

### Filter

* `to_ini` - Convert hash/map/dict to INI format
* `from_ini` - Convert INI to hash/map/dict
* `to_toml` - Convert hash/map/dict to TOML format
* `from_toml` - Convert TOML to hash/map/dict
* `jq` - Parse JSON using `jq`
* `export_dicts` - Export list of dicts to file in either comma-delimited '*.csv' or markdown '*.md' format

### Modules

#### net_tools

* `speedtest` - Tests internet bandwidth using speedtest.net

#### packaging

* `go` - Manage Golang packages

#### system

* `cert_locations` - Report CA cert locations used by Ansible

### Callback

* `dump_stats` - Callback to dump to stats from `set_stat` to a JSON file
* `cprofile` - Uses `cProfile` to profile the python execution of ansible







## Setup test environment

The collection project structure:

```
tree -A -d -L 4 .
.
├── collections
│   └── ansible_collections
│       └── dettonville
│           └── utils
├── docs -> collections/ansible_collections/dettonville/utils/docs
├── plugins -> collections/ansible_collections/dettonville/utils/plugins
├── roles -> collections/ansible_collections/dettonville/utils/roles
└── tests -> collections/ansible_collections/dettonville/utils/tests

9 directories
```

Run `ansible-test` from within `ansible_collections/dettonville/utils/`:

```shell
git clone https://github.com/dettonville/ansible-collection ansible-dettonville-collection
cd ansible-dettonville-collection/collections/ansible_collections/dettonville/utils
```


Validate that the local module is available by viewing the module documentation:

```shell
ansible-doc -t module dettonville.utils.export_dicts
> DETTONVILLE.UTILS.EXPORT_DICTS    (/Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/plugins/modules/export_dicts.py)

        Write a list of flat dictionaries to a flat file using a specified format choice (csv or markdown) from a list of provided column names, headers and column list order.

OPTIONS (= is mandatory):

- column_list
        List containing a list of column dictionary specifications for each column in the file. Each column element should contain a dict specifying values for the 'name' and 'header' keys. If the 'column_list'
        is not specified, it will be derived from the keys of the first row in the export_list.
        (Aliases: columns)[Default: []]
        elements: dict
        type: list

= export_list
        Specifies a list of dicts to write to flat file.
        (Aliases: list)
        elements: dict
        type: list

= file
        File path where file will be written/saved.

        type: path

- format
        `csv' write to csv formatted file. `md'  write to markdown formatted file.
        (Choices: csv, md)[Default: csv]
        type: str


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:

- name: csv | Write file1.csv
  export_dicts:
    file: /tmp/test-exports/file1.csv
    format: csv
    export_list: 
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: md | Write markdown export_dicts.md
  export_dicts:
    file: /tmp/test-exports/export_dicts.md
    format: md
    export_list: 
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: csv with headers | Write file1.csv
  export_dicts:
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
  export_dicts:
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
- changed
        True if successful

        returned: always
        type: bool

- failed
        True if cyberark accounts lookup failed to find results

        returned: always
        type: bool

- message
        Status message for lookup

        returned: always
        sample: The markdown file has been created successfully at /foo/bar/test.md
        type: str

```

## Run Tests

```shell
run_tests.sh > run_test.results.2022-06-16.txt

```



## Local Library Install Method

To use/develop the 'export_dicts' module locally, you can copy `ansible_collections/dettonville/utils/plugins/modules/export_dicts.py` into a `library` directory in the root of your Ansible project:

```
myproject/
├── ansible.cfg
├── inv/
├── library/
│   ├── export_dicts.py
├── playbooks/
├── roles/
├── tests/
```

Make sure to include the local 'library' path in the project ansible.cfg:

```ini
## custom library paths
## ref: https://stackoverflow.com/questions/53750049/location-to-keep-ansible-custom-modules
;library = ./library
library = ~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules:./library
```

Validate that the local module is available by viewing the module documentation:

```shell
$ ansible-doc -t module export_dicts

> EXPORT_DICTS    (/Users/ljohnson/repos/ansible/ansible-datacenter/library/export_dicts.py)

        Write a list of flat dictionaries to a flat file using a
        specified format choice (csv or markdown) from a list of
        provided column names, headers and column list order.
  ...

RETURN VALUES:
- output
        A message describing the task result.

        returned: always
        sample: The markdown file has been created successfully at
        /foo/bar/test.md
        type: str

```

Local test custom module using python:
```shell
python -m library.export_dicts tests/modules/export_dicts.test1.args.json

{"changed": true, "original_message": "hello", "message": "goodbye", "invocation": {"module_args": {"name": "hello", "new": true}}}

```

Test using ansible:
```shell
$ ansible localhost -m test_module -a name=foo

PLAY [Ansible Ad-Hoc] *********************************************************************************************************************************************************************************************************************************************************

TASK [test_module] ************************************************************************************************************************************************************************************************************************************************************
ok: [localhost]

PLAY RECAP ********************************************************************************************************************************************************************************************************************************************************************
localhost                  : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

```




### Ansible Galaxy Install (for Ansible version > 2.9)

All info related to Ansible Galax install are available [here](ansible_collections/lvrfrc87/dettonville.utils/README.md)

### Module Documentation:

```
module: export_dicts
author:
    - "Lee Johnson (@lj020326)"
short_description: Write a list of flat dictionaries (a dictionary mapping fieldnames to strings or numbers) to a file with either csv or markdown format. 
description:
    - Write a list of flat dictionaries to a flat file using a specified format choice (csv or markdown) from a list of provided column names, headers and column list order.
options:
    file:
        required: true
        type: path
        description:
            - File path where file will be written/saved.
    format:
        description:
          - C(csv) write to csv formatted file.
            C(md)  write to markdown formatted file.
        required: false
        type: str
        choices: [ csv, md ]
        default: "csv"
    export_list:
        aliases: ['list']
        required: true
        type: list
        elements: dict
        description:
            - Specifies a list of dicts to write to flat file.
    column_list:
        aliases: ['columns']
        description:
            - List containing a list of column dictionary specifications for each column in the file.  
              Each column element should contain a dict specifying values for the 'name' and 'header' keys.
              If the 'column_list' is not specified, it will be derived from the keys of the first row in the export_list. 
        required: false
        default: []
        type: list
        elements: dict

```

### Examples:

```
- name: csv | Write file1.csv
  export_dicts:
    file: /tmp/test-exports/file1.csv
    format: csv
    export_list: 
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: md | Write markdown export_dicts.md
  export_dicts:
    file: /tmp/test-exports/export_dicts.md
    format: md
    export_list: 
      - { key1: "value11", key2: "value12", key3: "value13", key4: "value14" }
      - { key1: "value21", key2: "value22", key3: "value23", key4: "value24" }
      - { key1: "value31", key2: "value32", key3: "value33", key4: "value34" }
      - { key1: "value41", key2: "value42", key3: "value43", key4: "value44" }

- name: csv with headers | Write file1.csv
  export_dicts:
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
  export_dicts:
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

```







