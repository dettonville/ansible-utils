## module > new

> **Note:** The compiled HTML documentation for this module is available at: [https://dettonville.github.io/ansible-utils/new_module.html](https://dettonville.github.io/ansible-utils/new_module.html)

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis


## Parameters

No parameters specified.

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.3]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_5arr08x0
  executable location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.git_update_content.new | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/git_update_content.new.md
```
