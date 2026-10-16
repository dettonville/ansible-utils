## module > git_update_content

> **Note:** The compiled HTML documentation for this module is available at: [https://dettonville.github.io/ansible-utils/git_update_content_module.html](https://dettonville.github.io/ansible-utils/git_update_content_module.html)

Update one or more files in a Git repository across supported formats ( YAML, JSON, INI, raw/text).

- [Synopsis](#synopsis)
- [Parameters](#parameters)
- [Examples](#examples)
- [Return Values](#return-values)
- [CLI Reproducibility & Environment](#cli-reproducibility--environment)

## Synopsis

- Clones a remote Git repository using SSH or HTTPS credentials.
- Creates a new feature branch and updates specified files across YAML, JSON, INI, or raw text formats.
- Supports 'merge', 'overwrite', and 'absent' states for file updates.
- Commits and pushes the branch back to the remote repository.
- Optionally creates a Pull Request via the Gitea API if enabled.

## Parameters

| Parameter | Choices / Defaults | Comments |
| :--- | :--- | :--- |
| **branch_name**<br>`str / **required**` |  | Name of the new feature branch to create and push for the content updates. |
| **content**<br>`raw / **required**` |  | Dictionary where keys are relative file paths from the repository root and values are the content/data to update.<br>Can also be a list of file paths when using C(state: absent) to remove entire files. |
| **git_comment_prefix**<br>`str` | Default: `"INFRA"` | Prefix string for git commit comments (e.g. ticket ID). |
| **git_repo_branch**<br>`str` | Default: `"main"` | Source branch to clone and checkout initially.<br><br>*aliases:* `repo_branch, branch` |
| **git_repo_url**<br>`str / **required**` |  | Git repository SSH or HTTPS URL to clone.<br><br>*aliases:* `repo_url, url` |
| **gitea_api_token**<br>`str` |  | Gitea API token. Required when C(post_gitea_pr) is set to true. |
| **logging_level**<br>`str` | Default: `"INFO"`<br>Choices:<br>&bull; `NOTSET`<br>&bull; `DEBUG`<br>&bull; `INFO`<br>&bull; `WARNING`<br>&bull; `ERROR` | Logging level for troubleshooting output. |
| **post_gitea_pr**<br>`bool` | Default: `false` | Boolean indicating whether to issue a Gitea API request to open a pull request. |
| **ssh_params**<br>`dict` | Default: `{}` | Dictionary containing SSH parameters (key_file, key, accept_hostkey, ssh_opts). |
| **state**<br>`str` | Default: `"merge"`<br>Choices:<br>&bull; `merge`<br>&bull; `overwrite`<br>&bull; `absent` | State of the content update. |

## Examples

```yaml
- name: Update YAML configuration file in git repo with overwrite state and open Gitea PR
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test
    git_comment_prefix: "TEST"
    state: overwrite
    post_gitea_pr: true
    gitea_api_token: "{{ lookup('env', 'GITEA_TOKEN') }}"
    ssh_params:
      accept_hostkey: true
      key_file: '~/.ssh/id_rsa'
    content:
      vars/test.yml:
        key: value

- name: Merge new keys into existing YAML configuration file in git repo
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test-merge
    git_comment_prefix: "TEST"
    state: merge
    post_gitea_pr: false
    content:
      vars/test.yml:
        new_key: new_value

- name: Remove a file from the git repo using absent state
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test-absent
    git_comment_prefix: "TEST"
    state: absent
    post_gitea_pr: false
    content:
      - vars/test.yml
```

## Return Values

| Key | Returned | Description |
| :--- | :--- | :--- |
| **branch**<br>`(str)` | always | The created branch name.<br><br>*sample:* `feature/update-vars-25088` |
| **changed**<br>`(bool)` | always | True if repository files were modified and pushed.<br><br>*sample:* `True` |
| **msg**<br>`(str)` | always | Summary message of actions performed.<br><br>*sample:* `Git content update completed successfully on branch feature/update-vars-25088` |
| **pr_url**<br>`(str)` | when post_gitea_pr is true | URL of the created Gitea pull request if C(post_gitea_pr) is enabled.<br><br>*sample:* `https://gitea.example.org/api/v1/repos/ansible/demo-inventory/pulls/42` |

## CLI Reproducibility & Environment

To view this module documentation directly in your terminal or replicate the output:

```shell
$ ansible --version
ansible [core 2.21.3]
  config file = None
  configured module search path = ['/Users/ljohnson/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/lib/python3.13/site-packages/ansible
  ansible collection location = /var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_1qpr4num
  executable location = /Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.cache/pre-commit/repor618j53f/py_env-python3.13/bin/python)
  jinja version = 3.1.6
  pyyaml version = 6.0.3 (with libyaml v0.2.5)
$ REPO_DIR="$( git rev-parse --show-toplevel )"
cd ${REPO_DIR}
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.git_update_content | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/git_update_content.md
> MODULE dettonville.utils.git_update_content (/var/folders/w6/3rcdpp211v5cxml6vg45ww3r0000gn/T/ansible_doc_1qpr4num/ansible_collections/dettonville/utils/plugins/modules/git_update_content.py)

  Clones a remote Git repository using SSH or HTTPS credentials.
  Creates a new feature branch and updates specified files across
  YAML, JSON, INI, or raw text formats.
  Supports 'merge', 'overwrite', and 'absent' states for file updates.
  Commits and pushes the branch back to the remote repository.
  Optionally creates a Pull Request via the Gitea API if enabled.

OPTIONS (= indicates it is required):

= branch_name  Name of the new feature branch to create and push for
                the content updates.
        type: str

= content  Dictionary where keys are relative file paths from the
            repository root and values are the content/data to update.
            Can also be a list of file paths when using `state:
            absent' to remove entire files.
        type: raw

- git_comment_prefix  Prefix string for git commit comments (e.g.
                       ticket ID).
        default: INFRA
        type: str

- git_repo_branch  Source branch to clone and checkout initially.
        aliases: [repo_branch, branch]
        default: main
        type: str

= git_repo_url  Git repository SSH or HTTPS URL to clone.
        aliases: [repo_url, url]
        type: str

- gitea_api_token  Gitea API token. Required when `post_gitea_pr' is
                    set to true.
        default: null
        type: str

- logging_level  Logging level for troubleshooting output.
        choices: [NOTSET, DEBUG, INFO, WARNING, ERROR]
        default: INFO
        type: str

- post_gitea_pr  Boolean indicating whether to issue a Gitea API
                  request to open a pull request.
        default: false
        type: bool

- ssh_params  Dictionary containing SSH parameters (key_file, key,
               accept_hostkey, ssh_opts).
        default: {}
        type: dict

- state   State of the content update.
        choices: [merge, overwrite, absent]
        default: merge
        type: str

AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
- name: Update YAML configuration file in git repo with overwrite state and open Gitea PR
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test
    git_comment_prefix: "TEST"
    state: overwrite
    post_gitea_pr: true
    gitea_api_token: "{{ lookup('env', 'GITEA_TOKEN') }}"
    ssh_params:
      accept_hostkey: true
      key_file: '~/.ssh/id_rsa'
    content:
      vars/test.yml:
        key: value

- name: Merge new keys into existing YAML configuration file in git repo
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test-merge
    git_comment_prefix: "TEST"
    state: merge
    post_gitea_pr: false
    content:
      vars/test.yml:
        new_key: new_value

- name: Remove a file from the git repo using absent state
  dettonville.utils.git_update_content:
    git_repo_url: ssh://git@repo.example.org:2222/ansible/demo-inventory.git
    git_repo_branch: main
    branch_name: feature/test-absent
    git_comment_prefix: "TEST"
    state: absent
    post_gitea_pr: false
    content:
      - vars/test.yml

RETURN VALUES:

- branch  The created branch name.
        returned: always
        sample: feature/update-vars-25088
        type: str

- changed  True if repository files were modified and pushed.
        returned: always
        sample: true
        type: bool

- msg     Summary message of actions performed.
        returned: always
        sample: Git content update completed successfully on branch feature/update-vars-25088
        type: str

- pr_url  URL of the created Gitea pull request if `post_gitea_pr' is
           enabled.
        returned: when post_gitea_pr is true
        sample: https://gitea.example.org/api/v1/repos/ansible/demo-inventory/pulls/42
        type: str
```
