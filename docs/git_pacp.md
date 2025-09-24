

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.git_pacp | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/git_pacp.md
> MODULE dettonville.utils.git_pacp (/Users/ljohnson/tmp/_lRlHig/ansible_collections/dettonville/utils/plugins/modules/git_pacp.py)

  Manage git `clone', `pull', `acp', `pacp', `config' user name and
  email on a local or remote git repository.

OPTIONS (= indicates it is required):

- action  Git operation to perform - 'clone', 'pull', 'pacp'(Pull +
           Add + Commit + Push), or 'acp' (Add + Commit + Push)
        choices: [clone, pull, pacp, acp]
        default: pacp
        type: str

- add     List of files under `path' to be staged. Same as `git add
           .'. File globs not accepted, such as `./*' or `*'.
        default: [.]
        elements: str
        type: list

- branch  Git branch where perform git push.
        default: main
        type: str

- comment  Git commit comment. Same as `git commit -m'.
            Required if action performs commit (e.g., if action in
            ['pacp', 'acp'])
        default: null
        type: str

- executable  Path to git executable to use. If not supplied, the
               normal mechanism for resolving binary paths will be
               used.
        default: null
        type: path

- logging_level  Parameter used to define the level of
                  troubleshooting output.
        choices: [NOTSET, DEBUG, INFO, ERROR]
        default: INFO
        type: str

- mode    Git operations are performend either over ssh, https or
           local. Same as `git@git...' or `https://user:token@git...'.
           If not specified, the mode will be set to the scheme
           implied by the URL.
        choices: [ssh, https, local]
        default: null
        type: str

= path    Folder path where git repo `.git/' is located.
        type: path

- push_option  Git push options. Same as `git --push-option=option'.
        default: null
        type: str

- remote  Local system alias for git remote PUSH and PULL repository
           operations.
        default: origin
        type: str

- ssh_params  Dictionary containing SSH parameters.
        default: null
        type: dict
        suboptions:

        - accept_hostkey  If `yes', ensure that "-o
                           StrictHostKeyChecking=no" is present as an
                           ssh option.
          default: false
          type: bool

        - key_file  Specify an optional private key file path, on the
                     target host, to use for the checkout.
          default: null
          type: path

        - ssh_opts  Creates a wrapper script and exports the path as
                     GIT_SSH which git then automatically uses to
                     override ssh arguments. An example value could be
                     "-o StrictHostKeyChecking=no" (although this
                     particular option is better set via
                     `accept_hostkey').
          default: null
          type: str

- token   Git API token for https operations.
        default: null
        type: str

= url     Git repo URL.
        type: str

- user    Git username for https operations.
        default: null
        type: str

- user_email  Explicit git local email address. Nice to have for
               remote operations.
        default: ansible@example.org
        type: str

- user_name  Explicit git local user name. Nice to have for remote
              operations.
        default: ansible
        type: str

REQUIREMENTS:  git>=2.10.0 (the command line tool)


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
- name: "Perform git pull/add/commit/push"
  dettonville.utils.git_pacp:
    url: ssh://git@bitbucket.example.org:2222/test/repo.git
    path: /usr/local/src
    branch: develop
    comment: "PR-123"
    ssh_params:
      accept_hostkey: true
      key_file: /tmp/.ansible_test_jobs_qhg_dmhp/ansible_repo.key
  register: git_pacp_result

- name: "Perform git pull/add/commit/push"
  dettonville.utils.git_pacp:
    action: pacp
    url: ssh://git@bitbucket.example.org:2222/test/repo.git
    path: /usr/local/src
    branch: develop
    comment: "PR-124"
    ssh_params:
      accept_hostkey: true
      key_file: /tmp/.ansible_test_jobs_qhg_dmhp/ansible_repo.key
      ssh_opts: '-o UserKnownHostsFile={{ remote_tmp_dir }}/known_hosts'
  register: git_pacp_result

- name: "Pull latest repo changes into {{ __test_git_repo_dir }}"
  dettonville.utils.git_pacp:
    url: https://github.com/test/repo.git
    branch: develop
    path: "{{ __test_git_repo_dir }}"
    action: pull
  register: git_pull_result

- name: "Perform git add/commit/push"
  dettonville.utils.git_pacp:
    url: ssh://git@bitbucket.example.org:2222/test/repo.git
    action: acp
    path: "{{ __test_git_repo_dir }}"
    branch: "{{ __test_git_repo_branch }}"
    comment: "{{ __git_comment }}"
    ssh_params:
      accept_hostkey: true
      key_file: /tmp/.ansible_test_jobs_qhg_dmhp/ansible_repo.key
      # avoid changing the test environment
      ssh_opts: "-o UserKnownHostsFile=/dev/null"
  register: git_pacp_result

- name: SSH | add/commit/push file1.
  dettonville.utils.git_pacp:
    url: "git@gitlab.com:networkAutomation/git_test_module.git"
    path: /Users/git/git_pacp
    branch: main
    comment: Add file1.
    add: ['file1']
    remote: dev_test
    mode: ssh
    user_name: ansible
    user_email: ansible@example.org

- name: HTTPS | add/commit/push all file changes
  dettonville.utils.git_pacp:
    url: "https://gitlab.com/networkAutomation/git_test_module.git"
    user: username
    token: mytoken
    path: /Users/git/git_pacp
    branch: main
    comment: Add file1.
    remote: origin
    add: ['.']

- name: SSH with private key | add file1.
  dettonville.utils.git_pacp:
    url: "git@gitlab.com:networkAutomation/git_test_module.git"
    path: /Users/git/git_pacp
    branch: main
    comment: Add file1.
    add: ['file1']
    remote: dev_test
    mode: ssh
    ssh_params:
      accept_hostkey: true
      key_file: '~/.ssh/id_rsa'
      ssh_opts: '-o UserKnownHostsFile={{ remote_tmp_dir }}/known_hosts'

- name: LOCAL | push on local repo.
  dettonville.utils.git_pacp:
    path: "~/test_directory/repo"
    branch: main
    comment: Add file1.
    add: ['file1']
    mode: local
    url: /Users/federicoolivieri/test_directory/repo.git

RETURN VALUES:

- output  list of git cli command stdout
        returned: always
        sample: ['[main 99830f4] Remove [ test.txt, tax.txt ] 4 files changed, 26 insertions(+)...']
        type: list

```
