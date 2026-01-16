#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license (https://opensource.org/license/mit/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: git_pacp
version_added: "2.20.0"
author:
    - "Lee Johnson (@lj020326)"
short_description: Perform git 'clone', 'pull', 'acp', and 'pacp' (pull, add, commit and push) operations. 
description:
    - Manage git C(clone), C(pull), C(acp), C(pacp), C(config) user name and email on a local
      or remote git repository.
options:
    path:
        description:
            - Folder path where git repo C(.git/) is located.
        required: true
        type: path
    action:
        description:
            - Git operation to perform - 'clone', 'pull', 'pacp'(Pull + Add + Commit + Push), or 'acp' (Add + Commit + Push)
        choices: [ 'clone', 'pull', 'pacp', 'acp' ]
        default: pacp
        type: str
    comment:
        description:
            - Git commit comment. Same as C(git commit -m).
            - Required if action performs commit (e.g., if action in ['pacp', 'acp'])
        type: str
    add:
        description:
            - List of files under C(path) to be staged. Same as C(git add .).
              File globs not accepted, such as C(./*) or C(*).
        type: list
        elements: str
        default: ["."]
    user:
        description:
            - Git username for https operations.
        type: str
    token:
        description:
            - Git API token for https operations.
        type: str
    branch:
        description:
            - Git branch where perform git push.
        type: str
        default: main
    push_option:
        description:
            - Git push options. Same as C(git --push-option=option).
        type: str
    mode:
        description:
            - Git operations are performend either over ssh, https or local.
              Same as C(git@git...) or C(https://user:token@git...).
              If not specified, the mode will be set to the scheme implied by the URL.
        choices: ['ssh', 'https', 'local']
        type: str
    url:
        description:
            - Git repo URL.
        required: True
        type: str
    ssh_params:
        description:
            - Dictionary containing SSH parameters.
        type: dict
        suboptions:
            key_file:
                description:
                    - Specify an optional private key file path, on the target host, to use for the checkout.
                type: path
            accept_hostkey:
                description:
                    - If C(yes), ensure that "-o StrictHostKeyChecking=no" is
                      present as an ssh option.
                type: bool
                default: false
            ssh_opts:
                description:
                    - Creates a wrapper script and exports the path as GIT_SSH
                      which git then automatically uses to override ssh arguments.
                      An example value could be "-o StrictHostKeyChecking=no"
                      (although this particular option is better set via
                      C(accept_hostkey)).
                type: str
        version_added: 2025.7.0
    executable:
        description:
            - Path to git executable to use. If not supplied,
              the normal mechanism for resolving binary paths will be used.
        type: path
        version_added: 2025.7.0
    remote:
        description:
            - Local system alias for git remote PUSH and PULL repository operations.
        type: str
        default: origin
    user_name:
        description:
            - Explicit git local user name. Nice to have for remote operations.
        type: str
        default: ansible
    user_email:
        description:
            - Explicit git local email address. Nice to have for remote operations.
        type: str
        default: ansible@example.org
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output.
        required: false
        choices: [NOTSET, DEBUG, INFO, ERROR]
        default: INFO
        type: str

requirements:
    - git>=2.10.0 (the command line tool)
"""  # NOQA

EXAMPLES = """
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
"""

RETURN = """
output:
    description: list of git cli command stdout
    type: list
    returned: always
    sample: [
        "[main 99830f4] Remove [ test.txt, tax.txt ]\n 4 files changed, 26 insertions(+)..."
    ]
"""

import logging
import pprint
from ansible.module_utils.basic import AnsibleModule

try:
    from module_utils.git_actions import Git
except ImportError:
    try:
        from ansible.module_utils.git_actions import Git
    except ImportError:
        from ansible_collections.dettonville.utils.plugins.module_utils.git_actions import (
            Git,
        )

argument_spec = dict(
    url=dict(required=True),
    branch=dict(type="str", default='main'),
    path=dict(required=True, type="path"),
    action=dict(choices=["acp", "pacp", "pull", "clone"], default="pacp"),
    executable=dict(default=None, type="path"),
    logging_level=dict(
        type="str", choices=["NOTSET", "DEBUG", "INFO", "ERROR"], default="INFO"
    ),
    comment=dict(default=None, type="str"),
    add=dict(type="list", elements="str", default=["."]),
    user=dict(),
    token=dict(no_log=True),
    ssh_params=dict(
        type="dict",
        required=False,
        options=dict(
            key_file=dict(type="path"),
            accept_hostkey=dict(type="bool", default=False),
            ssh_opts=dict(type="str", default=None),
        ),
    ),
    push_option=dict(default=None, type="str"),
    mode=dict(choices=["ssh", "https", "local"], default=None),
    remote=dict(default="origin"),
    user_name=dict(type="str", default="ansible"),
    user_email=dict(type="str", default="ansible@example.org"),
)


# ref: https://docs.ansible.com/ansible/latest/dev_guide/testing_units_modules.html#restructuring-modules-to-enable-testing-module-set-up-and-other-processes
def setup_module_object():
    required_if = [
        ("mode", "https", ["user", "token"]),
        ("action", "acp", ["comment"]),
        ("action", "pacp", ["comment"]),
    ]

    required_together = [
        ["user_name", "user_email"],
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        required_together=required_together,
    )
    return module


def run_module():
    """
    Code entrypoint.

    args: none
    return:
        * result:
            type: dict()
            description: returned output from git commands and updated changed status.
    """

    module = setup_module_object()
    # module._ansible_debug = True

    url = module.params.get("url")
    action = module.params.get("action")
    mode = module.params.get("mode")
    push_option = module.params.get("push_option")
    ssh_params = module.params.get("ssh_params")
    user_name = module.params.get("user_name")
    user_email = module.params.get("user_email")

    repo_config = {
        "repo_url": url,
        "repo_action": action,
        "repo_scheme": mode,
        "push_option": push_option,
        "token": module.params.get("token"),
        "repo_dir": module.params.get("path"),
        "repo_branch": module.params.get("branch"),
        "remote": module.params.get("remote"),
        "user": module.params.get("user"),
        "user_name": user_name,
        "user_email": user_email,
        "ssh_params": ssh_params,
    }

    loglevel = module.params.get("logging_level")
    logging.basicConfig(level=loglevel)
    module.debug("repo_config => %s" % pprint.pformat(repo_config))

    comment = module.params.get("comment")

    # We screen scrape a huge amount of git commands so use C
    # locale anytime we call run_command()
    module.run_command_environ_update = dict(
        LANG="C", LC_ALL="C", LC_MESSAGES="C", LC_CTYPE="C"
    )

    if mode == "local":
        if url.startswith(("https://", "git", "ssh://git")):
            module.fail_json(msg='SSH or HTTPS mode selected but repo is "local')

        if push_option:
            module.fail_json(msg='"--push-option" not supported with mode "local"')

        if ssh_params:
            module.warn('SSH Parameters will be ignored as mode "local"')

    elif mode == "https":
        if not url.startswith("https://"):
            module.fail_json(
                msg="HTTPS mode selected but url ("
                + url
                + ') not starting with "https"'
            )
        if ssh_params:
            module.warn('SSH Parameters will be ignored as mode "https"')

    elif mode == "ssh":
        if not url.startswith(("git", "ssh://git")):
            module.fail_json(
                msg="SSH mode selected but url ("
                + url
                + ') not starting with "git" or "ssh://git"'
            )

        if url.startswith("ssh://git@github.com"):
            module.fail_json(
                msg='GitHub does not support "ssh://" URL. Please remove it from url'
            )

    result = dict(changed=False)

    git = Git(module, repo_config)

    if action == "clone":
        result.update(git.clone())
    elif action == "pull":
        result.update(git.pull())
    else:  # default is in ['acp','pacp']
        changed_files = git.status()
        if changed_files:
            user_config = {
                "name": user_name,
                "email": user_email
            }
            git.set_user_config(user_config)

            if action == "pacp":
                result.update(git.pull())
            result.update(git.add())
            result.update(git.commit(comment))
            result.update(git.push())

    # logging.info("result => %s", pprint.pformat(result))
    module.debug("result => %s" % pprint.pformat(result))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
