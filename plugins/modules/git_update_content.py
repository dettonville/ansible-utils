#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Lee Johnson <ljohnson@dettonville.org>
# MIT license (https://opensource.org)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: git_update_content
short_description: >-
    Update one or more files in a Git repository across supported formats (
    YAML, JSON, INI, raw/text).
description:
  - Clones a remote Git repository using SSH or HTTPS credentials.
  - Creates a new feature branch and updates specified files across YAML, JSON, INI, or raw text formats.
  - Supports 'merge', 'overwrite', and 'absent' states for file updates.
  - Commits and pushes the branch back to the remote repository.
  - Optionally creates a Pull Request via the Gitea API if enabled.
version_added: "2026.10.0"
options:
  git_repo_url:
    description:
      - Git repository SSH or HTTPS URL to clone.
    type: str
    required: true
    aliases: ['repo_url', 'url']
  git_repo_branch:
    description:
      - Source branch to clone and checkout initially.
    type: str
    default: main
    aliases: ['repo_branch', 'branch']
  branch_name:
    description:
      - Name of the new feature branch to create and push for the content updates.
    type: str
    required: true
  content:
    description:
      - Dictionary where keys are relative file paths from the repository root and values are the content/data to update.
      - "Can also be a list of file paths when using C(state: absent) to remove entire files."
    type: raw
    required: true
  state:
    description:
      - State of the content update.
    type: str
    choices: ['merge', 'overwrite', 'absent']
    default: merge
  git_comment_prefix:
    description:
      - Prefix string for git commit comments (e.g. ticket ID).
    type: str
    default: "INFRA"
  post_gitea_pr:
    description:
      - Boolean indicating whether to issue a Gitea API request to open a pull request.
    type: bool
    default: false
  gitea_api_token:
    description:
      - Gitea API token. Required when C(post_gitea_pr) is set to true.
    type: str
  ssh_params:
    description:
      - Dictionary containing SSH parameters (key_file, key, accept_hostkey, ssh_opts).
    type: dict
    default: {}
  logging_level:
    description:
      - Logging level for troubleshooting output.
    type: str
    default: INFO
    choices: ['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR']
author:
  - Lee Johnson (@lj020326)
'''

EXAMPLES = r'''
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
'''

RETURN = r'''
changed:
  description: True if repository files were modified and pushed.
  returned: always
  type: bool
  sample: true
branch:
  description: The created branch name.
  returned: always
  type: str
  sample: "feature/update-vars-25088"
pr_url:
  description: URL of the created Gitea pull request if C(post_gitea_pr) is enabled.
  returned: when post_gitea_pr is true
  type: str
  sample: "https://gitea.example.org/api/v1/repos/ansible/demo-inventory/pulls/42"
msg:
  description: Summary message of actions performed.
  returned: always
  type: str
  sample: "Git content update completed successfully on branch feature/update-vars-25088"
'''

import configparser
import io
import json
import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url

from ansible_collections.dettonville.utils.plugins.module_utils.git_actions import (
    Git,
)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class GitUpdateContentManager:
    def __init__(self, module):
        self.module = module
        if not HAS_YAML:
            self.module.fail_json(
                msg="PyYAML is required for the git_update_content module."
            )

        self.params = module.params
        self.git_repo_url = self.params.get("git_repo_url")
        self.git_repo_branch = self.params.get("git_repo_branch")
        self.branch_name = self.params.get("branch_name")
        self.content = self.params.get("content") or {}
        self.state = self.params.get("state")
        self.git_comment_prefix = (
            self.params.get("git_comment_prefix") or "INFRA"
        )
        self.post_gitea_pr = self.params.get("post_gitea_pr")
        self.gitea_api_token = self.params.get("gitea_api_token")
        self.ssh_params = self.params.get("ssh_params") or {}
        self.logging_level = self.params.get("logging_level")

        if self.post_gitea_pr and not self.gitea_api_token:
            self.module.fail_json(
                msg="gitea_api_token is required when post_gitea_pr is set to true."
            )

        self.results = {
            "changed": False,
            "branch": self.branch_name,
            "msg": "",
        }

    def run(self):
        log_prefix = "[git_update_content]"

        # Configure Git repo parameters
        git_repo_config = {
            "repo_url": self.git_repo_url,
            "branch": self.git_repo_branch,
            "ssh_params": self.ssh_params,
            "logging_level": self.logging_level,
        }

        self.git = Git(self.module, git_repo_config)

        if git_repo_config.get("repo_url"):
            self.module.log(f"{log_prefix} cloning git repository")
            self.git.clone()
            self.git.pull()

        repo_path = self.git.path

        # Create and checkout new branch
        self.module.log(f"{log_prefix} creating branch {self.branch_name}")
        self.git.execute(["checkout", "-b", self.branch_name])

        changed_files = []
        for rel_path, new_data in self.content.items():
            abs_path = os.path.join(repo_path, rel_path)
            file_changed = self._apply_file_state(abs_path, new_data)
            if file_changed:
                changed_files.append(rel_path)

        if changed_files:
            self.results["changed"] = True
            # Stage changed files
            self.git.add(changed_files)
            comment = f"{self.git_comment_prefix}: Update content for {', '.join(changed_files)}"
            self.git.commit(comment)
            self.git.push(remote="origin", branch=self.branch_name)

            if self.post_gitea_pr:
                pr_url = self._create_gitea_pr()
                if pr_url:
                    self.results["pr_url"] = pr_url

            self.results["msg"] = (
                f"Successfully updated and pushed files: {', '.join(changed_files)}"
            )
        else:
            self.results["msg"] = "No changes detected in target files."

        self.module.exit_json(**self.results)

    def _apply_file_state(self, abs_path, new_data):
        dir_name = os.path.dirname(abs_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

        ext = os.path.splitext(abs_path)[1].lower()

        if self.state == 'absent':
            if os.path.exists(abs_path):
                # If new_data is a dict or list with keys/items to selectively remove,
                # or if it's empty/none, delete the whole file.
                if isinstance(new_data, (dict, list)) and len(new_data) > 0:
                    existing_data = self._read_file(abs_path, ext)
                    modified = False
                    if isinstance(existing_data, dict) and isinstance(
                        new_data, dict
                    ):
                        for k in list(new_data.keys()):
                            if k in existing_data:
                                del existing_data[k]
                                modified = True
                    elif isinstance(existing_data, list) and isinstance(
                        new_data, list
                    ):
                        for item in new_data:
                            if item in existing_data:
                                existing_data.remove(item)
                                modified = True

                    if modified:
                        new_content_str = self._serialize_content(
                            existing_data, ext
                        )
                        with open(abs_path, 'w', encoding='utf-8') as f:
                            f.write(new_content_str)
                        return True
                    return False
                else:
                    os.remove(abs_path)
                    return True
            return False

        existing_data = self._read_file(abs_path, ext)

        if self.state == 'overwrite':
            merged_data = new_data
        elif self.state == 'merge':
            if isinstance(existing_data, dict) and isinstance(new_data, dict):
                existing_data.update(new_data)
                merged_data = existing_data
            elif isinstance(existing_data, list) and isinstance(
                new_data, list
            ):
                existing_data.extend(new_data)
                merged_data = existing_data
            else:
                merged_data = new_data
        else:
            merged_data = new_data

        new_content_str = self._serialize_content(merged_data, ext)
        old_content_str = self._read_raw_file(abs_path)

        if new_content_str != old_content_str:
            with open(abs_path, 'w', encoding='utf-8') as f:
                f.write(new_content_str)
            return True
        return False

    def _read_file(self, abs_path, ext):
        if not os.path.exists(abs_path):
            return {}
        try:
            with open(abs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            if ext in ['.yml', '.yaml']:
                return yaml.safe_load(content) or {}
            elif ext == '.json':
                return json.loads(content) or {}
            elif ext == '.ini':
                parser = configparser.ConfigParser()
                parser.read_string(content)
                return {s: dict(parser.items(s)) for s in parser.sections()}
            else:
                return content
        except Exception:
            return {}

    def _read_raw_file(self, abs_path):
        if not os.path.exists(abs_path):
            return None
        with open(abs_path, 'r', encoding='utf-8') as f:
            return f.read()

    def _serialize_content(self, data, ext):
        if ext in ['.yml', '.yaml']:
            return yaml.safe_dump(
                data, default_flow_style=False, sort_keys=False
            )
        elif ext == '.json':
            return json.dumps(data, indent=2)
        elif ext == '.ini':
            parser = configparser.ConfigParser()
            if isinstance(data, dict):
                for section, vals in data.items():
                    parser.add_section(section)
                    if isinstance(vals, dict):
                        for k, v in vals.items():
                            parser.set(section, str(k), str(v))
            with io.StringIO() as sio:
                parser.write(sio)
                return sio.getvalue()
        else:
            return str(data)

    def _create_gitea_pr(self):
        # Extract API base URL from git_repo_url (supports ssh://git@host:port/owner/repo.git or https://...)
        try:
            repo_url = self.git_repo_url
            if repo_url.startswith("ssh://"):
                # ssh://git@repo.example.org:2222/ansible/demo-inventory.git
                without_proto = repo_url.replace("ssh://", "")
                host_port = without_proto.split("/")[0]
                host = host_port.split(":")[0]
                path_parts = without_proto.split("/")[1:]
                owner, repo = (
                    path_parts[-2],
                    path_parts[-1].replace(".git", ""),
                )
                api_url = f"https://{host}/api/v1/repos/{owner}/{repo}/pulls"
            else:
                api_url = repo_url.replace(".git", "") + "/api/v1/pulls"

            headers = {
                "Authorization": f"token {self.gitea_api_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "head": self.branch_name,
                "base": self.git_repo_branch,
                "title": f"Automated update for {self.branch_name}",
            }
            resp, info = fetch_url(
                self.module,
                api_url,
                data=json.dumps(payload),
                headers=headers,
                method="POST",
            )
            if info.get("status") in [200, 201]:
                res_json = json.loads(resp.read().decode('utf-8'))
                return res_json.get("html_url")
        except Exception as e:
            self.module.log(f"Failed to create Gitea PR: {str(e)}")
        return None


def main():
    argument_spec = dict(
        git_repo_url=dict(
            type='str', required=True, aliases=['repo_url', 'url']
        ),
        git_repo_branch=dict(
            type='str', default='main', aliases=['repo_branch', 'branch']
        ),
        branch_name=dict(type='str', required=True),
        content=dict(type='raw', required=True),
        state=dict(
            type='str',
            choices=['merge', 'overwrite', 'absent'],
            default='merge',
        ),
        git_comment_prefix=dict(type='str', default='INFRA'),
        post_gitea_pr=dict(type='bool', default=False),
        gitea_api_token=dict(type='str', no_log=True),
        ssh_params=dict(type='dict', default=dict()),
        logging_level=dict(
            type='str',
            default='INFO',
            choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR'],
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=False
    )

    manager = GitUpdateContentManager(module)
    manager.run()


if __name__ == '__main__':
    main()
