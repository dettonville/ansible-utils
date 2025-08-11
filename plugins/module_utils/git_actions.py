from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.dettonville.utils.plugins.module_utils.utils import PrettyLog
from ansible_collections.dettonville.utils.plugins.module_utils.messages import (
    FailingMessage,
)

__metaclass__ = type

import os
import sys
import re
import logging
import pprint
import traceback

# ref: https://discuss.python.org/t/pep-632-deprecate-distutils-module/5134/130?page=7
# from distutils.version import LooseVersion

# PEP
# ref: https://packaging.pypa.io/en/latest/version.html#packaging.version.Version
# from packaging.version import Version
try:
    from packaging.version import Version
except ImportError:
    PACKAGING_VERSION_IMPORT_ERROR = traceback.format_exc()
else:
    PACKAGING_VERSION_IMPORT_ERROR = None


_LOGLEVEL_DEFAULT = "INFO"


class Git:
    def __init__(self, module, repo_config):
        self.module = module

        self.loglevel = self.module.params.get("logging_level", _LOGLEVEL_DEFAULT)

        # # ref:
        # # https://www.tutorialexample.com/fix-python-logging-module-not-writing-to-file-python-tutorial/
        # for handler in logging.root.handlers[:]:
        #     logging.root.removeHandler(handler)
        #
        # #        console = self.log.StreamHandler()
        # #        console.setLevel(self.loglevel)
        # #        # add the handler to the root logger
        # #        self.log.getLogger().addHandler(console)

        logging.basicConfig(level=self.loglevel, stream=sys.stdout)
        self.log = logging.getLogger()

        self.git_bin_path = self.module.params.get(
            "executable"
        ) or self.module.get_bin_path("git")
        if not self.git_bin_path:
            module.fail_json(msg="Git executable not found in PATH.")

        log_prefix = "%s.init():" % self.__class__.__name__
        self.log.debug("%s repo_config => %s", log_prefix, PrettyLog(repo_config))

        self.repo_url = repo_config.get("repo_url")
        self.repo_dir = repo_config.get("repo_dir")

        # Fallback to get_url_scheme if repo_scheme is not explicitly provided
        self.repo_scheme = repo_config.get("repo_scheme")
        if not self.repo_scheme:
            self.repo_scheme = self.get_url_scheme(self.repo_url)

        self.repo_branch = repo_config.get("repo_branch")
        self.user_name = repo_config.get("user_name")
        self.user_email = repo_config.get("user_email")
        self.user_config = {}

        self.log.debug("%s self.git_bin_path=%s", log_prefix, self.git_bin_path)
        self.log.debug("%s self.repo_url=%s", log_prefix, self.repo_url)
        self.log.debug("%s self.repo_dir=%s", log_prefix, self.repo_dir)
        self.log.debug("%s self.repo_scheme=%s", log_prefix, self.repo_scheme)
        self.log.debug("%s self.repo_branch=%s", log_prefix, self.repo_branch)

        self.remote = repo_config.get("remote") or "origin"
        self.push_option = repo_config.get("push_option")
        self.user = repo_config.get("user")
        self.token = repo_config.get("token")

        self.ssh_key_file = None
        self.ssh_opts = ""
        self.ssh_accept_hostkey = False

        if self.user_name and self.user_email:
            self.user_config = {
                "name": self.user_name,
                "email": self.user_email,
            }

        ssh_params = repo_config.get("ssh_params")
        if ssh_params:
            self.ssh_key_file = ssh_params.get("key_file")
            self.ssh_opts = ssh_params.get("ssh_opts") or ""
            self.ssh_accept_hostkey = ssh_params.get("accept_hostkey", False)
            if self.ssh_accept_hostkey:
                if "-o StrictHostKeyChecking=no" not in self.ssh_opts:
                    self.ssh_opts += " -o StrictHostKeyChecking=no"

        # Ensure GIT_SSH_COMMAND is constructed and stored in an instance variable
        # so it can be passed to run_command later.
        self.git_ssh_command_env = {}  # Initialize an empty dict

        # Construct the GIT_SSH_COMMAND
        self.git_ssh_command = None
        if self.repo_scheme == "ssh":
            ssh_command_parts = ["ssh"]
            if self.ssh_key_file:
                ssh_command_parts.extend(["-i", self.ssh_key_file, "-o", "IdentitiesOnly=yes"])
            ssh_command_parts.extend(["-o", "BatchMode=yes"])
            if self.ssh_opts:
                ssh_command_parts.extend(self.ssh_opts.split())

            final_ssh_command = ' '.join([
                f"'{part}'" if ' ' in part and not (part.startswith("'") or part.startswith('"')) else part
                for part in ssh_command_parts
            ])
            self.git_ssh_command = final_ssh_command
            self.log.debug("Git class initialized with GIT_SSH_COMMAND: %s", self.git_ssh_command)

        # We screen scrape a huge amount of git commands so use C locale
        self.module.run_command_environ_update = dict(
            LANG="C", LC_ALL="C", LC_MESSAGES="C", LC_CTYPE="C"
        )
        if self.git_ssh_command:
            self.module.run_command_environ_update['GIT_SSH_COMMAND'] = self.git_ssh_command

    @staticmethod
    def get_url_scheme(url) -> str:
        # type: (str) -> Optional[str]
        scheme = "local"
        if url.startswith(("http://", "https://")):
            return "https"
        if url.startswith(("git@", "ssh://git@")):
            return "ssh"
        return scheme

    def execute_git_command(self, cmd, cwd=None, data=None, check_rc=True):
        log_prefix = "%s.execute_git_command():" % self.__class__.__name__

        if self.user_name:
            self.module.run_command_environ_update['GIT_AUTHOR_NAME'] = self.user_name
            self.module.run_command_environ_update['GIT_COMMITTER_NAME'] = self.user_name
        if self.user_email:
            self.module.run_command_environ_update['GIT_AUTHOR_EMAIL'] = self.user_email
            self.module.run_command_environ_update['GIT_COMMITTER_EMAIL'] = self.user_email

        git_cmd = [self.git_bin_path] + cmd

        self.log.info("%s Executing git command: %s with env: %s in cwd: %s", log_prefix, ' '.join(git_cmd), self.module.run_command_environ_update, cwd)

        try:
            rc, stdout, stderr = self.module.run_command(
                git_cmd,
                cwd=cwd,
                data=data,
                binary_data=True,
                check_rc=check_rc,
            )
            # Safely decode stdout, as it may already be a string or bytes
            decoded_stdout = stdout.decode('utf-8') if isinstance(stdout, bytes) else stdout
            decoded_stderr = stderr.decode('utf-8') if isinstance(stderr, bytes) else stderr

            self.log.debug("%s: rc=%d", log_prefix, rc)
            self.log.debug("%s: decoded_stdout=%s", log_prefix, decoded_stdout)
            self.log.debug("%s: decoded_stderr=%s", log_prefix, decoded_stderr)

            if rc != 0:
                FailingMessage(self.module, rc, git_cmd, stdout, stderr)
                # self.module.fail_json(msg=f"Failed to clone repository: {self.repo_url}", rc=rc, stdout=stdout, stderr=stderr)

            return rc, decoded_stdout, decoded_stderr
        except Exception as e:
            self.module.fail_json(
                msg=f"Failed to execute git command: {e}",
                cmd=" ".join(git_cmd),
                stderr=str(e),
            )

    def get_branches(self, dest) -> list:
        branches = []
        cmd = "branch --no-color -a"
        (rc, out, err) = self.execute_git_command(cmd, check_rc=True, cwd=dest)
        for line in out.split("\n"):
            if line.strip():
                branches.append(line.strip())
        return branches

    def git_version(self):
        """return the installed version of git"""
        cmd = "--version"
        (rc, out, err) = self.execute_git_command(cmd)
        rematch = re.search("git version (.*)$", to_native(out))
        if not rematch:
            return None

        if PACKAGING_VERSION_IMPORT_ERROR:
            self.module.fail_json(
                msg=missing_required_lib("packaging"),
                exception=PACKAGING_VERSION_IMPORT_ERROR,
            )
        # return LooseVersion(rematch.groups()[0])
        return Version(rematch.groups()[0])

    def get_annotated_tags(self, dest) -> list:
        tags = []
        cmd = [
            "for-each-ref",
            "refs/tags/",
            "--format",
            "%(objecttype):%(refname:short)",
        ]
        (rc, out, err) = self.execute_git_command(cmd, check_rc=True, cwd=dest)
        for line in to_native(out).split("\n"):
            if line.strip():
                tagtype, tagname = line.strip().split(":")
                if tagtype == "tag":
                    tags.append(tagname)
        return tags

    def set_user_config(self, user_config) -> dict:
        """
        Config git local user.name and user.email.

        args:
            * module:
                type: dict()
                description: Ansible basic module utilities and module arguments.
            * user_config:
                type: dict()
                description: Git user config for 'name' and 'email'
        return:
            * result:
                type: dict()
                description: updated changed status.
        """
        log_prefix = "%s.set_user_config():" % self.__class__.__name__
        self.log.debug("%s user_config => %s", log_prefix, PrettyLog(user_config))

        user_name = user_config.get("name")
        user_email = user_config.get("email")

        result = dict()

        current_user_name_rc, current_user_name, _stderr = self.execute_git_command(
            ['config', '--local', 'user.name', user_name],
            check_rc=False,
            cwd=self.repo_dir
        )
        current_user_email_rc, current_user_email, _stderr = self.execute_git_command(
            ['config', '--local', 'user.email', user_email],
            check_rc=False,
            cwd=self.repo_dir
        )

        # Set user.name if it's not already configured or if it's different from the desired value
        if current_user_name_rc != 0 or current_user_name.strip() != user_name:
            self.execute_git_command(
                ['config', '--local', 'user.name', user_name],
                check_rc=True,
                cwd=self.repo_dir
            )
            self.log.debug("%s Set git user.name to %s", log_prefix, user_name)

        # Set user.email if it's not already configured or if it's different from the desired value
        if current_user_email_rc != 0 or current_user_email.strip() != user_email:
            self.execute_git_command(
                ['config', '--local', 'user.email', user_email],
                check_rc=True,
                cwd=self.repo_dir
            )
            self.log.debug("%s Set git user.email to %s", log_prefix, user_email)

        # result.update({"message": stdout, "changed": True})
        result.update({"changed": True, "message": "Git user configuration updated."})
        return result

    def clone(self, shallow=True, bare=False, reference=None, refspec=None) -> dict:
        """makes a new git repo if it does not already exist"""
        log_prefix = "%s.clone(%s):" % (self.__class__.__name__, self.repo_dir)

        self.log.debug("%s started", log_prefix)

        try:
            os.makedirs(os.path.dirname(self.repo_dir))
        except OSError:
            pass
        command = ["clone"]

        # ref:
        # https://stackoverflow.com/questions/1911109/how-do-i-clone-a-specific-git-branch
        command.extend(["--single-branch", "--branch", self.repo_branch])

        # ref:
        # https://stackoverflow.com/questions/26957237/how-to-make-git-clone-faster-with-multiple-threads#26957305
        if shallow:
            command.append("--depth=1")

        if bare:
            command.append("--bare")
        else:
            command.extend(["--origin", self.remote])

        if reference:
            command.extend(["--reference", str(reference)])

        result = dict()

        command.extend([self.repo_url, self.repo_dir])

        self.log.debug("%s command=%s", log_prefix, command)

        rc, stdout, stderr = self.execute_git_command(
            command, check_rc=True, cwd=self.repo_dir
        )

        result.update({"message": stdout, "git.clone": str(stdout) + str(stderr), "changed": True})

        if bare and self.remote != "origin":
            self.execute_git_command(
                ["remote", "add", self.remote, self.repo_url],
                check_rc=True,
                cwd=self.repo_dir,
            )

        if refspec:
            command = ["fetch"]
            command.extend([self.remote, refspec])
            self.execute_git_command(command, check_rc=True, cwd=self.repo_dir)

        self.log.debug("%s result => %s", log_prefix, pprint.pformat(result))
        return result

    def pull(self) -> dict:
        """pull git repo"""
        log_prefix = "%s.pull():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        command = ["pull"]
        command.extend([self.remote, "--ff", self.repo_branch])

        result = dict()

        # self.log.info('%s command=%s' % (log_prefix, command))
        self.log.debug("%s command=%s", log_prefix, command)

        rc, stdout, stderr = self.execute_git_command(
            command, check_rc=True, cwd=self.repo_dir
        )

        result.update({"message": stdout, "git.pull": str(stdout) + str(stderr), "changed": True})

        self.log.debug("%s result => %s", log_prefix, pprint.pformat(result))
        return result

    def add(self, add_files=None) -> dict:
        """
        Run git add and stage changed files.

        args:
            * module:
                type: dict()
                descrition: Ansible basic module utilities and module arguments.

        return: null
        """
        log_prefix = "%s.add():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        if add_files is None:
            add_files = ["."]

        # FIX for older git versions (on awx control node => version 1.8.3.1)
        command = ["add", "--all"]

        command.extend(add_files)

        result = dict()

        self.log.debug("%s command => %s", log_prefix, command)

        rc, stdout, stderr = self.execute_git_command(command, check_rc=True, cwd=self.repo_dir)

        result.update({"message": stdout, "git.add": str(stdout) + str(stderr), "changed": True})

        self.log.debug("%s result => %s", log_prefix, pprint.pformat(result))

        return result

    def status(self) -> set:
        """
        Run git status and check if repo has changes.

        args:
            * module:
                type: dict()
                descrition: Ansible basic module utilities and module arguments.
        return:
            * data:
                type: set()
                description: list of files changed in repo.
        """
        log_prefix = "%s.status():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        data = set()
        command = ["status", "--porcelain"]

        self.log.debug("%s command => %s", log_prefix, command)

        rc, stdout, stderr = self.execute_git_command(command, check_rc=True, cwd=self.repo_dir)

        if rc == 0:
            for line in stdout.split("\n"):
                file_name = line.split(" ")[-1].strip()
                if file_name:
                    data.add(file_name)
            return data

        else:
            FailingMessage(self.module, rc, command, stdout, stderr)

    def commit(self, comment="ansible update") -> dict:
        """
        Run git commit and commit files in repo.

        args:
            * module:
                type: dict()
                descrition: Ansible basic module utilities and module arguments.
        return:
            * result:
                type: dict()
                description: returned stdout from git commit command and changed status
        """
        log_prefix = "%s.commit():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        result = dict()
        command = ["commit", "-m", comment]

        self.log.debug("%s command => %s", log_prefix, command)

        rc, stdout, stderr = self.execute_git_command(command, check_rc=True, cwd=self.repo_dir)

        result.update({"message": stdout, "git.commit": str(stdout) + str(stderr), "changed": True})

        self.log.debug("%s result => %s", log_prefix, pprint.pformat(result))

        return result

    def push(self) -> dict:
        """
        Set URL and remote if required. Push changes to remote repo.

        args:
            * module:
                type: dict()
                descrition: Ansible basic module utilities and module arguments.
        return:
            * result:
                type: dict()
                description: returned stdout from git push command and updated changed status.
        """
        log_prefix = "%s.push():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        command = ["push", self.remote, self.repo_branch]

        def set_url() -> dict:
            """
            Set URL and remote if required.

            args:
                * module:
                    type: dict()
                    descrition: Ansible basic module utilities and module arguments.
            return: null
            """
            cmd = ["remote", "get-url", "--all", self.remote]

            rc, _stdout, _stderr = self.execute_git_command(cmd, check_rc=True, cwd=self.repo_dir)

            if rc == 0:
                return

            if rc == 128:
                if self.repo_scheme == "https":
                    if self.repo_url.startswith("https://"):
                        cmd = [
                            "remote",
                            "add",
                            self.remote,
                            "https://{0}:{1}@{2}".format(
                                self.user, self.token, self.repo_url[8:]
                            ),
                        ]
                    else:
                        self.module.fail_json(
                            msg="HTTPS scheme selected but not HTTPS URL provided"
                        )
                else:
                    cmd = [
                        "remote",
                        "add",
                        self.remote,
                        self.repo_url,
                    ]

                rc, stdout, stderr = self.execute_git_command(cmd, check_rc=True, cwd=self.repo_dir)

                if rc == 0:
                    return
                else:
                    FailingMessage(self.module, rc, cmd, stdout, stderr)

        def push_cmd() -> dict:
            """
            Set URL and remote if required. Push changes to remote repo.

            args:
                * path:
                    type: path
                    descrition: git repo local path.
                * cmd_push:
                    type: list()
                    descrition: list of commands to perform git push operation.
            return:
                * result:
                    type: dict()
                    description: returned stdout from git push command and updated changed status.
            """
            result = dict()

            rc, stdout, stderr = self.execute_git_command(command, check_rc=True, cwd=self.repo_dir)

            if rc == 0:
                result.update(
                    {
                        "message": stdout,
                        "git.push": str(stderr) + str(stdout),
                        "changed": True,
                    }
                )
                return result
            else:
                FailingMessage(self.module, rc, command, stdout, stderr)

        if self.push_option:
            command.insert(3, "--push-option={0} ".format(self.push_option))

        set_url()

        return push_cmd()
