from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.six import b
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    PrettyLog
)
from ansible_collections.dettonville.utils.plugins.module_utils.messages import (
    FailingMessage
)

__metaclass__ = type

import os
import sys
import stat
import re
import tempfile
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

        self.git_bin_path = self.module.params.get("executable") or self.module.get_bin_path("git")

        log_prefix = "%s.init():" % self.__class__.__name__
        self.log.debug(
            "%s repo_config => %s", log_prefix, PrettyLog(repo_config)
        )

        self.repo_url = repo_config.get("repo_url")
        self.repo_dir = repo_config.get("repo_dir")
        self.repo_scheme = repo_config.get("repo_scheme", self.get_url_scheme(self.repo_url))
        self.repo_branch = repo_config.get("repo_branch")

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
        self.ssh_opts = None
        self.ssh_accept_hostkey = False
        self.user_config = {}

        ssh_params = repo_config.get("ssh_params", None)

        if ssh_params:
            self.ssh_key_file = (
                ssh_params["key_file"] if "key_file" in ssh_params else None
            )
            self.ssh_opts = ssh_params["ssh_opts"] if "ssh_opts" in ssh_params else None
            self.ssh_accept_hostkey = (
                ssh_params["accept_hostkey"]
                if "accept_hostkey" in ssh_params
                else False
            )

            if self.ssh_accept_hostkey:
                if self.ssh_opts is not None:
                    if "-o StrictHostKeyChecking=no" not in self.ssh_opts:
                        self.ssh_opts += " -o StrictHostKeyChecking=no"
                else:
                    self.ssh_opts = "-o StrictHostKeyChecking=no"

        # We screen scrape a huge amount of git commands so use C
        # locale anytime we call run_command()
        self.module.run_command_environ_update = dict(
            LANG="C", LC_ALL="C", LC_MESSAGES="C", LC_CTYPE="C"
        )

        if self.repo_scheme == "local":
            if self.repo_url.startswith(("https://", "git", "ssh://git")):
                self.module.fail_json(
                    msg='SSH or HTTPS scheme selected but repo is "local'
                )

            if ssh_params:
                self.module.warn(
                    'SSH Parameters will be ignored as scheme "local"')

        elif self.repo_scheme == "https":
            if not self.repo_url.startswith("https://"):
                self.module.fail_json(
                    msg="HTTPS scheme selected but url ("
                    + self.repo_url
                    + ') not starting with "https"'
                )
            if ssh_params:
                self.module.warn(
                    'SSH Parameters will be ignored as scheme "https"')

        elif self.repo_scheme == "ssh":
            if not self.repo_url.startswith(("git", "ssh://git")):
                self.module.fail_json(
                    "SSH scheme selected but url ("
                    + self.repo_url
                    + ') not starting with "git" or "ssh://git"'
                )

            if self.repo_url.startswith("ssh://git@github.com"):
                self.module.fail_json(
                    'GitHub does not support "ssh://" URL. Please remove it from url'
                )

            self.ssh_wrapper = self.write_ssh_wrapper(self.module.tmpdir)
            self.set_git_ssh(self.ssh_wrapper, self.ssh_key_file, self.ssh_opts)
            self.module.add_cleanup_file(path=self.ssh_wrapper)

    @staticmethod
    def get_url_scheme(url) -> str:
        # type: (str) -> Optional[str]
        scheme = "local"
        if "://" in url:
            scheme = url.split("://", 1)[0].lower()
        if url.startswith("git"):
            scheme = "ssh"
        return scheme

    def write_ssh_wrapper(self, module_tmpdir):
        try:
            # make sure we have full permission to the module_dir, which
            # may not be the case if we're sudo'ing to a non-root user
            if os.access(module_tmpdir, os.W_OK | os.R_OK | os.X_OK):
                fd, wrapper_path = tempfile.mkstemp(prefix=module_tmpdir + "/")
            else:
                raise OSError
        except (IOError, OSError):
            fd, wrapper_path = tempfile.mkstemp()

        fh = os.fdopen(fd, "w+b")
        template = b(
            """#!/bin/sh
if [ -z "$GIT_SSH_OPTS" ]; then
    BASEOPTS=""
else
    BASEOPTS=$GIT_SSH_OPTS
fi

# Let ssh fail rather than prompt
BASEOPTS="$BASEOPTS -o BatchMode=yes"

if [ -z "$GIT_KEY" ]; then
    ssh $BASEOPTS "$@"
else
    ssh -i "$GIT_KEY" -o IdentitiesOnly=yes $BASEOPTS "$@"
fi
"""
        )
        fh.write(template)
        fh.close()
        st = os.stat(wrapper_path)
        os.chmod(wrapper_path, st.st_mode | stat.S_IEXEC)
        return wrapper_path

    def set_git_ssh(self, ssh_wrapper, key_file, ssh_opts):
        if os.environ.get("GIT_SSH"):
            del os.environ["GIT_SSH"]
        os.environ["GIT_SSH"] = ssh_wrapper

        if os.environ.get("GIT_KEY"):
            del os.environ["GIT_KEY"]

        if key_file:
            os.environ["GIT_KEY"] = key_file

        if os.environ.get("GIT_SSH_OPTS"):
            del os.environ["GIT_SSH_OPTS"]

        if ssh_opts:
            os.environ["GIT_SSH_OPTS"] = ssh_opts

    def get_branches(self, dest) -> list:
        branches = []
        cmd = "%s branch --no-color -a" % (self.git_bin_path,)
        (rc, out, err) = self.module.run_command(cmd, cwd=dest)
        if rc != 0:
            self.module.fail_json(
                msg="Could not determine branch data - received %s" % out,
                stdout=out,
                stderr=err,
            )
        for line in out.split("\n"):
            if line.strip():
                branches.append(line.strip())
        return branches

    def git_version(self):
        """return the installed version of git"""
        cmd = "%s --version" % self.git_bin_path
        (rc, out, err) = self.module.run_command(cmd)
        if rc != 0:
            # one could fail_json here, but the version info is not that important,
            # so let's try to fail only on actual git commands
            return None
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
            self.git_bin_path,
            "for-each-ref",
            "refs/tags/",
            "--format",
            "%(objecttype):%(refname:short)",
        ]
        (rc, out, err) = self.module.run_command(cmd, cwd=dest)
        if rc != 0:
            self.module.fail_json(
                msg="Could not determine tag data - received %s" % out,
                stdout=out,
                stderr=err,
            )
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
        parameters = ["name", "email"]
        result = dict()

        self.user_config = user_config

        for parameter in parameters:
            if self.user_config[parameter]:
                config_parameter = self.user_config[parameter]
            else:
                config_parameter = self.module.params.get(
                    "user_{0}".format(parameter))

            if config_parameter:
                command = [
                    self.git_bin_path,
                    "config",
                    "--local",
                    "user.{0}".format(parameter),
                ]
                _rc, output, _error = self.module.run_command(
                    command, cwd=self.repo_dir
                )

                if output != config_parameter:
                    command.append(config_parameter)
                    _rc, output, _error = self.module.run_command(
                        command, cwd=self.repo_dir
                    )

                    result.update({"message": output, "changed": True})

        return result

    def clone(self, shallow=True, bare=False, reference=None, refspec=None) -> dict:
        """makes a new git repo if it does not already exist"""
        log_prefix = "%s.clone(%s):" % (self.__class__.__name__, self.repo_dir)

        self.log.debug("%s started", log_prefix)

        try:
            os.makedirs(os.path.dirname(self.repo_dir))
        except OSError:
            pass
        command = [self.git_bin_path, "clone"]

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

        rc, output, error = self.module.run_command(
            command, check_rc=True, cwd=self.repo_dir
        )

        if bare and self.remote != "origin":
            self.module.run_command(
                [self.git_bin_path, "remote", "add", self.remote, self.repo_url],
                check_rc=True,
                cwd=self.repo_dir,
            )

        if refspec:
            command = [self.git_bin_path, "fetch"]
            command.extend([self.remote, refspec])
            self.module.run_command(command, check_rc=True, cwd=self.repo_dir)

        if rc == 0:
            if output:
                result.update(
                    {"message": output, "git.clone": output, "changed": True})
        else:
            FailingMessage(self.module, rc, command, output, error)

        self.log.debug("%s result => %s", log_prefix, pprint.pformat(result))
        return result

    def pull(self) -> dict:
        """pull git repo"""
        log_prefix = "%s.pull():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        command = [self.git_bin_path, "pull"]
        command.extend([self.remote, self.repo_branch])

        result = dict()

        # self.log.info('%s command=%s' % (log_prefix, command))
        self.log.debug("%s command=%s", log_prefix, command)

        rc, output, error = self.module.run_command(
            command, check_rc=True, cwd=self.repo_dir
        )

        if rc == 0:
            if output:
                result.update(
                    {"message": output, "git.pull": output, "changed": True})
        else:
            FailingMessage(self.module, rc, command, output, error)

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
        # command = [self.git_bin_path, 'add', '--']
        command = [self.git_bin_path, "add", "--all"]

        command.extend(add_files)

        result = dict()

        self.log.debug("%s command => %s", log_prefix, command)

        rc, output, error = self.module.run_command(command, cwd=self.repo_dir)

        if rc == 0:
            if output:
                result.update(
                    {"message": output, "git.add": output, "changed": True})
        else:
            FailingMessage(self.module, rc, command, output, error)

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
        command = [self.git_bin_path, "status", "--porcelain"]

        self.log.debug("%s command => %s", log_prefix, command)

        rc, output, error = self.module.run_command(command, cwd=self.repo_dir)

        if rc == 0:
            for line in output.split("\n"):
                file_name = line.split(" ")[-1].strip()
                if file_name:
                    data.add(file_name)
            return data

        else:
            FailingMessage(self.module, rc, command, output, error)

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
                description: returned output from git commit command and changed status
        """
        log_prefix = "%s.commit():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        result = dict()
        command = [self.git_bin_path, "commit", "-m", comment]

        self.log.debug("%s command => %s", log_prefix, command)

        rc, output, error = self.module.run_command(command, cwd=self.repo_dir)

        if rc == 0:
            if output:
                result.update(
                    {"message": output, "git.commit": output, "changed": True}
                )
        else:
            FailingMessage(self.module, rc, command, output, error)

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
                description: returned output from git push command and updated changed status.
        """
        log_prefix = "%s.push():" % self.__class__.__name__

        self.log.debug("%s started", log_prefix)

        command = [self.git_bin_path, "push", self.remote, self.repo_branch]

        def set_url() -> dict:
            """
            Set URL and remote if required.

            args:
                * module:
                    type: dict()
                    descrition: Ansible basic module utilities and module arguments.
            return: null
            """
            cmd = [
                self.git_bin_path,
                "remote",
                "get-url",
                "--all",
                self.remote]

            rc, _output, _error = self.module.run_command(
                cmd, cwd=self.repo_dir)

            if rc == 0:
                return

            if rc == 128:
                if self.repo_scheme == "https":
                    if self.repo_url.startswith("https://"):
                        cmd = [
                            self.git_bin_path,
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
                        self.git_bin_path,
                        "remote",
                        "add",
                        self.remote,
                        self.repo_url,
                    ]

                rc, output, error = self.module.run_command(
                    cmd, cwd=self.repo_dir)

                if rc == 0:
                    return
                else:
                    FailingMessage(self.module, rc, cmd, output, error)

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
                    description: returned output from git push command and updated changed status.
            """
            result = dict()

            rc, output, error = self.module.run_command(
                command, cwd=self.repo_dir)

            if rc == 0:
                result.update(
                    {
                        "message": output,
                        "git.push": str(error) + str(output),
                        "changed": True,
                    }
                )
                return result
            else:
                FailingMessage(self.module, rc, command, output, error)

        if self.push_option:
            command.insert(3, "--push-option={0} ".format(self.push_option))

        set_url()

        return push_cmd()
