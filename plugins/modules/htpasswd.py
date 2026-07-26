#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Lee Johnson (@lj020326)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: htpasswd
short_description: Manage user credentials in an htpasswd file with backup and overwrite support
version_added: "2.20.0"
author:
  - Lee Johnson (@lj020326)
description:
  - Add and remove username/password entries in a password file using htpasswd.
  - Supports managing a single user or a list of users in a single task execution.
  - Supports adding, updating, and removing users using different password encryption algorithms.
  - Adds C(backup) capability before modifying target htpasswd files.
  - Adds C(overwrite) capability to remove residue/unmanaged entries left over from prior runs.
  - Supports standard file attribute management (owner, group, mode, secontext).
options:
  path:
    description:
      - Path to the htpasswd file.
    type: path
    required: true
    aliases: [ dest, destfile ]
  name:
    description:
      - User name to add, update, or remove.
      - Mutually exclusive with C(user_list).
      - Required when C(user_list) is not provided and C(state=absent) or when adding/updating a single user.
    type: str
    aliases: [ username ]
  password:
    description:
      - Password associated with C(name).
      - Required when C(state=present), C(name) is provided, and C(user_list) is not used.
    type: str
  user_list:
    description:
      - A list of user dictionaries to manage.
      - Each dictionary in the list must contain C(username) and C(password) keys.
      - Mutually exclusive with C(name) and C(password).
    type: list
    elements: dict
  hash_scheme:
    description:
      - Encryption algorithm scheme to use when hashing passwords.
    type: str
    default: apr_md5_crypt
    aliases: [ crypt_scheme ]
  state:
    description:
      - Whether the specified entry or entries should be present or absent.
    type: str
    default: present
    choices: [ present, absent ]
  create:
    description:
      - Used with C(state=present). If C(true), the file is created if it does not exist.
    type: bool
    default: true
  backup:
    description:
      - Create a backup file including timestamp information before modifying.
    type: bool
    default: false
  overwrite:
    description:
      - When C(true) and C(state=present), purges any entries from the htpasswd file
        that are not explicitly defined in the task execution.
    type: bool
    default: false
extends_documentation_fragment:
  - ansible.builtin.files
requirements:
  - passlib >= 1.6
"""

EXAMPLES = r"""
- name: Add a single user to an htpasswd file
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    name: admin
    password: SuperSecretPassword123!
    hash_scheme: apr_md5_crypt
    owner: root
    group: www-data
    mode: '0640'

- name: Add user and backup existing file before making changes
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    name: devuser
    password: Password456!
    backup: true

- name: Enforce strict file contents by overwriting residue from prior runs
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    name: sole_user
    password: Password789!
    overwrite: true

- name: Remove a user from htpasswd file
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    name: devuser
    state: absent

- name: Populate multiple users from a list with overwrite enabled
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    user_list:
      - username: alice
        password: AlicePassword123!
      - username: bob
        password: BobPassword456!
    crypt_scheme: bcrypt
    overwrite: true
    backup: true

- name: Remove a single user from htpasswd file
  dettonville.utils.htpasswd:
    path: /etc/nginx/.htpasswd
    name: devuser
    state: absent
"""

RETURN = r"""
backup_file:
  description: Name of the backup file created.
  type: str
  returned: when backup=true and changes were made
  sample: /etc/nginx/.htpasswd.2026-07-23@15:00:00~
"""

import os
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

HAS_PASSLIB = False
try:
    from passlib.apache import HtpasswdFile, htpasswd_context
    from passlib.context import CryptContext

    HAS_PASSLIB = True
except ImportError:
    HAS_PASSLIB = False

APACHE_HASHES = ["apr_md5_crypt", "des_crypt", "ldap_sha1", "plaintext"]


def obtain_crypt_context(hash_scheme):
    if hash_scheme in APACHE_HASHES or hash_scheme in htpasswd_context.schemes():
        return htpasswd_context
    try:
        return CryptContext(schemes=[hash_scheme] + APACHE_HASHES)
    except KeyError:
        return htpasswd_context


def create_missing_directories(dest):
    destpath = os.path.dirname(dest)
    if destpath and not os.path.exists(destpath):
        os.makedirs(destpath)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path', required=True, aliases=['dest', 'destfile']),
            name=dict(type='str', aliases=['username']),
            password=dict(type='str', no_log=True),
            user_list=dict(type='list', elements='dict', no_log=True),
            hash_scheme=dict(
                type='str', default='apr_md5_crypt', aliases=['crypt_scheme']
            ),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            create=dict(type='bool', default=True),
            backup=dict(type='bool', default=False),
            overwrite=dict(type='bool', default=False),
        ),
        mutually_exclusive=[
            ('name', 'user_list'),
            ('password', 'user_list'),
        ],
        add_file_common_args=True,
        supports_check_mode=True,
    )

    if not HAS_PASSLIB:
        module.fail_json(msg=missing_required_lib('passlib'))

    path = module.params['path']
    username = module.params.get('name')
    password = module.params.get('password')
    user_list = module.params.get('user_list')
    hash_scheme = module.params['hash_scheme']
    state = module.params['state']
    create = module.params['create']
    backup = module.params['backup']
    overwrite = module.params['overwrite']
    check_mode = module.check_mode

    target_users = []

    if user_list:
        for idx, entry in enumerate(user_list):
            if not isinstance(entry, dict):
                module.fail_json(
                    msg=f"Item at index {idx} in 'user_list' must be a dictionary"
                )
            u_name = entry.get('username') or entry.get('name')
            u_pass = entry.get('password')
            if not u_name:
                module.fail_json(
                    msg=f"Item at index {idx} in 'user_list' missing required key 'username'"
                )
            if state == 'present' and u_pass is None:
                module.fail_json(
                    msg=f"Item at index {idx} ('{u_name}') in 'user_list' missing required key 'password'"
                )
            target_users.append({'username': u_name, 'password': u_pass})
    elif username:
        if state == 'present' and password is None:
            module.fail_json(
                msg="parameter 'password' required when state=present and name is provided"
            )
        target_users.append({'username': username, 'password': password})
    else:
        if state == 'present' and not overwrite:
            module.fail_json(
                msg="Either 'name'/'password' or 'user_list' must be specified when state=present"
            )
        elif state == 'absent':
            module.fail_json(
                msg="Either 'name' or 'user_list' must be specified when state=absent"
            )

    context = obtain_crypt_context(hash_scheme)
    file_exists = os.path.exists(path)
    changed = False
    backup_file = None
    messages = []

    # Clean blank lines from file if present
    if file_exists:
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            if any(not line.strip() for line in lines):
                if not check_mode:
                    with open(path, 'w') as f:
                        f.writelines(line for line in lines if line.strip())
        except OSError as e:
            module.fail_json(msg=f"Error reading file {path}: {str(e)}")

    if state == 'present':
        if not file_exists:
            if not create:
                module.fail_json(
                    msg=f"Destination {path} does not exist and create=false"
                )
            if not check_mode:
                create_missing_directories(path)
            ht = HtpasswdFile(
                path, new=True, default_scheme=hash_scheme, context=context
            )
            changed = True
            messages.append(f"Created {path}")
        else:
            ht = HtpasswdFile(
                path, new=False, default_scheme=hash_scheme, context=context
            )

        valid_usernames = {user['username'] for user in target_users}

        # Overwrite mode: prune users not present in the defined list
        if overwrite:
            for existing_user in list(ht.users()):
                if existing_user not in valid_usernames:
                    if not check_mode:
                        ht.delete(existing_user)
                    changed = True
                    messages.append(f"Removed unmanaged user {existing_user}")

        # Process adding/updating all target users
        for user_data in target_users:
            u_name = user_data['username']
            u_pass = user_data['password']

            password_valid = (u_name in ht.users()) and ht.check_password(
                u_name, u_pass
            )
            if not password_valid:
                if not check_mode:
                    ht.set_password(u_name, u_pass)
                changed = True
                messages.append(f"Added/updated {u_name}")

    elif state == 'absent':
        if not file_exists:
            module.exit_json(msg=f"{path} does not exist", changed=False)

        ht = HtpasswdFile(path, new=False, default_scheme=hash_scheme, context=context)
        for user_data in target_users:
            u_name = user_data['username']
            if u_name in ht.users():
                if not check_mode:
                    ht.delete(u_name)
                changed = True
                messages.append(f"Removed {u_name}")

    # Create backup if file exists and changes occurred
    if changed and backup and file_exists:
        backup_file = module.backup_local(path)

    # Save changes to file
    if changed and not check_mode:
        try:
            ht.save()
        except Exception as e:
            module.fail_json(msg=f"Failed to write htpasswd file to {path}: {str(e)}")

    # Handle standard Ansible file ownership, perms, secontext attributes
    file_args = module.load_file_common_arguments(module.params)
    if module.set_fs_attributes_if_different(file_args, False):
        changed = True
        messages.append("Ownership/permissions updated")

    result = {
        'changed': changed,
        'msg': ", ".join(messages) if messages else "No changes required",
        'path': path,
    }

    if backup_file:
        result['backup_file'] = backup_file

    module.exit_json(**result)


if __name__ == '__main__':
    main()
