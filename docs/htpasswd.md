

```shell
$ ansible --version
ansible [core 2.20.1]
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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.htpasswd | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/htpasswd.md
> MODULE dettonville.utils.htpasswd (/Users/ljohnson/tmp/_8dDQgK/ansible_collections/dettonville/utils/plugins/modules/htpasswd.py)

  Add and remove username/password entries in a password file using
  htpasswd.
  Supports managing a single user or a list of users in a single task
  execution.
  Supports adding, updating, and removing users using different
  password encryption algorithms.
  Adds `backup' capability before modifying target htpasswd files.
  Adds `overwrite' capability to remove residue/unmanaged entries left
  over from prior runs.
  Supports standard file attribute management (owner, group, mode,
  secontext).

OPTIONS (= indicates it is required):

- attributes  The attributes the resulting filesystem object should
               have.
               To get supported flags look at the man page for
               `chattr' on the target system.
               This string should contain the attributes in the same
               order as the one displayed by `lsattr'.
               The `=' operator is assumed as default, otherwise `+'
               or `-' operators need to be included in the string.
        aliases: [attr]
        default: null
        type: str

- backup  Create a backup file including timestamp information before
           modifying.
        default: false
        type: bool

- create  Used with `state=present'. If `true', the file is created
           if it does not exist.
        default: true
        type: bool

- group   Name of the group that should own the filesystem object, as
           would be fed to `chown'.
           When left unspecified, it uses the current group of the
           current user unless you are root, in which case it can
           preserve the previous ownership.
           Specifying a numeric group name (for example, "1000") will
           be assumed to be a group ID (GID) and not a group name. To
           prevent confusion, avoid using purely numeric group names.
        default: null
        type: str

- hash_scheme  Encryption algorithm scheme to use when hashing
                passwords.
        aliases: [crypt_scheme]
        default: apr_md5_crypt
        type: str

- mode    The permissions the resulting filesystem object should
           have.
           For those used to `/usr/bin/chmod' remember that modes are
           actually octal numbers. You must give Ansible enough
           information to parse them correctly. For consistent
           results, quote octal numbers (for example, `'644'' or
           `'1777'') so Ansible receives a string and can do its own
           conversion from string into number. Adding a leading zero
           (for example, `0755') works sometimes, but can fail in
           loops and some other circumstances.
           Giving Ansible a number without following either of these
           rules will end up with a decimal number which will have
           unexpected results.
           As of Ansible 1.8, the mode may be specified as a symbolic
           mode (for example, `u+rwx' or `u=rw,g=r,o=r').
           If `mode' is not specified and the destination filesystem
           object *does not* exist, the default `umask' on the system
           will be used when setting the mode for the newly created
           filesystem object.
           If `mode' is not specified and the destination filesystem
           object *does* exist, the mode of the existing filesystem
           object will be used.
           Specifying `mode' is the best way to ensure filesystem
           objects are created with the correct permissions. See
           CVE-2020-1736 for further details.
        default: null
        type: raw

- name    User name to add, update, or remove.
           Mutually exclusive with `user_list'.
           Required when `user_list' is not provided and
           `state=absent' or when adding/updating a single user.
        aliases: [username]
        default: null
        type: str

- overwrite  When `true' and `state=present', purges any entries from
              the htpasswd file that are not explicitly defined in the
              task execution.
        default: false
        type: bool

- owner   Name of the user that should own the filesystem object, as
           would be fed to `chown'.
           When left unspecified, it uses the current user unless you
           are root, in which case it can preserve the previous
           ownership.
           Specifying a numeric username (for example, "1000") will be
           assumed to be a user ID (UID) and not a username. To
           prevent confusion, avoid using purely numeric usernames.
        default: null
        type: str

- password  Password associated with `name'.
             Required when `state=present', `name' is provided, and
             `user_list' is not used.
        default: null
        type: str

= path    Path to the htpasswd file.
        aliases: [dest, destfile]
        type: path

- selevel  The level part of the SELinux filesystem object context.
            This is the MLS/MCS attribute, sometimes known as the
            `range'.
            When set to `_default', it will use the `level' portion of
            the policy if available.
        default: null
        type: str

- serole  The role part of the SELinux filesystem object context.
           When set to `_default', it will use the `role' portion of
           the policy if available.
        default: null
        type: str

- setype  The type part of the SELinux filesystem object context.
           When set to `_default', it will use the `type' portion of
           the policy if available.
        default: null
        type: str

- seuser  The user part of the SELinux filesystem object context.
           By default it uses the `system' policy, where applicable.
           When set to `_default', it will use the `user' portion of
           the policy if available.
        default: null
        type: str

- state   Whether the specified entry or entries should be present or
           absent.
        choices: [present, absent]
        default: present
        type: str

- unsafe_writes  Influence when to use atomic operation to prevent
                  data corruption or inconsistent reads from the
                  target filesystem object.
                  By default this module uses atomic operations to
                  prevent data corruption or inconsistent reads from
                  the target filesystem objects, but sometimes systems
                  are configured or just broken in ways that prevent
                  this. One example is docker mounted filesystem
                  objects, which cannot be updated atomically from
                  inside the container and can only be written in an
                  unsafe manner.
                  This option allows Ansible to fall back to unsafe
                  methods of updating filesystem objects when atomic
                  operations fail (however, it doesn't force Ansible
                  to perform unsafe writes).
                  IMPORTANT! Unsafe writes are subject to race
                  conditions and can lead to data corruption.
        default: false
        type: bool

- user_list  A list of user dictionaries to manage.
              Each dictionary in the list must contain `username' and
              `password' keys.
              Mutually exclusive with `name' and `password'.
        default: null
        elements: dict
        type: list

REQUIREMENTS:  passlib >= 1.6


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
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

RETURN VALUES:

- backup_file  Name of the backup file created.
        returned: when backup=true and changes were made
        sample: /etc/nginx/.htpasswd.2026-07-23@15:00:00~
        type: str

```
