# -*- coding: utf-8 -*-

from unittest.mock import MagicMock, patch

# noinspection PyPackageRequirements
import pytest

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.modules import htpasswd

# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.tests.unit.plugins.modules.utils import (  # noqa: E501
    MODULES_IMPORT_PATH,
    AnsibleExitJson,
    exit_json,
    fail_json,
    make_absolute,
)


@pytest.fixture
def mock_ansible_module():
    """Fixture to mock AnsibleModule functionality."""

    def _generator(params, check_mode=False):
        mock = MagicMock()
        mock.params = params
        mock.check_mode = check_mode
        mock.backup_local.return_value = f"{params.get('path')}.2026-07-23.bak"
        mock.load_file_common_arguments.return_value = {}
        mock.set_fs_attributes_if_different.return_value = False

        mock.exit_json.side_effect = exit_json
        mock.fail_json.side_effect = fail_json
        return mock

    return _generator


@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HAS_PASSLIB"), True)
@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HtpasswdFile"))
@patch("builtins.open")
@patch("os.path.exists", return_value=True)
def test_htpasswd_add_user(
    mock_exists, mock_open, mock_htfile_cls, mock_ansible_module
):
    """Test adding a user to an existing file."""
    mock_htfile = MagicMock()
    mock_htfile.users.return_value = []
    mock_htfile.check_password.return_value = False
    mock_htfile_cls.return_value = mock_htfile

    params = {
        "path": "/tmp/.htpasswd",
        "name": "alice",
        "password": "secretpassword",
        "hash_scheme": "apr_md5_crypt",
        "state": "present",
        "create": True,
        "backup": False,
        "overwrite": False,
    }

    module_mock = mock_ansible_module(params)
    with patch(
        make_absolute(MODULES_IMPORT_PATH, "htpasswd.AnsibleModule"),
        return_value=module_mock,
    ):
        with pytest.raises(AnsibleExitJson) as exc_info:
            htpasswd.main()

    res = exc_info.value.kwargs
    assert res["changed"] is True
    mock_htfile.set_password.assert_called_once_with("alice", "secretpassword")
    mock_htfile.save.assert_called_once()


@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HAS_PASSLIB"), True)
@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HtpasswdFile"))
@patch("builtins.open")
@patch("os.path.exists", return_value=True)
def test_htpasswd_overwrite_prunes_legacy_users(
    mock_exists, mock_open, mock_htfile_cls, mock_ansible_module
):
    """Test overwrite mode removes legacy/stale user accounts."""
    mock_htfile = MagicMock()
    mock_htfile.users.return_value = ["alice", "legacy_bob"]
    mock_htfile.check_password.return_value = True
    mock_htfile_cls.return_value = mock_htfile

    params = {
        "path": "/tmp/.htpasswd",
        "name": "alice",
        "password": "secretpassword",
        "hash_scheme": "apr_md5_crypt",
        "state": "present",
        "create": True,
        "backup": True,
        "overwrite": True,
    }

    module_mock = mock_ansible_module(params)
    with patch(
        make_absolute(MODULES_IMPORT_PATH, "htpasswd.AnsibleModule"),
        return_value=module_mock,
    ):
        with pytest.raises(AnsibleExitJson) as exc_info:
            htpasswd.main()

    res = exc_info.value.kwargs
    assert res["changed"] is True
    assert res["backup_file"] == "/tmp/.htpasswd.2026-07-23.bak"
    mock_htfile.delete.assert_called_once_with("legacy_bob")
    mock_htfile.save.assert_called_once()


@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HAS_PASSLIB"), True)
@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HtpasswdFile"))
@patch("builtins.open")
@patch("os.path.exists", return_value=True)
def test_htpasswd_delete_user(
    mock_exists, mock_open, mock_htfile_cls, mock_ansible_module
):
    """Test deleting an existing user."""
    mock_htfile = MagicMock()
    mock_htfile.users.return_value = ["alice", "bob"]
    mock_htfile_cls.return_value = mock_htfile

    params = {
        "path": "/tmp/.htpasswd",
        "name": "bob",
        "password": None,
        "hash_scheme": "apr_md5_crypt",
        "state": "absent",
        "create": True,
        "backup": False,
        "overwrite": False,
    }

    module_mock = mock_ansible_module(params)
    with patch(
        make_absolute(MODULES_IMPORT_PATH, "htpasswd.AnsibleModule"),
        return_value=module_mock,
    ):
        with pytest.raises(AnsibleExitJson) as exc_info:
            htpasswd.main()

    res = exc_info.value.kwargs
    assert res["changed"] is True
    mock_htfile.delete.assert_called_once_with("bob")
    mock_htfile.save.assert_called_once()


@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HAS_PASSLIB"), True)
@patch(make_absolute(MODULES_IMPORT_PATH, "htpasswd.HtpasswdFile"))
@patch("builtins.open")
@patch("os.path.exists", return_value=True)
def test_htpasswd_user_list_overwrite(
    mock_exists, mock_open, mock_htfile_cls, mock_ansible_module
):
    """Test managing multiple users via user_list with overwrite option."""
    mock_htfile = MagicMock()
    mock_htfile.users.return_value = ["alice", "stale_user"]
    mock_htfile.check_password.side_effect = lambda u, p: (
        u == "alice" and p == "secret1"
    )
    mock_htfile_cls.return_value = mock_htfile

    params = {
        "path": "/tmp/.htpasswd",
        "user_list": [
            {"username": "alice", "password": "secret1"},
            {"username": "bob", "password": "secret2"},
        ],
        "hash_scheme": "bcrypt",
        "state": "present",
        "create": True,
        "backup": False,
        "overwrite": True,
    }

    module_mock = mock_ansible_module(params)
    with patch(
        make_absolute(MODULES_IMPORT_PATH, "htpasswd.AnsibleModule"),
        return_value=module_mock,
    ):
        with pytest.raises(AnsibleExitJson) as exc_info:
            htpasswd.main()

    res = exc_info.value.kwargs
    assert res["changed"] is True
    # Verify stale_user was pruned
    mock_htfile.delete.assert_called_once_with("stale_user")
    # Verify new user bob was created
    mock_htfile.set_password.assert_called_once_with("bob", "secret2")
    mock_htfile.save.assert_called_once()
