# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from ansible_collections.dettonville.utils.plugins.filter.ldif import to_ldif, from_ldif


def test_to_ldif_basic_and_ordering():
    """Verify standard mapping, key presence, and ordering layout constraints."""
    entry = {
        'changetype': 'add',
        'objectClass': 'posixGroup',
        'dn': 'cn=admins,ou=groups,dc=dettonville,dc=int',
        'cn': 'admins',
        'gidNumber': 2000
    }
    output = to_ldif(entry)

    # Assert structural ordering (dn and changetype must lead)
    lines = output.splitlines()
    assert lines[0] == "dn: cn=admins,ou=groups,dc=dettonville,dc=int"
    assert lines[1] == "changetype: add"
    assert "cn: admins" in lines
    assert "gidNumber: 2000" in lines
    # Verify closing blank line trailer sequence is respected
    assert output.endswith("\n")


def test_to_ldif_lists_and_multivalue():
    """Verify multi-valued arrays (member, objectClass) render multiple distinct lines."""
    entry = {
        'dn': 'cn=wheel,ou=groups,dc=dettonville,dc=int',
        'objectClass': ['top', 'posixGroup'],
        'memberUid': ['ljohnson', 'testuser_infra_dev01']
    }
    output = to_ldif(entry)
    lines = output.splitlines()

    assert lines.count("objectClass: top") == 1
    assert lines.count("objectClass: posixGroup") == 1
    assert lines.count("memberUid: ljohnson") == 1
    assert lines.count("memberUid: testuser_infra_dev01") == 1


def test_to_ldif_explicit_base64():
    """Verify fields terminating with explicit double colons are base64-encoded automatically."""
    entry = {
        'dn': 'cn=search,dc=dettonville,dc=int',
        'userPassword::': '{SSHA}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    }
    output = to_ldif(entry)
    # {SSHA}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx encodes exactly to e1NTSEF9eFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFg=
    assert "userPassword:: e1NTSEF9eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=" in output


def test_to_ldif_skips_none_values():
    """Verify dictionary fields evaluated to None are silently skipped instead of breaking."""
    entry = {
        'dn': 'cn=sudo.root,ou=SUDOers,dc=dettonville,dc=int',
        'gidNumber': None,
        'description': 'Root Sudo Rule'
    }
    output = to_ldif(entry)
    assert "description: Root Sudo Rule" in output
    assert "gidNumber" not in output


def test_from_ldif_basic_parsing():
    """Verify basic LDIF records accurately turn back into native python dictionaries."""
    ldif_str = (
        "dn: cn=admins,ou=groups,dc=dettonville,dc=int\n"
        "changetype: add\n"
        "objectClass: posixGroup\n"
        "cn: admins\n"
        "gidNumber: 2000\n"
    )
    result = from_ldif(ldif_str)
    assert result['dn'] == "cn=admins,ou=groups,dc=dettonville,dc=int"
    assert result['changetype'] == "add"
    assert result['cn'] == "admins"
    assert result['gidNumber'] == "2000"


def test_from_ldif_multivalue_collapsing():
    """Verify repeating keys are reassembled back into structural lists."""
    ldif_str = (
        "dn: cn=wheel,ou=groups,dc=dettonville,dc=int\n"
        "objectClass: top\n"
        "objectClass: posixGroup\n"
        "memberUid: ljohnson\n"
        "memberUid: testuser_infra_dev01\n"
    )
    result = from_ldif(ldif_str)
    assert isinstance(result['objectClass'], list)
    assert "top" in result['objectClass']
    assert "posixGroup" in result['objectClass']
    assert isinstance(result['memberUid'], list)
    assert "ljohnson" in result['memberUid']
    assert "testuser_infra_dev01" in result['memberUid']


def test_from_ldif_base64_decoding():
    """Verify base64 values parse back out to human-readable strings."""
    ldif_str = (
        "dn: cn=search,dc=dettonville,dc=int\n"
        "description:: TERBUCBSZWFkIE9ubHkgVXNlcg==\n"
    )
    result = from_ldif(ldif_str)
    assert result['description'] == "LDAP Read Only User"


def test_to_ldif_from_ldif_roundtrip():
    """Verify round-trip conversion: dict → LDIF → dict produces equivalent data.

    Tests both explicit base64 (:: suffix with plain text value) and auto-detected base64 (non-ASCII).
    """
    original = {
        'dn': 'cn=john.doe,ou=people,dc=dettonville,dc=int',
        'changetype': 'modify',
        'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
        'cn': 'John Doe',
        'sn': 'Doe',
        'givenName': 'John',
        'uid': 'john.doe',
        'mail': 'john.doe@dettonville.int',
        'gidNumber': 5000,
        'uidNumber': 5000,
        'homeDirectory': '/home/john.doe',
        'loginShell': '/bin/bash',
        'description': 'LDAP Test User with special chars: éñ@',  # auto base64
        'userPassword::': '{SSHA}secure123',  # explicit base64 (pass plain-text!)
        'jpegPhoto::': 'PixelData',
        # explicit base64 binary
        'employeeNumber': '12345',
        # Test None value (should be skipped)
        'inactive': None,
    }

    # Step 1: Convert to LDIF
    ldif_output = to_ldif(original)

    # Step 2: Convert LDIF back to dict
    reconstructed = from_ldif(ldif_output)

    # Step 3: Assertions
    assert isinstance(ldif_output, str)
    assert ldif_output.startswith("dn: ")
    assert ldif_output.endswith("\n")

    # Compare content (Note: keys stripped of '::' by from_ldif parser)
    assert reconstructed['dn'] == original['dn']
    assert reconstructed['changetype'] == original['changetype']
    assert set(reconstructed['objectClass']) == set(original['objectClass'])

    # Check scalar values
    for key in ['cn', 'sn', 'givenName', 'uid', 'mail', 'homeDirectory', 'loginShell',
                'description', 'employeeNumber']:
        assert reconstructed.get(key) == original[key]

    # Check integer values (come back as strings from LDIF strings)
    assert int(reconstructed['gidNumber']) == original['gidNumber']
    assert int(reconstructed['uidNumber']) == original['uidNumber']

    # Verify both explicit base64 target fields decoded cleanly back to source plain-text
    assert reconstructed['userPassword'] == '{SSHA}secure123'
    assert reconstructed['jpegPhoto'] == 'PixelData'

    # Verify None was skipped
    assert 'inactive' not in reconstructed

    # Optional: Verify that description was base64 encoded/decoded correctly
    assert 'éñ@' in reconstructed['description']
