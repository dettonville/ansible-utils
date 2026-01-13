#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license

from ansible_collections.dettonville.utils.plugins.modules.ntlm_uri import main
import pytest
from unittest.mock import Mock, patch, ANY

# Custom exception to stop execution after exit_json or fail_json


class StopExecution(Exception):
    pass

# No need for explicit import of main here; it's imported via patches in conftest.py or tests.
# Assuming conftest.py with mock_ntlm_uri_imports fixture is in place to handle global import checks.


@pytest.fixture
def mock_module():
    """Fixture to mock AnsibleModule and capture exit_json/fail_json calls."""
    mock_exit_json = Mock()
    mock_fail_json = Mock()
    with patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.AnsibleModule') as mock_ansible_module:
        mock_instance = Mock()
        mock_instance.params = {}
        mock_instance.check_mode = False
        mock_instance.exit_json = mock_exit_json
        mock_instance.exit_json.side_effect = StopExecution
        mock_instance.fail_json = mock_fail_json
        mock_instance.fail_json.side_effect = StopExecution
        mock_ansible_module.return_value = mock_instance
        yield mock_instance, mock_exit_json, mock_fail_json


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_basic_get_success(mock_requests, mock_module):
    """Test a basic GET request that succeeds with status 200."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {'Server': 'TestServer'}
    mock_response.json.return_value = {'key': 'value'}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_requests.request.assert_called_once()
    call_args = mock_requests.request.call_args
    assert call_args[1]['method'] == 'GET'
    assert call_args[1]['url'] == 'http://example.com'
    # Note: Bug in module - always passes json=body, but body is None here
    assert call_args[1]['json'] is None
    assert call_args[1]['headers'] == {}
    mock_module[1].assert_called_once_with(changed=False, headers={
                                           'Server': 'TestServer'}, msg='OK', status=200, url='http://example.com')
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_post_json_body(mock_requests, mock_module):
    """Test POST with JSON body formatting."""
    body_dict = {'key': 'value'}
    mock_module[0].params = {
        'body': body_dict,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'POST',
        'status_code': [201],
        'return_content': True,
        'body_format': 'json',
        'headers': {},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 201
    mock_response.headers = {'Content-Type': 'application/json'}
    mock_response.json.return_value = {'id': 123}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_requests.request.assert_called_once()
    call_args = mock_requests.request.call_args
    assert call_args[1]['method'] == 'POST'
    assert call_args[1]['headers']['Content-Type'] == 'application/json'
    # json= should be the dumped body
    assert call_args[1]['json'] == '{"key": "value"}'
    mock_module[1].assert_called_once_with(
        changed=False,
        headers={'Content-Type': 'application/json'},
        json={'id': 123},
        msg='OK',
        status=201,
        url='http://example.com'
    )
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_post_raw_body(mock_requests, mock_module):
    """Test POST with raw body (string). Note: Module bug - uses json= even for raw."""
    raw_body = 'raw data'
    mock_module[0].params = {
        'body': raw_body,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'POST',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {'Content-Type': 'text/plain'},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_requests.request.assert_called_once()
    call_args = mock_requests.request.call_args
    assert call_args[1]['method'] == 'POST'
    assert call_args[1]['headers']['Content-Type'] == 'text/plain'
    # Bug: json=raw_body instead of data=raw_body
    assert call_args[1]['json'] == 'raw data'
    mock_module[1].assert_called_once_with(
        changed=False, headers={}, msg='OK', status=200, url='http://example.com')
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_status_code_failure(mock_requests, mock_module):
    """Test failure when status code is not accepted."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.headers = {}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_requests.request.assert_called_once()
    mock_module[1].assert_not_called()
    mock_module[2].assert_called_once_with(
        changed=False,
        headers={},
        msg='Status code 404 not in accepted status codes [200]',
        status=404,
        url='http://example.com'
    )


def test_invalid_method(mock_module):
    """Test failure on invalid method format."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'get invalid',  # after upper: 'GET INVALID' - has space, fails regex
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }

    with pytest.raises(StopExecution):
        main()

    mock_module[1].assert_not_called()
    mock_module[2].assert_called_once_with(
        msg="Parameter 'method' needs to be a single word in uppercase, like GET or POST.")


def test_check_mode_get(mock_module):
    """Test check mode for GET - should make real call (as per module logic)."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_module[0].check_mode = True

    with patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests') as mock_requests:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_requests.request.return_value = mock_response

        with pytest.raises(StopExecution):
            main()

        # In check_mode, for GET, it should still call requests (as per code: only mocks if method != GET)
        mock_requests.request.assert_called_once()
        mock_module[1].assert_called_once_with(
            changed=False,
            headers={},
            msg='OK',
            status=200,
            url='http://example.com'
        )
        mock_module[2].assert_not_called()


def test_check_mode_post(mock_module):
    """Test check mode for POST - should mock response without calling requests."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'POST',
        'status_code': [201],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_module[0].check_mode = True

    # Patch requests to ensure it's not called
    with patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests') as mock_requests:
        with pytest.raises(StopExecution):
            main()
        mock_requests.request.assert_not_called()

    # Check the mocked exit (note: always sets json in check_mode, even if return_content=False)
    mock_module[1].assert_called_once_with(
        changed=False,
        headers={},
        json={'content': 'sample content for check mode'},
        msg='OK',
        status=201,  # Takes first status_code
        url='http://example.com'
    )
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_return_content_true(mock_requests, mock_module):
    """Test returning content (json) when return_content=True."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': True,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.return_value = {'data': 'content'}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_module[1].assert_called_once_with(
        changed=False,
        headers={},
        json={'data': 'content'},
        msg='OK',
        status=200,
        url='http://example.com'
    )
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_validate_certs_false(mock_requests, mock_module):
    """Test with validate_certs=False."""
    mock_module[0].params = {
        'body': None,
        'url': 'https://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': False
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    mock_requests.request.assert_called_once()
    call_args = mock_requests.request.call_args
    assert call_args[1]['verify'] is False
    mock_module[1].assert_called_once_with(
        changed=False, headers={}, msg='OK', status=200, url='https://example.com')
    mock_module[2].assert_not_called()


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.re')
def test_method_validation_uppercase(mock_re, mock_requests, mock_module):
    """Test method validation - already uppercase, should pass."""
    mock_module[0].params = {
        'body': None,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'GET',
        'status_code': [200],
        'return_content': False,
        'body_format': 'raw',
        'headers': {},
        'validate_certs': True
    }
    mock_re.match.return_value = True  # Matches ^[A-Z]+$
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_requests.request.return_value = mock_response

    with pytest.raises(StopExecution):
        main()

    # No failure
    mock_module[2].assert_not_called()
    mock_module[1].assert_called_once_with(
        changed=False, headers={}, msg='OK', status=200, url='http://example.com')


@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.json')
@patch('ansible_collections.dettonville.utils.plugins.modules.ntlm_uri.requests')
def test_json_string_body(mock_requests, mock_json, mock_module):
    """Test JSON body as pre-formatted string."""
    json_string = '{"key": "value"}'
    mock_module[0].params = {
        'body': json_string,
        'url': 'http://example.com',
        'user': 'user',
        'password': 'pass',
        'method': 'POST',
        'status_code': [200],
        'return_content': False,
        'body_format': 'json',
        'headers': {},
        'validate_certs': True
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_requests.request.return_value = mock_response
    # json.dumps not called since it's string

    with pytest.raises(StopExecution):
        main()

    mock_json.dumps.assert_not_called()
    mock_requests.request.assert_called_once_with(
        method='POST',
        url='http://example.com',
        auth=ANY,
        verify=True,
        headers={'Content-Type': 'application/json'},
        json='{"key": "value"}'
    )
    mock_module[1].assert_called_once_with(
        changed=False, headers={}, msg='OK', status=200, url='http://example.com')
    mock_module[2].assert_not_called()
