import pytest
from unittest.mock import patch, Mock

# fixture for x509_certificate_verify


@pytest.fixture(autouse=True)
def mock_ansible_module_dependencies():
    """
    Globally override the library check flags for the module under test.
    This prevents the module from failing on import during unit tests.
    """
    module_path = "ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify"

    with patch(f"{module_path}.HAS_LIBS", True), \
            patch(f"{module_path}.HAS_CRYPTOGRAPHY", True), \
            patch(f"{module_path}.HAS_PYOPENSSL", True), \
            patch(f"{module_path}.cryptography_version", "46.0.1"):
        yield


# fixture for ntlm_uri
@pytest.fixture(autouse=True)
def mock_ntlm_uri_imports():
    """
    Globally mock the requests and HttpNtlmAuth imports for ntlm_uri to prevent
    early fail_json during tests. This ensures the module doesn't bail out on
    missing libs, while allowing per-test patches for behavior.
    """
    module_path = "ansible_collections.dettonville.utils.plugins.modules.ntlm_uri"

    # Mock the global 'requests' to a full Mock object (so it has .request, .packages, etc.)
    mock_requests = Mock()
    # For the module's disable_warnings call
    mock_requests.packages.urllib3.disable_warnings = Mock()

    # Mock HttpNtlmAuth as a callable that returns a mock auth object
    mock_http_ntlm_auth = Mock(return_value=Mock())

    with patch(f"{module_path}.requests", mock_requests), \
            patch(f"{module_path}.HttpNtlmAuth", mock_http_ntlm_auth):
        yield
