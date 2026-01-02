import pytest
from unittest.mock import patch


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
