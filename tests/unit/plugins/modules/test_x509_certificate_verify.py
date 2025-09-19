"""
Unit tests for the x509_certificate_verify Ansible module.

This test suite covers the implementation of the x509_certificate_verify module
which verifies X.509 certificate properties and signatures.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import NameOID, NameAttribute, Name

# Mocks for AnsibleModule and its methods
from ansible_collections.dettonville.utils.tests.unit.plugins.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
    exit_json,
    fail_json,
)

# Import the main module function to be tested
from ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify import (
    main as module_main,
)

MODULE_PATH = "ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify"


class TestX509CertificateVerifyModule(ModuleTestCase):
    """Test cases for the x509_certificate_verify main function."""

    def setUp(self):
        super().setUp()
        self.all_params = {
            'path': '/path/to/cert.pem',
            'issuer_path': '/path/to/issuer.pem',
            'common_name': 'test.example.com',
            'organization': 'TestOrg',
            'organizational_unit': 'IT',
            'key_algo': 'rsa',
            'key_size': 2048,
            'validate_expired': True,
            'validate_checkend': True,
            'checkend_value': 86400,
        }

    def _setup_valid_cert_mock(self, mock_cert):
        """Helper to set up a valid certificate mock."""
        # Create mock NameAttribute objects
        mock_cn = MagicMock(spec=NameAttribute)
        mock_cn.oid = NameOID.COMMON_NAME
        mock_cn.value = 'test.example.com'

        mock_org = MagicMock(spec=NameAttribute)
        mock_org.oid = NameOID.ORGANIZATION_NAME
        mock_org.value = 'TestOrg'

        mock_ou = MagicMock(spec=NameAttribute)
        mock_ou.oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        mock_ou.value = 'IT'

        # Mock the subject to return a list of NameAttribute objects when iterated
        mock_subject = MagicMock(spec=Name)
        mock_subject.__iter__.return_value = [mock_cn, mock_org, mock_ou]

        mock_cert.subject = mock_subject
        mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(days=31)
        mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_cert.public_key.return_value = MagicMock(
            spec=rsa.RSAPublicKey, key_size=2048)

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate, mock_x509_store,
                          mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_details(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate, mock_x509_store,
                                  mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario with correct details output."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")
        details = exc.exception.args[0]['details']
        self.assertEqual(details['common_name'], 'test.example.com')
        self.assertEqual(details['organization'], 'TestOrg')
        self.assertEqual(details['organizational_unit'], 'IT')
        self.assertEqual(details['key_algo'], 'rsa')
        self.assertEqual(details['key_size'], 2048)

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_common_name_mismatch(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                       mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function common name mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        # Set up mock similar to _setup_valid_cert_mock but with wrong common name
        mock_cn = MagicMock(spec=NameAttribute)
        mock_cn.oid = NameOID.COMMON_NAME
        mock_cn.value = 'wrong.example.com'

        mock_org = MagicMock(spec=NameAttribute)
        mock_org.oid = NameOID.ORGANIZATION_NAME
        mock_org.value = 'TestOrg'

        mock_ou = MagicMock(spec=NameAttribute)
        mock_ou.oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        mock_ou.value = 'IT'

        # Mock the subject to return a list of NameAttribute objects when iterated
        mock_subject = MagicMock(spec=Name)
        mock_subject.__iter__.return_value = [mock_cn, mock_org, mock_ou]

        mock_cert.subject = mock_subject
        mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(days=31)
        mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_cert.public_key.return_value = MagicMock(
            spec=rsa.RSAPublicKey, key_size=2048)

        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Common name mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expired(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                      mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function failure when certificate has expired."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) - timedelta(days=1)
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Certificate has expired"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_algo_mismatch(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.public_key.return_value = MagicMock(
            spec=ec.EllipticCurvePublicKey, key_size=256)
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Key algorithm mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_size_mismatch(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.public_key.return_value = MagicMock(
            spec=rsa.RSAPublicKey, key_size=1024)
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Key size mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_check_mode(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate, mock_x509_store,
                             mock_x509_store_context, mock_load_certificate):
        """Test main function in check mode."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = True
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertFalse(exc.exception.args[0]['changed'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "Check mode: All validations passed.")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_checkend_failure(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                               mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function failure when certificate is about to expire."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params,
                              'validate_checkend': True, 'checkend_value': 86400}
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(hours=12)
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Certificate will expire within 86400 seconds"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.x509.load_der_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_certificate(self, mock_ansible_module, mock_open, mock_load_der_x509_certificate,
                                      mock_load_pem_x509_certificate, mock_x509_store,
                                      mock_x509_store_context, mock_load_certificate):
        """Test main function with invalid certificate file."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json
        mock_open.return_value.__enter__.return_value.read.return_value = b'invalid_cert_data'
        mock_load_pem_x509_certificate.side_effect = ValueError(
            "Invalid PEM format")
        mock_load_der_x509_certificate.side_effect = ValueError(
            "Invalid DER format")
        with self.assertRaisesRegex(AnsibleFailJson, "Could not parse certificate. Must be PEM or DER format."):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_validation(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function with issuer certificate validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_pem_x509_certificate.return_value = mock_cert

        # Define side_effect function for mock_open
        def open_side_effect(path, mode):
            if path == '/path/to/cert.pem':
                file_mock = MagicMock()
                file_mock.read.return_value = b'mock_cert_data'
                cm_mock = MagicMock()
                cm_mock.__enter__.return_value = file_mock
                return cm_mock
            elif path == '/path/to/issuer.pem':
                file_mock = MagicMock()
                file_mock.read.return_value = b'mock_issuer_data'
                cm_mock = MagicMock()
                cm_mock.__enter__.return_value = file_mock
                return cm_mock
            else:
                raise FileNotFoundError(f"Unexpected path: {path}")

        mock_open.side_effect = open_side_effect

        # Mock OpenSSL objects
        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = MagicMock()
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        # Mock store and context for successful verification
        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None  # No exception means valid

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.open", new_callable=mock_open)
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_optional_params(self, mock_ansible_module, mock_open, mock_load_pem_x509_certificate,
                                     mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function with no optional parameters."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            'path': '/path/to/cert.pem',
            'issuer_path': None,
            'common_name': None,
            'organization': None,
            'organizational_unit': None,
            'key_algo': None,
            'key_size': None,
            'validate_expired': False,
            'validate_checkend': False,
            'checkend_value': 86400,
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_pem_x509_certificate.return_value = mock_cert
        mock_open.return_value.__enter__.return_value.read.return_value = b'mock_cert_data'
        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()
        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")


if __name__ == '__main__':
    ModuleTestCase.main()
