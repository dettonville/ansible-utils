"""
Unit tests for the x509_certificate_verify Ansible module.

This test suite covers the implementation of the x509_certificate_verify module
which verifies X.509 certificate properties and signatures.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
import logging

# import re
import pprint
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
from cryptography.x509 import NameOID, NameAttribute, Name, Version, BasicConstraints, ExtensionOID, ExtensionNotFound, DNSName

# from OpenSSL.crypto import Error as CryptoError
from OpenSSL import crypto

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

MODULE_PATH = (
    "ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify"
)

import logging
logging.getLogger('ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify').setLevel(logging.DEBUG)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

import sys
import pytest


def _normalize_serial(serial_str):
    cleaned = str(serial_str).replace(":", "").replace(" ", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return int(cleaned, 16)


@pytest.fixture(autouse=True, scope="module")
def disable_stdin_capture():
    """Prevent AnsibleModule from failing on captured stdin during unit tests."""
    original_stdin = sys.stdin
    sys.stdin = open('/dev/null', 'r')  # empty, non-blocking stdin
    yield
    sys.stdin = original_stdin  # restore


class TestX509CertificateVerifyModule(ModuleTestCase):
    """Test cases for the x509_certificate_verify main function."""

    def setUp(self):
        super().setUp()
        self.all_params = {
            "path": "/path/to/cert.pem",
            "common_name": "test.example.com",
            "organization": "TestOrg",
            "organizational_unit": "IT",
            "country": "US",
            "state_or_province": "California",
            "locality": "San Francisco",
            "email_address": "admin@example.com",
            "version": 3,
            "signature_algorithm": "sha256WithRSAEncryption",
            "key_type": "rsa",
            "key_size": 2048,
            "validate_expired": True,
            "validate_checkend": True,
            "validate_is_ca": False,
            "checkend_value": 86400,
            "logging_level": "INFO",
        }

    def _setup_valid_cert_mock(
        self,
        mock_cert,
        key_type="rsa",
        modulus=None,
        issuer=None,
        serial_number=12345,
        include_utc=True,
        ca_flag=None,  # None: no extension, True: CA:TRUE, False: CA:FALSE
        sans_list=None,  # List of DNS SANs
    ):
        """Helper to set up a valid certificate mock."""
        mock_cn = MagicMock(spec=NameAttribute)
        mock_cn.oid = NameOID.COMMON_NAME
        mock_cn.value = "test.example.com"

        mock_org = MagicMock(spec=NameAttribute)
        mock_org.oid = NameOID.ORGANIZATION_NAME
        mock_org.value = "TestOrg"

        mock_ou = MagicMock(spec=NameAttribute)
        mock_ou.oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        mock_ou.value = "IT"

        mock_country = MagicMock(spec=NameAttribute)
        mock_country.oid = NameOID.COUNTRY_NAME
        mock_country.value = "US"

        mock_state = MagicMock(spec=NameAttribute)
        mock_state.oid = NameOID.STATE_OR_PROVINCE_NAME
        mock_state.value = "California"

        mock_locality = MagicMock(spec=NameAttribute)
        mock_locality.oid = NameOID.LOCALITY_NAME
        mock_locality.value = "San Francisco"

        mock_email = MagicMock(spec=NameAttribute)
        mock_email.oid = NameOID.EMAIL_ADDRESS
        mock_email.value = "admin@example.com"

        mock_subject = MagicMock(spec=Name)
        mock_subject.__iter__.return_value = [
            mock_cn,
            mock_org,
            mock_ou,
            mock_country,
            mock_state,
            mock_locality,
            mock_email,
        ]

        mock_issuer = MagicMock(spec=Name)
        mock_issuer_cn = MagicMock(spec=NameAttribute)
        mock_issuer_cn.oid = NameOID.COMMON_NAME
        mock_issuer_cn.value = issuer if issuer else "caGrund"
        mock_issuer.__iter__.return_value = [mock_issuer_cn]

        mock_cert.subject = mock_subject
        mock_cert.issuer = mock_issuer
        mock_cert.not_valid_before = datetime.now(timezone.utc) - timedelta(days=365)
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=30)
        if include_utc:
            mock_cert.not_valid_before_utc = datetime.now(timezone.utc) - timedelta(
                days=365
            )
            mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(
                days=30
            )
        # mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        # mock_cert.not_valid_after_utc = datetime.now(
        #     timezone.utc) + timedelta(days=31)
        # mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        # mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        if key_type == "rsa":
            mock_public_key = MagicMock(spec=rsa.RSAPublicKey)
            mock_public_key.key_size = 2048
            mock_public_numbers = MagicMock()
            mock_public_numbers.n = int(modulus, 16) if modulus else 123456789
            mock_public_key.public_numbers.return_value = mock_public_numbers
        elif key_type == "ec":
            mock_public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
            mock_public_key.curve.key_size = 256
        elif key_type == "dsa":
            mock_public_key = MagicMock(spec=dsa.DSAPublicKey)
            mock_public_key.key_size = 2048
        elif key_type == "ed25519":
            mock_public_key = MagicMock(spec=ed25519.Ed25519PublicKey)
        mock_cert.public_key.return_value = mock_public_key
        mock_cert.public_bytes.return_value = (
            b"-----BEGIN CERTIFICATE-----MII...-----END CERTIFICATE-----"
        )
        mock_cert.serial_number = serial_number
        mock_cert.version = Version.v3
        mock_sig_oid = MagicMock()
        mock_sig_oid._name = "sha256WithRSAEncryption"
        mock_cert.signature_algorithm_oid = mock_sig_oid

        # Mock extensions for CA check and SAN
        mock_ext_iter = MagicMock()
        mock_cert.extensions = mock_ext_iter

        def get_extension(oid):
            if oid == ExtensionOID.BASIC_CONSTRAINTS:
                if ca_flag is True:
                    mock_bc_ext = MagicMock()
                    mock_bc = MagicMock(spec=BasicConstraints)
                    mock_bc.ca = True
                    mock_bc_ext.value = mock_bc
                    return mock_bc_ext
                elif ca_flag is False:
                    mock_bc_ext = MagicMock()
                    mock_bc = MagicMock(spec=BasicConstraints)
                    mock_bc.ca = False
                    mock_bc_ext.value = mock_bc
                    return mock_bc_ext
                else:
                    raise ExtensionNotFound("No basicConstraints", oid)
            elif oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME and sans_list:
                mock_san_ext = MagicMock()
                mock_san_names = [MagicMock(value=san, __class__=DNSName) for san in sans_list]

                def iter_sans():
                    yield from mock_san_names

                mock_san_ext.value.__iter__ = MagicMock(return_value=iter_sans())
                mock_san_ext.value.get_values_for_type.return_value = mock_san_names
                return mock_san_ext
            else:
                raise ExtensionNotFound(f"No extension for {oid}", oid)

        mock_ext_iter.get_extension_for_oid.side_effect = get_extension

    def _setup_openssl_x509_mock(self, mock_x509, subject_cn="ca-root"):
        """Helper to set up an OpenSSL.crypto.X509 mock with a subject."""
        mock_subject = MagicMock()
        mock_subject.CN = subject_cn
        mock_subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value=subject_cn)
        ]
        mock_x509.get_subject.return_value = mock_subject
        return mock_x509

    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_libs(self, mock_ansible_module):
        """Test main function when required libraries are missing."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with patch(f"{MODULE_PATH}.HAS_LIBS", False):
            with self.assertRaises(AnsibleFailJson) as exc:
                module_main()

            result = exc.exception.args[0]
            self.assertTrue(result["failed"])
            self.assertIn(
                "'pyopenssl' and 'cryptography' Python libraries are required.",
                result["msg"],
            )

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_verification_properties(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function when no verification properties are provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": False,
            "validate_checkend": False,
            "validate_is_ca": False,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_data"
        mock_load_certificate_chain.return_value = (MagicMock(), [])

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"], "At least one verification property must be provided."
        )

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_serial_number(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function with invalid serial number."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params["serial_number"] = "invalid"
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_load_certificate_chain.return_value = (MagicMock(), [])

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertTrue(result["failed"])
        self.assertRegex(
            result["msg"],
            r"serial_number must be a valid integer .* or hex string"
        )

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_check_mode(self, mock_ansible_module, mock_cryptography_version):
        """Test main function in check mode."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = True
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["changed"])
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertEqual(result["details"], {})
        self.assertEqual(result["verify_results"], {})
        self.assertIsNone(result["cert_modulus"])
        self.assertIsNone(result["issuer_modulus"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_version(self, mock_ansible_module, mock_cryptography_version):
        """Test main function with invalid version."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        # mock_module.params = {**self.all_params, 'version': 2}
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "version": 2,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertIn("Invalid version. Expected 1 or 3", result["msg"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_details(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function success scenario with correct details output and CA certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert, modulus="A1B2C3")
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        details = result["details"]
        self.assertEqual(details["common_name"], "test.example.com")
        self.assertEqual(details["organization"], "TestOrg")
        self.assertEqual(details["organizational_unit"], "IT")
        self.assertEqual(details["country"], "US")
        self.assertEqual(details["state_or_province"], "California")
        self.assertEqual(details["locality"], "San Francisco")
        self.assertEqual(details["email_address"], "admin@example.com")
        self.assertEqual(details["version"], 3)
        self.assertEqual(details["signature_algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(details["key_type"], "rsa")
        self.assertEqual(details["key_size"], 2048)
        self.assertEqual(details["subject_alt_names"], [])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])
        mock_load_ca_certs.assert_called_once()

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_with_chain(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function success with chain validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "ca_path": "/path/to/issuer_ca.pem",
            "key_type": "rsa",
            "version": 3,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        mock_load_certificate_chain.return_value = (mock_cert, [])

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="A1B2C3", issuer="ca.example.com"
        )

        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertTrue(result["verify_results"]["key_type"])
        self.assertTrue(result["verify_results"]["version"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_mismatch(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function modulus mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        mock_load_certificate_chain.return_value = (mock_cert, [])

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="D4E5F6", issuer="ca.example.com"
        )

        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertFalse(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], None)

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_logging_level_debug(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function with logging_level=DEBUG."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "DEBUG",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    @patch.object(logging.Logger, "error")
    def test_main_invalid_certificate_with_debug_logging(
        self,
        mock_logger_error,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test stack trace logging when logging_level=DEBUG and an exception occurs."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "DEBUG",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.side_effect = Exception("Failed to read certificate file")
        # Ensure load_certificate_chain is not called
        mock_load_certificate_chain.side_effect = AssertionError(
            "load_certificate_chain should not be called"
        )

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(result["msg"], "Failed to read certificate file")
        mock_logger_error.assert_called_once()
        error_call_args = mock_logger_error.call_args[0]
        self.assertEqual(error_call_args[0], "Exception occurred: %s\nStack trace:\n%s")
        self.assertEqual(error_call_args[1], "Failed to read certificate file")
        self.assertIn("x509_certificate_verify.py", error_call_args[2])

    # @patch("cryptography.__version__", return_value="41.0.7")
    # @patch(f"{MODULE_PATH}._load_certificate_chain")
    # @patch(f"{MODULE_PATH}._read_cert_file")
    # @patch(f"{MODULE_PATH}.AnsibleModule")
    # @patch.object(logging.Logger, 'error')
    # def test_main_certificate_missing_not_valid_after_utc(self, mock_logger_error, mock_ansible_module,
    #                                                       mock_read_cert_file, mock_load_certificate_chain,
    #                                                       mock_cryptography_version):
    #     """Test error logging when not_valid_after_utc is unavailable in cryptography >= 41.0.0."""
    #     mock_module = MagicMock()
    #     mock_ansible_module.return_value = mock_module
    #     mock_module.params = {
    #         'path': '/path/to/cert.pem',
    #         'validate_expired': True,
    #         'logging_level': 'DEBUG'
    #     }
    #     mock_module.check_mode = False
    #     mock_module.exit_json = exit_json
    #     mock_module.fail_json = fail_json
    #     mock_read_cert_file.return_value = b"mock_cert_data"
    #
    #     mock_cert = MagicMock()
    #     future_date = datetime.now(timezone.utc) + timedelta(days=365)
    #     self._setup_valid_cert_mock(mock_cert, include_utc=False)
    #     mock_cert.not_valid_after = future_date
    #     mock_load_certificate_chain.return_value = (mock_cert, [])
    #
    #     with self.assertRaises(AnsibleExitJson) as exc:
    #         module_main()
    #
    #     result = exc.exception.args[0]
    #     self.assertFalse(result['failed'])
    #     self.assertTrue(result['valid'])
    #     self.assertFalse(result['verify_failed'])
    #     self.assertEqual(result['msg'], "All certificate validations passed successfully")
    #     self.assertTrue(result['verify_results']['expiry_valid'])
    #     mock_logger_error.assert_called_once()
    #     error_call_args = mock_logger_error.call_args[0]
    #     self.assertIn("not_valid_after_utc unavailable in cryptography 41.0.7, expected to be present",
    #                   error_call_args[0])
    #     self.assertIn("Stack trace:", error_call_args[0])
    #     self.assertTrue(any("x509_certificate_verify.py" in line for line in error_call_args[1].splitlines()))
    #
    # @patch("cryptography.__version__", return_value="40.0.2")
    # @patch(f"{MODULE_PATH}._load_certificate_chain")
    # @patch(f"{MODULE_PATH}._read_cert_file")
    # @patch(f"{MODULE_PATH}.AnsibleModule")
    # @patch.object(logging.Logger, 'warning')
    # def test_main_certificate_fallback_not_valid_after(self, mock_logger_warning, mock_ansible_module,
    #                                                    mock_read_cert_file, mock_load_certificate_chain,
    #                                                    mock_cryptography_version):
    #     """Test fallback to not_valid_after when not_valid_after_utc is unavailable in older cryptography versions."""
    #     mock_module = MagicMock()
    #     mock_ansible_module.return_value = mock_module
    #     mock_module.params = {
    #         'path': '/path/to/cert.pem',
    #         'validate_expired': True,
    #         'logging_level': 'DEBUG'
    #     }
    #     mock_module.check_mode = False
    #     mock_module.exit_json = exit_json
    #     mock_module.fail_json = fail_json
    #     mock_read_cert_file.return_value = b"mock_cert_data"
    #
    #     mock_cert = MagicMock()
    #     future_date = datetime.now(timezone.utc) + timedelta(days=365)
    #     self._setup_valid_cert_mock(mock_cert, include_utc=False)
    #     mock_cert.not_valid_after = future_date
    #     mock_load_certificate_chain.return_value = (mock_cert, [])
    #
    #     with self.assertRaises(AnsibleExitJson) as exc:
    #         module_main()
    #
    #     result = exc.exception.args[0]
    #     self.assertFalse(result['failed'])
    #     self.assertTrue(result['valid'])
    #     self.assertFalse(result['verify_failed'])
    #     self.assertEqual(result['msg'], "All certificate validations passed successfully")
    #     self.assertTrue(result['verify_results']['expiry_valid'])
    #     mock_logger_warning.assert_called_once_with(
    #         "not_valid_after_utc not available in cryptography 40.0.2, falling back to not_valid_after"
    #     )

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_checkend_failure(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function certificate checkend failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(
            seconds=3600
        )
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["checkend_valid"])

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_common_name_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function common name mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="wrong.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="IT"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="US"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="California"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="San Francisco"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="admin@example.com"),
        ]
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["common_name"])

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_country_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function country mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="IT"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="CA"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="California"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="San Francisco"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="admin@example.com"),
        ]
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["country"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_deprecated_issuer_ca_path(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function with deprecated issuer_ca_path parameter."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "issuer_ca_path": "/path/to/issuer.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_module.warn = MagicMock()
        mock_cryptography_version.return_value = "36.0.0"

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="A1B2C3", issuer="ca.example.com"
        )

        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(mock_module.warn.called)
        self.assertIn("deprecated", mock_module.warn.call_args[0][0])
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ec_key_size_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function EC key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, "key_type": "ec", "key_size": 384}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="ec")
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertFalse(result["verify_results"]["key_size"])

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ed25519_key(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function with Ed25519 key."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "key_type": "ed25519",
            "key_size": None,
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="ed25519")
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_email_address_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function email address mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="IT"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="US"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="California"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="San Francisco"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="wrong@example.com"),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["email_address"])

    @patch("cryptography.__version__")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_file_read_failure(
        self, mock_ansible_module, mock_read_cert_file, mock_cryptography_version
    ):
        """Test main function when certificate file cannot be read."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,  # Added to pass verification check
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        mock_read_cert_file.side_effect = Exception(
            "Failed to read certificate file /path/to/cert.pem: File not found"
        )

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"],
            "Failed to read certificate file /path/to/cert.pem: File not found",
        )

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_ca_file(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function when CA file cannot be read."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "ca_path": "/path/to/issuer_ca.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_load_ca_certs.side_effect = Exception(
            "Failed to read CA certificate file /path/to/issuer_ca.pem: CA file not found"
        )

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"],
            "Failed to read CA certificate file /path/to/issuer_ca.pem: CA file not found",
        )

    @patch("cryptography.__version__")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_serial_number_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function with invalid serial number."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "serial_number": "54321",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        mock_cert = MagicMock()
        mock_cert.subject = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
        ]
        mock_cert.serial_number = 12345
        # X.509 version 3 (0-based in cryptography)
        mock_cert.version = MagicMock(value=2)
        mock_cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
        mock_cert_public_key = MagicMock()
        mock_cert.public_key.return_value = mock_cert_public_key
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=30)

        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        # Debug print to see what happened
        print("Full result:", pprint.pformat(result))

        self.assertTrue(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["serial_number"])
        self.assertEqual(result["details"]["serial_number"], "12345")
        self.assertIsNone(result["cert_modulus"])
        self.assertIsNone(result["issuer_modulus"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ca_path_chain(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function with ca_path and chain validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "ca_path": "/path/to/issuer_ca.pem",
            "key_type": "rsa",
            "version": 3,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        mock_load_certificate_chain.return_value = (mock_cert, [])

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="A1B2C3", issuer="ca.example.com"
        )

        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertTrue(result["verify_results"]["key_type"])
        self.assertTrue(result["verify_results"]["version"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_with_chain_input(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function with chain input, verifying leaf properties and full chain signature."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/chain.pem",
            "ca_path": "/path/to/root-ca.pem",
            "common_name": "leaf.example.com",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.side_effect = [b"mock_chain_data", b"mock_root_ca_data"]

        # Mock leaf cert
        mock_leaf = MagicMock()
        self._setup_valid_cert_mock(mock_leaf, key_type="ec")
        # Override CN for leaf to match expected param
        mock_leaf_cn = MagicMock(spec=NameAttribute)
        mock_leaf_cn.oid = NameOID.COMMON_NAME
        mock_leaf_cn.value = "leaf.example.com"
        mock_leaf.subject.__iter__.return_value[0] = mock_leaf_cn  # First is CN

        # Mock intermediate cert
        mock_inter = MagicMock()
        self._setup_valid_cert_mock(mock_inter, key_type="rsa", issuer="root-ca")

        mock_load_certificate_chain.return_value = (mock_leaf, [mock_inter])

        # Mock root CA
        mock_root = MagicMock()
        self._setup_valid_cert_mock(mock_root, key_type="rsa")
        mock_load_ca_certs.return_value = [mock_root]

        mock_leaf_openssl = MagicMock()
        mock_inter_openssl = MagicMock()
        mock_root_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_leaf_openssl, mock_inter_openssl, mock_root_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertEqual(result["details"]["common_name"], "leaf.example.com")  # From leaf
        self.assertTrue(result["verify_results"]["common_name"])  # Matches expected
        self.assertTrue(result["verify_results"]["signature_valid"])  # Uses chain + ca

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_is_ca_true_success(self,
                                              mock_ansible_module,
                                              mock_read_cert_file,
                                              mock_load_certificate_chain,
                                              mock_cryptography_version):
        """Test validate_is_ca=True with a CA certificate (passes)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/ca.pem",
            "validate_is_ca": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_ca_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, ca_flag=True)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["verify_results"]["is_ca"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["msg"], "All certificate validations passed successfully")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_is_ca_true_failure_no_extension(self,
                                                           mock_ansible_module,
                                                           mock_read_cert_file,
                                                           mock_load_certificate_chain,
                                                           mock_cryptography_version):
        """Test validate_is_ca=True with no basicConstraints extension (fails)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/leaf.pem",
            "validate_is_ca": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_leaf_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, ca_flag=None)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["verify_results"]["is_ca"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertIn("One or more certificate validations failed", result["msg"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_is_ca_true_failure_ca_false(self,
                                                       mock_ansible_module,
                                                       mock_read_cert_file,
                                                       mock_load_certificate_chain,
                                                       mock_cryptography_version):
        """Test validate_is_ca=True with basicConstraints CA:FALSE (fails)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/end-entity.pem",
            "validate_is_ca": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_end_entity_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, ca_flag=False)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["verify_results"]["is_ca"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertIn("One or more certificate validations failed", result["msg"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_is_ca_false_skipped(self,
                                               mock_ansible_module,
                                               mock_read_cert_file,
                                               mock_load_certificate_chain,
                                               mock_cryptography_version):
        """Test validate_is_ca=False (skipped, no 'is_ca' in verify_results)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/any-cert.pem",
            "validate_is_ca": False,
            "validate_expired": True,  # Need at least one prop
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, ca_flag=None)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertNotIn("is_ca", result["verify_results"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["msg"], "All certificate validations passed successfully")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_is_ca_with_content(self,
                                              mock_ansible_module,
                                              mock_b64decode,
                                              mock_load_certificate_chain,
                                              mock_cryptography_version):
        """Test validate_is_ca=True with base64 content (CA cert)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        ca_b64 = (
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ5VENDQWVHQ0V3RFFZSktvWklodmNOQVFFQkJRQUVJQkFEQUJzTUNvWUlLb1pJem9RVEl3UWtBZlJRQQoK"
            "LS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
        )
        mock_module.params = {
            "content": ca_b64,
            "validate_is_ca": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_b64decode.return_value = b"mock_ca_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, ca_flag=True)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["verify_results"]["is_ca"])
        self.assertTrue(result["valid"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_subject_alt_names_success(self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain, mock_cryptography_version):
        """Test subject_alt_names validation success."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "subject_alt_names": ["*.admin.johnson.int", "admin.johnson.int"],
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, sans_list=["*.admin.johnson.int", "admin.johnson.int"])
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertTrue(result["verify_results"]["subject_alt_names"])
        self.assertEqual(result["details"]["subject_alt_names"], ["*.admin.johnson.int", "admin.johnson.int"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_subject_alt_names_failure(self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain, mock_cryptography_version):
        """Test subject_alt_names validation failure (missing wildcard)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "subject_alt_names": ["*.admin.johnson.int", "admin.johnson.int"],
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, sans_list=["admin.johnson.int"])  # Missing wildcard
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertFalse(result["verify_results"]["subject_alt_names"])
        self.assertEqual(result["details"]["subject_alt_names"], ["admin.johnson.int"])
        self.assertIn("One or more certificate validations failed", result["msg"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_subject_alt_names_no_extension(self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain, mock_cryptography_version):
        """Test subject_alt_names validation with no SAN extension (fails)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "subject_alt_names": ["example.com"],
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, sans_list=[])  # No SANs
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertFalse(result["verify_results"]["subject_alt_names"])
        self.assertEqual(result["details"]["subject_alt_names"], [])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_subject_alt_names_skipped(self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain, mock_cryptography_version):
        """Test when subject_alt_names is not provided (skipped)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertNotIn("subject_alt_names", result["verify_results"])
        self.assertTrue(result["valid"])

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ca_path_single_cert(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function with ca_path containing a single certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "ca_path": "/path/to/issuer_ca.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert, modulus="A1B2C3")

        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["signature_valid"])

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_validation(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
        mock_cryptography_version,
    ):
        """Test main function issuer validation failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "ca_path": "/path/to/issuer_ca.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        # Mock certificate
        mock_cert = MagicMock()
        mock_cert.subject = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
        ]
        mock_cert.serial_number = 12345
        # X.509 version 3 (0-based in cryptography)
        mock_cert.version = MagicMock(value=2)
        mock_cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
        mock_cert_public_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_cert_public_key.key_size = 2048
        mock_cert_public_numbers = MagicMock()
        mock_cert_public_numbers.n = 123456789  # Converts to "75BCD15"
        mock_cert_public_key.public_numbers.return_value = mock_cert_public_numbers
        mock_cert.public_key.return_value = mock_cert_public_key
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=30)

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        mock_ca_cert.subject = [
            MagicMock(oid=NameOID.COMMON_NAME, value="ca.example.com")
        ]
        mock_ca_cert_public_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_ca_cert_public_key.verify.side_effect = Exception("Invalid signature fallback")
        mock_ca_cert_public_numbers = MagicMock()
        mock_ca_cert_public_numbers.n = 987654321  # Converts to "3ADE68B1"
        mock_ca_cert_public_key.public_numbers.return_value = (
            mock_ca_cert_public_numbers
        )
        mock_ca_cert.public_key.return_value = mock_ca_cert_public_key

        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]
        mock_load_ca_certs.return_value = [mock_ca_cert]

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = MagicMock()
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.side_effect = crypto.Error(
            "Invalid signature"
        )

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["signature_valid"])
        self.assertEqual(result["cert_modulus"], "75BCD15")
        self.assertEqual(result["issuer_modulus"], None)
        self.assertFalse(result["verify_results"]["modulus_match"])
        self.assertIn("details", result)
        self.assertIn("verify_results", result)
        self.assertEqual(result["details"]["common_name"], "test.example.com")
        self.assertEqual(result["details"]["organization"], "TestOrg")
        self.assertEqual(_normalize_serial(result["details"]["serial_number"]), 12345)
        self.assertEqual(result["details"]["version"], 3)
        self.assertEqual(
            result["details"]["signature_algorithm"], "sha256WithRSAEncryption"
        )
        self.assertEqual(result["details"]["key_type"], "rsa")
        self.assertEqual(result["details"]["key_size"], 2048)

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_type_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function key algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, "key_type": "ec"}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="rsa")
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["key_type"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_size_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, "key_size": 4096}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["key_size"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_locality_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function locality mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="IT"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="US"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="California"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="Los Angeles"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="admin@example.com"),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["locality"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_mixed_cert_types(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function with mixed certificate types (RSA and EC)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "key_type": "ec",
            "key_size": 256,
            "ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="ec")
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert, key_type="rsa")
        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]

        mock_ca_certs = [mock_ca_cert]
        mock_load_ca_certs.return_value = mock_ca_certs

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        mock_load_ca_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_success(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function success scenario with modulus comparison."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert, modulus="A1B2C3")
        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]

        mock_ca_certs = [mock_ca_cert]
        mock_load_ca_certs.return_value = mock_ca_certs

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["signature_valid"])
        mock_load_ca_certs.assert_called_once()

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_organizational_unit_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function organizational unit mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="WrongUnit"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="US"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="California"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="San Francisco"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="admin@example.com"),
        ]
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["organizational_unit"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_serial_number_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function serial number mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params['serial_number'] = 12345
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        # self._setup_valid_cert_mock(mock_cert, serial_number=54321)
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.serial_number = 54321

        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]

        # Debug print to see what happened
        print("Full result:", pprint.pformat(result))

        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["serial_number"])

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_signature_algorithm_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function signature algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "signature_algorithm": "sha1WithRSAEncryption",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["signature_algorithm"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_state_or_province_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function state or province mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value="test.example.com"),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value="TestOrg"),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="IT"),
            MagicMock(oid=NameOID.COUNTRY_NAME, value="US"),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value="Texas"),
            MagicMock(oid=NameOID.LOCALITY_NAME, value="San Francisco"),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value="admin@example.com"),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["state_or_province"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function success scenario with CA certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
        mock_read_cert_file.side_effect = [b"mock_cert_data", b"mock_ca_data"]

        mock_ca_certs = [mock_ca_cert]
        mock_load_ca_certs.return_value = mock_ca_certs

        mock_cert_openssl = MagicMock()
        mock_ca_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [mock_cert_openssl, mock_ca_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertTrue(
            result["valid"], msg=f"Validation failed: {result['verify_results']}"
        )
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(
            result["verify_results"]["signature_valid"],
            msg="Signature verification failed unexpectedly",
        )
        mock_load_ca_certs.assert_called_once()

    @patch("cryptography.__version__")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_version(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function with invalid version."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "version": 2,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(result["msg"], "Invalid version: 2. Must be 1 or 3.")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    @patch.object(logging.Logger, "error")
    def test_main_valid_certificate_debug_logging(
        self,
        mock_logger_error,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function with valid certificate and debug logging."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "DEBUG",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        mock_logger_error.assert_not_called()

    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_expired_only(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain
    ):
        """Test main function with only validate_expired=True."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "validate_checkend": False,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("cryptography.x509.load_pem_x509_certificate")
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_certificate(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_der,
        mock_load_pem,
        mock_cryptography_version,
    ):
        """Test main function failure when an invalid certificate is provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b"invalid certificate data"
        mock_load_pem.side_effect = ValueError("Could not parse certificate")
        mock_load_der.side_effect = ValueError("Could not parse certificate")

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertIn(
            "Could not parse certificate. Must be PEM or DER format.", result["msg"]
        )

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expired(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function when certificate is expired."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) - timedelta(
            days=1
        )  # Expired
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["expiry_valid"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expires_soon(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_cryptography_version,
    ):
        """Test main function when certificate expires soon."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_checkend": True,
            "checkend_value": 86400,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b"mock_cert_data"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(
            hours=12
        )  # Expires soon
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["checkend_valid"])

    @patch(f"{MODULE_PATH}.verify_private_key_match")
    @patch(f"{MODULE_PATH}.serialization.load_pem_private_key")
    @patch("os.path.exists")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_private_key_match_success(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain,
        mock_exists, mock_load_key, mock_verify_match
    ):
        """Test main function with successful private key match."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        # Setup parameters including the new private_key_path
        params = self.all_params.copy()
        params["private_key_path"] = "/path/to/private_key.pem"
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Mock filesystem and utility functions
        mock_exists.return_value = True
        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_load_key.return_value = MagicMock()
        mock_verify_match.return_value = True

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["verify_results"]["private_key_match"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["msg"], "All certificate validations passed successfully")

    @patch(f"{MODULE_PATH}.verify_private_key_match")
    @patch(f"{MODULE_PATH}.serialization.load_pem_private_key")
    @patch("os.path.exists")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_private_key_match_failure(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain,
        mock_exists, mock_load_key, mock_verify_match
    ):
        """Test main function with a private key mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        # Setup parameters including the private_key_path
        params = self.all_params.copy()
        params["private_key_path"] = "/path/to/wrong_private_key.pem"
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Mock filesystem and utility functions
        mock_exists.return_value = True
        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_load_key.return_value = MagicMock()

        # Simulate a mismatch between key and cert
        mock_verify_match.return_value = False

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]

        # Assertions for failure state
        self.assertFalse(result["valid"], "Module should mark certificate as invalid on key mismatch")
        self.assertTrue(result["verify_failed"])
        self.assertIn("One or more certificate validations failed", result["msg"])

        # Verify the specific result in the verify_results dict
        self.assertFalse(result["verify_results"]["private_key_match"])

    @patch("os.path.exists")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_private_key_path_not_exists(
        self, mock_ansible_module, mock_read_cert_file, mock_load_certificate_chain, mock_exists
    ):
        """Test main function when private_key_path does not exist on disk."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        # Setup parameters with a non-existent path
        invalid_path = "/non/existent/path/to/key.pem"
        params = self.all_params.copy()
        params["private_key_path"] = invalid_path
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Mock os.path.exists to return False for the key path
        # We use a side_effect to ensure the cert path exists but the key path doesn't
        def exists_side_effect(path):
            if path == invalid_path:
                return False
            return True

        mock_exists.side_effect = exists_side_effect

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]

        # Assertions
        self.assertFalse(result["valid"], "Module should be invalid if key path is missing")
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["private_key_match"])

        # Verify that the general failure message is returned
        self.assertEqual(result["msg"], "One or more certificate validations failed")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_content_success(
        self, mock_ansible_module, mock_b64decode, mock_load_certificate_chain, mock_cryptography_version
    ):
        """Test main function with certificate provided via content (base64)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        cert_b64 = base64.b64encode(b"mock_cert_data").decode('utf-8')
        mock_module.params = {
            # No path provided
            "content": cert_b64,
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_b64decode.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(result["msg"], "All certificate validations passed successfully")
        mock_b64decode.assert_called_once_with(cert_b64, validate=True)

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_invalid_content(
        self, mock_ansible_module, mock_b64decode, mock_load_certificate_chain, mock_cryptography_version
    ):
        """Test main function failure when invalid base64 content for certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        invalid_b64 = "invalid_base64_content"
        mock_module.params = {
            # No path provided
            "content": invalid_b64,
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_b64decode.side_effect = ValueError("Invalid base64")

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertIn("Failed to decode content as base64", result["msg"])
        self.assertIn("Invalid base64", result["msg"])

    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_cert_source(self, mock_ansible_module):
        """Test main function failure when neither path nor content is provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(result["msg"], "Exactly one of path or content must be provided for the certificate.")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_both_path_and_content(
        self, mock_ansible_module, mock_read_cert_file, mock_b64decode, mock_load_certificate_chain, mock_cryptography_version
    ):
        """Test main function with both path and content provided (uses content)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        cert_b64 = base64.b64encode(b"mock_cert_data").decode('utf-8')
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "content": cert_b64,
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_b64decode.return_value = b"mock_cert_data"
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with patch.object(mock_module, 'warn') as mock_warn:
            with self.assertRaises(AnsibleExitJson) as exc:
                module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        mock_warn.assert_called_once_with("Both path and content provided; using content.")
        mock_b64decode.assert_called_once_with(cert_b64, validate=True)
        mock_read_cert_file.assert_not_called()

    @patch(f"{MODULE_PATH}.verify_private_key_match")
    @patch("cryptography.hazmat.primitives.serialization.load_pem_private_key")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_private_key_content_success(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_b64decode,
        mock_load_pem,
        mock_verify_match,
    ):
        """Test main function with successful private key match from content."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        params = self.all_params.copy()
        key_b64 = base64.b64encode(b"mock_key_data").decode('utf-8')
        params["private_key_content"] = key_b64
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_b64decode.return_value = b"mock_key_data"
        mock_load_pem.return_value = MagicMock()
        mock_verify_match.return_value = True

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["verify_results"]["private_key_match"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["msg"], "All certificate validations passed successfully")
        mock_b64decode.assert_called_once_with(key_b64, validate=True)
        mock_load_pem.assert_called_once()

    @patch("cryptography.hazmat.primitives.serialization.load_pem_private_key")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_invalid_private_key_content(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_b64decode,
        mock_load_pem,
    ):
        """Test main function failure when invalid base64 for private key content."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        params = self.all_params.copy()
        invalid_key_b64 = "invalid_base64_key"
        params["private_key_content"] = invalid_key_b64
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_b64decode.side_effect = ValueError("Invalid base64")

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["private_key_match"])
        self.assertIn("One or more certificate validations failed", result["msg"])
        mock_b64decode.assert_called_once_with(invalid_key_b64, validate=True)

    @patch(f"{MODULE_PATH}.verify_private_key_match")
    @patch("cryptography.hazmat.primitives.serialization.load_pem_private_key")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._load_certificate_chain")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_with_private_key_content_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_load_certificate_chain,
        mock_b64decode,
        mock_load_pem,
        mock_verify_match,
    ):
        """Test main function with private key mismatch from content."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        params = self.all_params.copy()
        key_b64 = base64.b64encode(b"mock_key_data").decode('utf-8')
        params["private_key_content"] = key_b64
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_read_cert_file.return_value = b"mock_cert_data"
        mock_b64decode.return_value = b"mock_key_data"
        mock_load_pem.return_value = MagicMock()
        mock_verify_match.return_value = False  # Mismatch

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_load_certificate_chain.return_value = (mock_cert, [])

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["private_key_match"])
        self.assertIn("One or more certificate validations failed", result["msg"])

    @patch(f"{MODULE_PATH}._verify_signature")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_match_with_bundle(self,
                                            mock_module,
                                            mock_parse,
                                            mock_read,
                                            mock_load_ca,
                                            mock_verify_sig):
        """Test modulus matching when the direct issuer is deep in a bundle."""
        mock_m = MagicMock()
        mock_module.return_value = mock_m
        # Include all_params and the new toggle
        mock_m.params = {**self.all_params, "ca_path": "/path/bundle.pem", "validate_modulus_match": True}
        mock_m.check_mode = False
        mock_m.exit_json = exit_json
        mock_m.fail_json = fail_json

        # Prevent signature verification from failing on mock PEM strings
        mock_verify_sig.return_value = True

        # Leaf cert: Issued by "Intermediate CA"
        leaf_cert = MagicMock()
        self._setup_valid_cert_mock(leaf_cert, modulus="AAAA", issuer="Intermediate CA")

        # Bundle: Root CA (modulus mismatch)
        root_ca = MagicMock()
        self._setup_valid_cert_mock(root_ca, modulus="BBBB")
        root_ca.subject = MagicMock()
        root_ca.subject.value = "Root CA"

        # Bundle: Intermediate CA (modulus match)
        int_ca = MagicMock()
        self._setup_valid_cert_mock(int_ca, modulus="AAAA")
        # Ensure this CA's subject matches the leaf's issuer exactly
        int_ca.subject = leaf_cert.issuer

        mock_parse.side_effect = [leaf_cert, root_ca, int_ca]
        mock_load_ca.return_value = [root_ca, int_ca]
        mock_read.return_value = b"mock_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "AAAA")
        self.assertEqual(result["issuer_modulus"], "AAAA")

    @patch(f"{MODULE_PATH}._verify_signature")  # Add this mock
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_skip_modulus_match_param(self,
                                           mock_module,
                                           mock_load_ca,
                                           mock_read,
                                           mock_parse,
                                           mock_verify_sig):
        """Test that modulus match can be explicitly disabled."""
        mock_m = MagicMock()
        mock_module.return_value = mock_m
        mock_m.params = {**self.all_params, "ca_path": "/path.pem", "validate_modulus_match": False}
        mock_m.check_mode = False
        mock_m.exit_json = exit_json
        mock_m.fail_json = fail_json

        # Ensure signature verification is mocked to return True
        mock_verify_sig.return_value = True

        # Setup Leaf and CA with mismatching moduli
        leaf_cert = MagicMock()
        self._setup_valid_cert_mock(leaf_cert, modulus="AAAA")

        ca_cert = MagicMock()
        self._setup_valid_cert_mock(ca_cert, modulus="FFFF")
        ca_cert.subject = leaf_cert.issuer

        mock_parse.side_effect = [leaf_cert, ca_cert]
        mock_read.return_value = b"mock_data"
        mock_load_ca.return_value = [ca_cert]

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        # The overall validation should pass because validate_modulus_match is False
        self.assertTrue(result["valid"])
        # Check that either modulus_match is True or not present depending on your logic
        if "modulus_match" in result["verify_results"]:
            self.assertTrue(result["verify_results"]["modulus_match"])

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_key_usage_all_present_should_pass(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test that key_usage validation passes when all requested values are present."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "key_usage": ["DigitalSignature", "KeyEncipherment"],
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="rsa")

        # Mock Key Usage extension
        ku = MagicMock()
        ku.digital_signature = True
        ku.key_encipherment = True
        ku.key_agreement = False
        ku.key_cert_sign = False
        ku.crl_sign = False

        # mock_cert.extensions.get_extension_for_oid.return_value = MagicMock(value=ku)
        mock_cert.extensions.get_extension_for_oid.side_effect = lambda oid: (
            MagicMock(value=ku) if oid == ExtensionOID.KEY_USAGE else
            ExtensionNotFound(oid=oid, msg="not found")
        )

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertTrue(result["verify_results"]["key_usage"])
        self.assertIn("DigitalSignature", result["details"].get("key_usage", []))
        self.assertIn("KeyEncipherment", result["details"].get("key_usage", []))

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_key_usage_missing_one_should_fail(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test that key_usage validation fails when one requested value is missing."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "key_usage": ["DigitalSignature", "KeyEncipherment", "KeyCertSign"],
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="rsa")

        ku = MagicMock()
        ku.digital_signature = True
        ku.key_encipherment = True
        ku.key_cert_sign = False   # missing
        mock_cert.extensions.get_extension_for_oid.return_value = MagicMock(value=ku)

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["key_usage"])
        self.assertIn("One or more certificate validations failed", result["msg"])

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_key_usage_extension_missing_should_fail(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test that requesting key_usage fails when the extension is not present."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "key_usage": ["DigitalSignature"]
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            oid=ExtensionOID.KEY_USAGE, msg="No Key Usage extension"
        )

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["key_usage"])

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_extended_key_usage_all_present_should_pass(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test extended_key_usage validation passes when all requested values exist."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "extended_key_usage": ["serverAuth", "clientAuth"],
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="rsa")

        # Setup EKU mock properly
        mock_eku = MagicMock()
        mock_eku.__iter__.return_value = [
            MagicMock(dotted_string="1.3.6.1.5.5.7.3.1"),  # serverAuth
            MagicMock(dotted_string="1.3.6.1.5.5.7.3.2"),  # clientAuth
        ]

        def get_ext(oid):
            if oid == ExtensionOID.EXTENDED_KEY_USAGE:
                return MagicMock(value=mock_eku)
            raise ExtensionNotFound(oid=oid, msg="not found")

        # mock_cert.extensions.get_extension_for_oid.return_value = MagicMock(value=mock_eku)
        mock_cert.extensions.get_extension_for_oid.side_effect = get_ext

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertTrue(result["verify_results"]["extended_key_usage"])
        self.assertEqual(
            sorted(result["details"].get("extended_key_usage", [])),
            ["clientAuth", "serverAuth"]
        )

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_extended_key_usage_missing_should_fail(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test extended_key_usage fails when one requested purpose is missing."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "extended_key_usage": ["serverAuth", "codeSigning"],
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)

        mock_eku = MagicMock()
        mock_eku.__iter__.return_value = [
            MagicMock(dotted_string="1.3.6.1.5.5.7.3.1"),  # serverAuth only
        ]
        mock_cert.extensions.get_extension_for_oid.return_value = MagicMock(value=mock_eku)

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["extended_key_usage"])

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_extended_key_usage_no_extension_should_fail(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test that requesting extended_key_usage fails if extension is absent."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()
        params.update({
            "content": "dummy-base64-cert-content",
            "extended_key_usage": ["serverAuth"],
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            oid=ExtensionOID.EXTENDED_KEY_USAGE, msg="No EKU"
        )

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["verify_results"]["extended_key_usage"])

    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_key_usage_not_requested_should_not_fail(self, mock_ansible_module, mock_parse, mock_b64decode):
        """Test that absence of key_usage param doesn't cause failure."""
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        params = self.all_params.copy()  # no key_usage here
        params.update({
            "content": "dummy-base64-cert-content"
        })
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            oid=ExtensionOID.KEY_USAGE,  # or any OID — doesn't matter
            msg="Simulated missing extension"
        )

        mock_parse.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])  # or depends on other params
        self.assertNotIn("key_usage", result["verify_results"])

    @patch("logging.basicConfig")
    @patch("base64.b64decode")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_content_takes_precedence_over_path(
            self,
            mock_ansible_module,
            mock_read_file,
            mock_parse,
            mock_b64decode,
            mock_basic_config):
        mock_b64decode.return_value = b"fake-cert-bytes"
        mock_m = MagicMock()
        mock_ansible_module.return_value = mock_m
        params = {
            "path": "/tmp/should-not-be-used.pem",
            "content": "base64-dummy",
            "validate_expired": True,
            "logging_level": "INFO"
        }
        mock_m.params = params

        mock_cert = MagicMock()
        mock_parse.return_value = mock_cert

        module_main()

        mock_read_file.assert_not_called()   # ← proves path was ignored
        mock_basic_config.assert_called_once()

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_content_raw_pem_success(self, mock_ansible_module, mock_parse):
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module

        raw_pem = """-----BEGIN CERTIFICATE-----
    MII...dummy PEM content here...
    -----END CERTIFICATE-----"""

        params = {
            "content": raw_pem,
            "validate_expired": True,
            "logging_level": "DEBUG"
        }
        mock_module.params = params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)

        # Make sure expiration check passes (mock notBefore/notAfter)
        mock_cert.not_valid_before = datetime.now(timezone.utc) - timedelta(days=365)
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=365)
        mock_parse.return_value = mock_cert

        with self.assertRaises(Exception) as exc:
            module_main()
        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        # self.assertFalse(result.get("verify_failed", True))
        self.assertFalse(result["verify_failed"])

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._normalize_cert_content")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_signing_ca_key_usage_cert(self, mock_ansible_module, mock_normalize, mock_parse):
        """
        Test that a signing CA certificate is correctly validated for KeyCertSign + CRLSign.
        Uses mocked parsing to avoid real PEM issues.
        """
        mock_m = MagicMock()
        mock_ansible_module.return_value = mock_m

        # Make normalize return valid-looking bytes
        mock_normalize.return_value = b"fake-cert-bytes"

        params = {
            "content": "dummy-content-does-not-matter",  # ignored anyway
            "key_usage": ["KeyCertSign", "CRLSign"],
            "validate_expired": True,
            "logging_level": "DEBUG",
        }
        mock_m.params = params
        mock_m.check_mode = False
        mock_m.exit_json = exit_json
        mock_m.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)

        # Make expiration check pass
        mock_cert.not_valid_before = datetime.now(timezone.utc) - timedelta(days=365)
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=365)

        # Mock Key Usage extension
        ku_mock = MagicMock()
        ku_mock.key_cert_sign = True
        ku_mock.crl_sign = True
        ku_mock.digital_signature = False
        ku_mock.key_encipherment = False
        ku_mock.key_agreement = False
        ku_mock.content_commitment = False
        ku_mock.data_encipherment = False
        ku_mock.encipher_only = False
        ku_mock.decipher_only = False

        def get_extension(oid):
            if oid == ExtensionOID.KEY_USAGE:
                return MagicMock(value=ku_mock)
            raise ExtensionNotFound(oid=oid, msg="Not mocked")

        mock_cert.extensions.get_extension_for_oid.side_effect = get_extension

        mock_parse.return_value = mock_cert

        # Run the module
        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]

        self.assertTrue(result["valid"], "Overall validation should pass")
        self.assertFalse(result.get("verify_failed", True), "verify_failed should be False")

        self.assertTrue(result["verify_results"].get("key_usage", False),
                        "key_usage validation should pass")

        self.assertEqual(
            sorted(result["details"].get("key_usage", [])),
            ["CRLSign", "KeyCertSign"],
            "Should extract exactly KeyCertSign and CRLSign"
        )

    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_signing_ca_key_usage_real_cert(self, mock_ansible_module):
        """
        Test that a real intermediate/signing CA certificate is correctly identified
        as having 'KeyCertSign' and 'CRLSign' when those are requested.
        Uses the exact PEM from the Jenkins playbook log.
        """
        # The real PEM from your log
        real_pem = """-----BEGIN CERTIFICATE-----
    MIIDGTCCAr6gAwIBAgIUdf7tumhxyy9Coa/0wAVdRmMrdnYwCgYIKoZIzj0EAwIw
    gZQxCzAJBgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEQMA4GA1UE
    BxMHUmFsZWlnaDEeMBwGA1UEChMVSm9obnNvbnZpbGxlIEludGVybmFsMRswGQYD
    VQQLExJNb3N0bHkgSW1wcmFjdGljYWwxHTAbBgNVBAMTFERldHRvbnZpbGxlIFZh
    dWx0IENBMB4XDTI2MDEzMTAzMDQ0M1oXDTI3MDEzMTAzMDUxM1owZDEeMBwGA1UE
    ChMVSm9obnNvbnZpbGxlIEludGVybmFsMRswGQYDVQQLExJNb3N0bHkgSW1wcmFj
    dGljYWwxJTAjBgNVBAMTHGNhLmFkbWluLmRldi5kZXR0b252aWxsZS5pbnQwWTAT
    BgcqhkjOPQIBBggqhkjOPQMBBwNCAAT0wVZrFOYoF/FOEE4fe5LVNGYGO9VS23hr
    WR+FS+6TMVnzUBq+B+fMAoalXyF4+VvUF2YQPEK71urkhYuc7/fNo4IBGzCCARcw
    DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS3VSI0+O+0DSCyh0m8ZjcQ7drIJjAf
    BgNVHSMEGDAWgBTbMtrStb+u4/TnTSOFFJMqJ+kt8TBPBggrBgEFBQcBAQRDMEEw
    PwYIKwYBBQUHMAKGM2h0dHBzOi8vdmF1bHQuYWRtaW4uam9obnNvbi5pbnQvcGtp
    LWludGVybWVkaWF0ZS9jYTAtBgNVHREEJjAkghxjYS5hZG1pbi5kZXYuZGV0dG9u
    dmlsbGUuaW50hwR/AAABMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHBzOi8vdmF1bHQu
    YWRtaW4uam9obnNvbi5pbnQvcGtpLWludGVybWVkaWF0ZS9jcmwwCgYIKoZIzj0E
    AwIDSQAwRgIhALnlFeNQ+6KG4g12ol0rpvx83mnC6nMnM69Ql93RU6QnAiEAuyT3
    KJxRTumYe9OclPgI6Zol1IywGEwTUp3OI6UUC8E=
    -----END CERTIFICATE-----"""

        mock_m = MagicMock()
        mock_ansible_module.return_value = mock_m

        params = {
            "content": real_pem,
            "key_usage": ["KeyCertSign", "CRLSign"],
            "logging_level": "DEBUG",
        }
        mock_m.params = params
        mock_m.check_mode = False
        mock_m.exit_json = exit_json
        mock_m.fail_json = fail_json

        # Run the module
        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        # Debug print to see what happened
        print("Full result:", pprint.pformat(result))

        # Core assertions
        self.assertTrue(result["valid"], "Overall validation should pass")
        self.assertFalse(result.get("verify_failed", True), "verify_failed should be False")

        # Key usage specific assertions
        self.assertIn("key_usage", result["verify_results"], "verify_results should contain key_usage")
        self.assertTrue(result["verify_results"]["key_usage"], "key_usage validation should pass")

        self.assertIn("key_usage", result["details"], "details should contain key_usage")
        self.assertEqual(
            sorted(result["details"]["key_usage"]),
            ["CRLSign", "KeyCertSign"],
            "Extracted key usages should be CRLSign and KeyCertSign"
        )


if __name__ == "__main__":
    ModuleTestCase.main()
