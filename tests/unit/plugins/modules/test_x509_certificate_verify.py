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

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
from cryptography.x509 import NameOID, NameAttribute, Name, Version

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
            "serial_number": "12345",
            "version": 3,
            "signature_algorithm": "sha256WithRSAEncryption",
            "key_algo": "rsa",
            "key_size": 2048,
            "validate_expired": True,
            "validate_checkend": True,
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

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_verification_properties(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
    ):
        """Test main function when no verification properties are provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "validate_expired": False,
            "validate_checkend": False,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(
            result["msg"], "At least one verification property must be provided."
        )

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_serial_number(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
    ):
        """Test main function with invalid serial number."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params["serial_number"] = "invalid"
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertTrue(result["failed"])
        self.assertRegex(
            result["msg"],
            r"Invalid serial number: .*\. Must be a valid decimal or hexadecimal number\.",
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
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_details(
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
        """Test main function success scenario with correct details output and CA certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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
        self.assertEqual(details["serial_number"], "12345")
        self.assertEqual(details["version"], 3)
        self.assertEqual(details["signature_algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(details["key_algo"], "rsa")
        self.assertEqual(details["key_size"], 2048)
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])
        mock_load_ca_certs.assert_called_once()

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_with_chain(
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
        """Test main function success with chain validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "issuer_ca_path": "/path/to/issuer_ca.pem",
            "key_algo": "rsa",
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

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="A1B2C3", issuer="ca.example.com"
        )

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
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertTrue(result["verify_results"]["key_algo"])
        self.assertTrue(result["verify_results"]["version"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        self.assertTrue(result["verify_results"]["modulus_match"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_mismatch(
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
        """Test main function modulus mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "issuer_ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Mock certificate
        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")

        # Mock CA certificate
        mock_ca_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_ca_cert, modulus="D4E5F6", issuer="ca.example.com"
        )

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
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertFalse(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "D4E5F6")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_logging_level_debug(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertFalse(result["failed"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    @patch.object(logging.Logger, "error")
    def test_main_invalid_certificate_with_debug_logging(
        self,
        mock_logger_error,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        # Ensure parse_certificate is not called
        mock_parse_certificate.side_effect = AssertionError(
            "parse_certificate should not be called"
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
    # @patch(f"{MODULE_PATH}._parse_certificate")
    # @patch(f"{MODULE_PATH}._read_cert_file")
    # @patch(f"{MODULE_PATH}.AnsibleModule")
    # @patch.object(logging.Logger, 'error')
    # def test_main_certificate_missing_not_valid_after_utc(self, mock_logger_error, mock_ansible_module,
    #                                                       mock_read_cert_file, mock_parse_certificate,
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
    #     mock_parse_certificate.return_value = mock_cert
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
    # @patch(f"{MODULE_PATH}._parse_certificate")
    # @patch(f"{MODULE_PATH}._read_cert_file")
    # @patch(f"{MODULE_PATH}.AnsibleModule")
    # @patch.object(logging.Logger, 'warning')
    # def test_main_certificate_fallback_not_valid_after(self, mock_logger_warning, mock_ansible_module,
    #                                                    mock_read_cert_file, mock_parse_certificate,
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
    #     mock_parse_certificate.return_value = mock_cert
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

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_checkend_failure(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["checkend_valid"])

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_common_name_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["common_name"])

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_country_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["country"])

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_deprecated_chain_path(
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
        """Test main function with deprecated chain_path parameter."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "chain_path": "/path/to/chain.pem",
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
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["verify_failed"])
        self.assertEqual(
            result["msg"], "All certificate validations passed successfully"
        )
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertTrue(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")
        mock_module.warn.assert_any_call(
            "chain_path is deprecated. Use issuer_ca_path instead."
        )

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_deprecated_issuer_path(
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
        """Test main function with deprecated issuer_path parameter."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "issuer_path": "/path/to/issuer.pem",
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

        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert]
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
        self.assertTrue(result["verify_results"]["modulus_match"])
        self.assertEqual(result["cert_modulus"], "A1B2C3")
        self.assertEqual(result["issuer_modulus"], "A1B2C3")

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ec_key_size_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
    ):
        """Test main function EC key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, "key_algo": "ec", "key_size": 384}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="ec")
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertFalse(result["verify_results"]["key_size"])

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ed25519_key(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
    ):
        """Test main function with Ed25519 key."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "key_algo": "ed25519",
            "key_size": None,
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="ed25519")
        mock_parse_certificate.return_value = mock_cert
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
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_ca_file(
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
        """Test main function when CA file cannot be read."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "issuer_ca_path": "/path/to/issuer_ca.pem",
            "validate_expired": True,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json
        mock_cryptography_version.return_value = "36.0.0"

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_parse_certificate.return_value = mock_cert
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
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_serial_number_mismatch(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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

        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["serial_number"])
        self.assertEqual(result["details"]["serial_number"], "12345")
        self.assertIsNone(result["cert_modulus"])
        self.assertIsNone(result["issuer_modulus"])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_ca_path_chain(
        self,
        mock_ansible_module,
        mock_load_ca_certs,
        mock_read_cert_file,
        mock_parse_certificate,
        mock_x509_store,
        mock_x509_store_context,
        mock_load_certificate,
    ):
        """Test main function with issuer_ca_path containing multiple certificates."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params,
            "issuer_ca_path": "/path/to/issuer_ca.pem",
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus="A1B2C3")
        mock_ca_cert1 = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert1, modulus="A1B2C3")
        mock_ca_cert2 = MagicMock()
        self._setup_valid_cert_mock(mock_ca_cert2)
        mock_parse_certificate.side_effect = [mock_cert, mock_ca_cert1]
        mock_read_cert_file.side_effect = [
            b"mock_cert_data",
            b"-----BEGIN CERTIFICATE-----mock_ca_data1-----END CERTIFICATE-----\n"
            b"-----BEGIN CERTIFICATE-----mock_ca_data2-----END CERTIFICATE-----",
        ]

        mock_ca_certs = [mock_ca_cert1, mock_ca_cert2]
        mock_load_ca_certs.return_value = mock_ca_certs

        mock_cert_openssl = MagicMock()
        mock_ca_openssl1 = self._setup_openssl_x509_mock(MagicMock(), subject_cn="ca1")
        mock_ca_openssl2 = self._setup_openssl_x509_mock(MagicMock(), subject_cn="ca2")
        mock_load_certificate.side_effect = [
            mock_cert_openssl,
            mock_ca_openssl1,
            mock_ca_openssl2,
        ]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store.add_cert = MagicMock()
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
        self.assertTrue(result["verify_results"]["signature_valid"])
        self.assertEqual(mock_store.add_cert.call_count, 2)
        mock_store.add_cert.assert_any_call(mock_ca_openssl1)
        mock_store.add_cert.assert_any_call(mock_ca_openssl2)

    @patch("cryptography.__version__")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_ca_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_ca_path_single_cert(
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
        """Test main function with issuer_ca_path containing a single certificate."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            "path": "/path/to/cert.pem",
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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
        self.assertEqual(result["issuer_modulus"], "3ADE68B1")
        self.assertFalse(result["verify_results"]["modulus_match"])
        self.assertIn("details", result)
        self.assertIn("verify_results", result)
        self.assertEqual(result["details"]["common_name"], "test.example.com")
        self.assertEqual(result["details"]["organization"], "TestOrg")
        self.assertEqual(result["details"]["serial_number"], "12345")
        self.assertEqual(result["details"]["version"], 3)
        self.assertEqual(
            result["details"]["signature_algorithm"], "sha256WithRSAEncryption"
        )
        self.assertEqual(result["details"]["key_algo"], "rsa")
        self.assertEqual(result["details"]["key_size"], 2048)

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_algo_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
    ):
        """Test main function key algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, "key_algo": "ec"}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type="rsa")
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["key_algo"])

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
            "key_algo": "ec",
            "key_size": 256,
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_organizational_unit_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
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
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, serial_number=54321)
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
        self.assertFalse(result["verify_results"]["serial_number"])

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_signature_algorithm_mismatch(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
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
            "issuer_ca_path": "/path/to/issuer_ca.pem",
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
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_version(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b"mock_cert_data"

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result["failed"])
        self.assertEqual(result["msg"], "Invalid version: 2. Must be 1 or 3.")

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    @patch.object(logging.Logger, "error")
    def test_main_valid_certificate_debug_logging(
        self,
        mock_logger_error,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertTrue(result["valid"])
        mock_logger_error.assert_not_called()

    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_validate_expired_only(
        self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate
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
        mock_parse_certificate.return_value = mock_cert
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
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expired(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["expiry_valid"])

    @patch("cryptography.__version__", return_value="41.0.7")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expires_soon(
        self,
        mock_ansible_module,
        mock_read_cert_file,
        mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result["failed"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["verify_failed"])
        self.assertEqual(result["msg"], "One or more certificate validations failed")
        self.assertFalse(result["verify_results"]["checkend_valid"])


if __name__ == "__main__":
    ModuleTestCase.main()
