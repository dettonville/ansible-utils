"""
Unit tests for the x509_certificate_verify Ansible module.

This test suite covers the implementation of the x509_certificate_verify module
which verifies X.509 certificate properties and signatures.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
import pprint

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
from cryptography.x509 import NameOID, NameAttribute, Name, Version
from OpenSSL.crypto import Error as CryptoError

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
    main as module_main
)

MODULE_PATH = "ansible_collections.dettonville.utils.plugins.modules.x509_certificate_verify"


class TestX509CertificateVerifyModule(ModuleTestCase):
    """Test cases for the x509_certificate_verify main function."""

    def setUp(self):
        super().setUp()
        self.all_params = {
            'path': '/path/to/cert.pem',
            'common_name': 'test.example.com',
            'organization': 'TestOrg',
            'organizational_unit': 'IT',
            'country': 'US',
            'state_or_province': 'California',
            'locality': 'San Francisco',
            'email_address': 'admin@example.com',
            'serial_number': '12345',
            'version': 3,
            'signature_algorithm': 'sha256WithRSAEncryption',
            'key_algo': 'rsa',
            'key_size': 2048,
            'validate_expired': True,
            'validate_checkend': True,
            'checkend_value': 86400,
            'logging_level': 'INFO',
        }

    def _setup_valid_cert_mock(self, mock_cert, key_type='rsa', modulus=None, issuer=None, serial_number=12345):
        """Helper to set up a valid certificate mock."""
        mock_cn = MagicMock(spec=NameAttribute)
        mock_cn.oid = NameOID.COMMON_NAME
        mock_cn.value = 'test.example.com'

        mock_org = MagicMock(spec=NameAttribute)
        mock_org.oid = NameOID.ORGANIZATION_NAME
        mock_org.value = 'TestOrg'

        mock_ou = MagicMock(spec=NameAttribute)
        mock_ou.oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        mock_ou.value = 'IT'

        mock_country = MagicMock(spec=NameAttribute)
        mock_country.oid = NameOID.COUNTRY_NAME
        mock_country.value = 'US'

        mock_state = MagicMock(spec=NameAttribute)
        mock_state.oid = NameOID.STATE_OR_PROVINCE_NAME
        mock_state.value = 'California'

        mock_locality = MagicMock(spec=NameAttribute)
        mock_locality.oid = NameOID.LOCALITY_NAME
        mock_locality.value = 'San Francisco'

        mock_email = MagicMock(spec=NameAttribute)
        mock_email.oid = NameOID.EMAIL_ADDRESS
        mock_email.value = 'admin@example.com'

        mock_subject = MagicMock(spec=Name)
        mock_subject.__iter__.return_value = [
            mock_cn, mock_org, mock_ou, mock_country, mock_state, mock_locality, mock_email]

        mock_issuer = MagicMock(spec=Name)
        mock_issuer_cn = MagicMock(spec=NameAttribute)
        mock_issuer_cn.oid = NameOID.COMMON_NAME
        mock_issuer_cn.value = issuer if issuer else 'ca-root'
        mock_issuer.__iter__.return_value = [mock_issuer_cn]

        mock_cert.subject = mock_subject
        mock_cert.issuer = mock_issuer
        mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(days=31)
        mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        if key_type == 'rsa':
            mock_public_key = MagicMock(spec=rsa.RSAPublicKey)
            mock_public_key.key_size = 2048
            if modulus:
                mock_public_key.public_numbers.return_value.n = int(
                    modulus, 16)
        elif key_type == 'ec':
            mock_public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
            mock_public_key.curve.key_size = 256
        elif key_type == 'dsa':
            mock_public_key = MagicMock(spec=dsa.DSAPublicKey)
            mock_public_key.key_size = 2048
        elif key_type == 'ed25519':
            mock_public_key = MagicMock(spec=ed25519.Ed25519PublicKey)
        mock_cert.public_key.return_value = mock_public_key
        mock_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----MII...-----END CERTIFICATE-----'
        mock_cert.serial_number = serial_number
        mock_cert.version = Version.v3
        mock_sig_oid = MagicMock()
        mock_sig_oid._name = 'sha256WithRSAEncryption'
        mock_cert.signature_algorithm_oid = mock_sig_oid

    def _setup_openssl_x509_mock(self, mock_x509, subject_cn='ca-root'):
        """Helper to set up an OpenSSL.crypto.X509 mock with a subject."""
        mock_subject = MagicMock()
        mock_subject.CN = subject_cn
        mock_subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value=subject_cn)
        ]
        mock_x509.get_subject.return_value = mock_subject
        return mock_x509

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                          mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                          mock_load_certificate):
        """Test main function success scenario."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params, 'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

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
            result['valid'], msg=f"Validation failed: {result['verify_results']}")
        self.assertFalse(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(
            result['msg'], "All certificate validations passed successfully")
        self.assertTrue(result['verify_results']['signature_valid'],
                        msg="Signature verification failed unexpectedly")
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_details(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                                  mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                                  mock_load_certificate):
        """Test main function success scenario with correct details output."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params, 'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        print("result =>", pprint.pformat(result))
        self.assertTrue(result['valid'])
        self.assertFalse(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(
            result['msg'], "All certificate validations passed successfully")
        details = result['details']
        self.assertEqual(details['common_name'], 'test.example.com')
        self.assertEqual(details['organization'], 'TestOrg')
        self.assertEqual(details['organizational_unit'], 'IT')
        self.assertEqual(details['country'], 'US')
        self.assertEqual(details['state_or_province'], 'California')
        self.assertEqual(details['locality'], 'San Francisco')
        self.assertEqual(details['email_address'], 'admin@example.com')
        self.assertEqual(details['serial_number'], '12345')
        self.assertEqual(details['version'], 3)
        self.assertEqual(details['signature_algorithm'],
                         'sha256WithRSAEncryption')
        self.assertEqual(details['key_algo'], 'rsa')
        self.assertEqual(details['key_size'], 2048)
        self.assertEqual(result['cert_modulus'], 'A1B2C3')
        self.assertEqual(result['issuer_modulus'], 'A1B2C3')
        self.assertTrue(result['modulus_match'])
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_success(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                                  mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                                  mock_load_certificate):
        """Test main function success scenario with modulus comparison."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params, 'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result['valid'])
        self.assertFalse(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(
            result['msg'], "All certificate validations passed successfully")
        self.assertTrue(result['modulus_match'])
        self.assertEqual(result['cert_modulus'], 'A1B2C3')
        self.assertEqual(result['issuer_modulus'], 'A1B2C3')
        self.assertTrue(result['verify_results']['signature_valid'])
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                   mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function modulus mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params,
                              'issuer_path': '/path/to/issuer.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, modulus='D4E5F6')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['modulus_match'])
        self.assertEqual(result['cert_modulus'], 'A1B2C3')
        self.assertEqual(result['issuer_modulus'], 'D4E5F6')

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_common_name_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                       mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='wrong.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['common_name'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_organization_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                        mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function organization mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.subject.__iter__.return_value = [
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='WrongOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['organization'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_organizational_unit_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                               mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='WrongUnit'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['organizational_unit'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_country_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                   mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='CA'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['country'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_state_or_province_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                             mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='Texas'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['state_or_province'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_locality_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='Los Angeles'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='admin@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['locality'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_email_address_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                         mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
            MagicMock(oid=NameOID.COMMON_NAME, value='test.example.com'),
            MagicMock(oid=NameOID.ORGANIZATION_NAME, value='TestOrg'),
            MagicMock(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value='IT'),
            MagicMock(oid=NameOID.COUNTRY_NAME, value='US'),
            MagicMock(oid=NameOID.STATE_OR_PROVINCE_NAME, value='California'),
            MagicMock(oid=NameOID.LOCALITY_NAME, value='San Francisco'),
            MagicMock(oid=NameOID.EMAIL_ADDRESS, value='wrong@example.com'),
        ]
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['email_address'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_serial_number_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                         mock_x509_store, mock_x509_store_context, mock_load_certificate):
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
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['serial_number'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_version_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                   mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function version mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.version = Version.v1
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['version'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_signature_algorithm_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                               mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function signature algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.signature_algorithm_oid._name = 'sha1WithRSAEncryption'
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['signature_algorithm'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_algo_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['key_algo'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_key_size_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, 'key_size': 4096}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['key_size'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ec_key_size_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                       mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function EC key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params,
                              'key_algo': 'ec', 'key_size': 384}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['key_size'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expired(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                      mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function certificate expired failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) - timedelta(days=1)
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['expiry_valid'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_checkend_failure(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                               mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function certificate checkend failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(seconds=3600)
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['checkend_valid'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_validation(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                                    mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                                    mock_load_certificate):
        """Test main function issuer validation failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params, 'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.side_effect = CryptoError(
            "Invalid signature")

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['valid'])
        self.assertTrue(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(result['msg'], "Some certificate validations failed")
        self.assertFalse(result['verify_results']['signature_valid'])
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_with_chain(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                                     mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                                     mock_load_certificate):
        """Test main function success with chain validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            **self.all_params, 'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert)
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result['valid'])
        self.assertFalse(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(
            result['msg'], "All certificate validations passed successfully")
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    @patch(f"{MODULE_PATH}.x509.load_pem_x509_certificate")
    @patch(f"{MODULE_PATH}.x509.load_der_x509_certificate")
    def test_main_invalid_certificate(self, mock_load_der, mock_load_pem, mock_ansible_module, mock_read_cert_file,
                                      mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function failure when an invalid certificate is provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        # Configure the mock to return a bytes object, preventing TypeError
        mock_read_cert_file.return_value = b"invalid certificate data"

        # Configure both parsing functions to raise a ValueError
        mock_load_pem.side_effect = ValueError("Could not parse certificate")
        mock_load_der.side_effect = ValueError("Could not parse certificate")

        # The module's main function should catch the ValueError from _parse_certificate
        # which in turn will call the mocked fail_json
        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        # Assert that fail_json was called with the correct message
        result = exc.exception.args[0]
        self.assertTrue(result['failed'])
        self.assertEqual(result['msg'],
                         "Could not parse certificate. Must be PEM or DER format. Error: Could not parse certificate")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}._load_chain_certs")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_mixed_cert_types(self, mock_ansible_module, mock_load_chain_certs, mock_read_cert_file,
                                   mock_parse_certificate, mock_x509_store, mock_x509_store_context,
                                   mock_load_certificate):
        """Test main function with mixed certificate types (RSA and EC)."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params, 'key_algo': 'ec', 'key_size': 256,
                              'issuer_path': '/path/to/issuer.pem', 'chain_path': '/path/to/chain.pem'}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, key_type='rsa')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_chain_cert = MagicMock()
        mock_chain_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----mock_chain_pem-----END CERTIFICATE-----'
        mock_load_chain_certs.return_value = [mock_chain_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_chain_openssl = self._setup_openssl_x509_mock(MagicMock())
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result['valid'])
        self.assertFalse(result['verify_failed'])
        self.assertFalse(result['failed'])
        self.assertEqual(
            result['msg'], "All certificate validations passed successfully")
        self.assertIsNone(result['modulus_match'])
        mock_load_chain_certs.assert_called_once()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_check_mode(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                             mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function in check mode."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = True
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertFalse(result['changed'])
        self.assertEqual(
            result['msg'], "Check mode: All validations passed successfully")

    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_verification_params(self, mock_ansible_module):
        """Test main function failure when no verification parameters provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            'path': '/path/to/cert.pem',
            'issuer_path': None,
            'chain_path': None,
            'common_name': None,
            'organization': None,
            'organizational_unit': None,
            'country': None,
            'state_or_province': None,
            'locality': None,
            'email_address': None,
            'serial_number': None,
            'version': None,
            'signature_algorithm': None,
            'key_algo': None,
            'key_size': None,
            'validate_expired': False,
            'validate_checkend': False,
            'checkend_value': 86400,
            'logging_level': 'INFO',
        }
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        with self.assertRaises(AnsibleFailJson) as exc:
            module_main()

        result = exc.exception.args[0]
        self.assertTrue(result['failed'])
        self.assertEqual(
            result['msg'], "At least one verification property must be provided.")


if __name__ == '__main__':
    ModuleTestCase.main()
