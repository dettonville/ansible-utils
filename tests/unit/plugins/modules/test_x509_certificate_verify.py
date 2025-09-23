"""
Unit tests for the x509_certificate_verify Ansible module.

This test suite covers the implementation of the x509_certificate_verify module
which verifies X.509 certificate properties and signatures.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, MagicMock
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
            'chain_path': '/path/to/chain.pem',
            'common_name': 'test.example.com',
            'organization': 'TestOrg',
            'organizational_unit': 'IT',
            'country': 'US',
            'state_or_province': 'California',
            'locality': 'San Francisco',
            'email_address': 'admin@example.com',
            'key_algo': 'rsa',
            'key_size': 2048,
            'validate_expired': True,
            'validate_checkend': True,
            'checkend_value': 86400,
        }

    def _setup_valid_cert_mock(self, mock_cert, key_type='rsa', modulus=None, issuer=None):
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

        # Mock the subject to return a list of NameAttribute objects when iterated
        mock_subject = MagicMock(spec=Name)
        mock_subject.__iter__.return_value = [mock_cn, mock_org, mock_ou, mock_country, mock_state, mock_locality, mock_email]

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
        else:
            mock_public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
            mock_public_key.curve.key_size = 256
        mock_cert.public_key.return_value = mock_public_key
        mock_cert.public_bytes.return_value = b'mock_der_data'

    def _setup_openssl_x509_mock(self, mock_x509, subject_cn='ca-root'):
        """Helper to set up an OpenSSL.crypto.X509 mock with a subject."""
        mock_subject = MagicMock()
        mock_subject.CN = subject_cn
        mock_x509.get_subject.return_value = mock_subject
        return mock_x509

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                          mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b'mock_cert_data'

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_details(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                  mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario with correct details output."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {**self.all_params,
                              'key_algo': 'rsa', 'key_size': 2048}
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, MagicMock()]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")
        details = exc.exception.args[0]['details']
        self.assertEqual(details['common_name'], 'test.example.com')
        self.assertEqual(details['organization'], 'TestOrg')
        self.assertEqual(details['organizational_unit'], 'IT')
        self.assertEqual(details['country'], 'US')
        self.assertEqual(details['state_or_province'], 'California')
        self.assertEqual(details['locality'], 'San Francisco')
        self.assertEqual(details['email_address'], 'admin@example.com')
        self.assertEqual(details['key_algo'], 'rsa')
        self.assertEqual(details['key_size'], 2048)
        self.assertEqual(exc.exception.args[0]['cert_modulus'], 'A1B2C3')
        self.assertEqual(exc.exception.args[0]['issuer_modulus'], 'A1B2C3')
        self.assertTrue(exc.exception.args[0]['modulus_match'])

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_success(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                  mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_cert, key_type='rsa', modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, MagicMock()]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")
        details = exc.exception.args[0]['details']
        self.assertEqual(details['common_name'], 'test.example.com')
        self.assertEqual(details['organization'], 'TestOrg')
        self.assertEqual(details['organizational_unit'], 'IT')
        self.assertEqual(details['country'], 'US')
        self.assertEqual(details['state_or_province'], 'California')
        self.assertEqual(details['locality'], 'San Francisco')
        self.assertEqual(details['email_address'], 'admin@example.com')
        self.assertEqual(details['key_algo'], 'rsa')
        self.assertEqual(details['key_size'], 2048)
        self.assertTrue(exc.exception.args[0]['modulus_match'])
        self.assertEqual(exc.exception.args[0]['cert_modulus'], 'A1B2C3')
        self.assertEqual(exc.exception.args[0]['issuer_modulus'], 'A1B2C3')
        self.assertTrue(exc.exception.args[0]['valid_signature'])

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
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        mock_cn = MagicMock(spec=NameAttribute)
        mock_cn.oid = NameOID.COMMON_NAME
        mock_cn.value = 'wrong.example.com'

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
        mock_subject.__iter__.return_value = [mock_cn, mock_org, mock_ou, mock_country, mock_state, mock_locality, mock_email]

        mock_cert.subject = mock_subject
        mock_cert.issuer = MagicMock()
        mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        mock_cert.not_valid_after_utc = datetime.now(
            timezone.utc) + timedelta(days=31)
        mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_cert.public_key.return_value = MagicMock(
            spec=ec.EllipticCurvePublicKey, key_size=256)
        mock_cert.public_bytes.return_value = b'mock_der_data'

        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [
            mock_cert, mock_issuer_cert, MagicMock()]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert, mock_issuer_openssl, MagicMock()]

        with self.assertRaisesRegex(AnsibleFailJson, "Common name mismatch"):
            module_main()

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
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
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
        mock_country.value = 'CA'  # Mismatch with self.all_params['country'] = 'US'

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
        mock_subject.__iter__.return_value = [mock_cn, mock_org, mock_ou, mock_country, mock_state, mock_locality,
                                              mock_email]

        mock_cert.subject = mock_subject
        mock_cert.issuer = MagicMock()
        mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
        mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=31)
        mock_cert.not_valid_before = mock_cert.not_valid_before_utc
        mock_cert.not_valid_after = mock_cert.not_valid_after_utc
        mock_public_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_public_key.key_size = 2048
        mock_public_key.public_numbers.return_value.n = int('A1B2C3', 16)  # Match issuer modulus
        mock_cert.public_key.return_value = mock_public_key
        mock_cert.public_bytes.return_value = b'mock_der_data'

        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert, MagicMock()]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_issuer_openssl = self._setup_openssl_x509_mock(MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [mock_cert, mock_issuer_openssl, MagicMock()]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaisesRegex(AnsibleFailJson, "Country mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_expired(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Certificate has expired"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_mixed_cert_types(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                   mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function success with EC certificate and RSA issuer."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params['key_algo'] = 'ec'
        mock_module.params['key_size'] = 256
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')

        # Create a mock for the EC public key to match the key_size parameter
        mock_ec_public_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        mock_ec_curve = MagicMock(spec=ec.EllipticCurve)
        mock_ec_curve.key_size = 256
        mock_ec_public_key.curve = mock_ec_curve
        mock_cert.public_key.return_value = mock_ec_public_key

        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [
            mock_cert, mock_issuer_cert, MagicMock()]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, MagicMock()]

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        # Assert that the module exits successfully
        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertFalse(exc.exception.args[0]['failed'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")

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
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.public_key.return_value = MagicMock(
            spec=ec.EllipticCurvePublicKey, key_size=256)
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Key algorithm mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_modulus_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                   mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key algorithm mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_cert, key_type='rsa', modulus='A1B2C3')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='B2C3A4')
        mock_parse_certificate.side_effect = [
            mock_cert, mock_issuer_cert, MagicMock()]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, MagicMock()]

        with self.assertRaisesRegex(AnsibleFailJson, "Modulus mismatch"):
            module_main()

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
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert)
        mock_cert.public_key.return_value = MagicMock(
            spec=rsa.RSAPublicKey, key_size=1024)
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Key size mismatch"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_ec_key_size_mismatch(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                       mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function key size mismatch failure."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_cert.public_key.return_value = MagicMock(
            spec=ec.EllipticCurvePublicKey, key_size=384)
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [
            mock_cert, mock_issuer_cert, MagicMock()]
        mock_read_cert_file.return_value = b'mock_cert_data'

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, MagicMock()]

        with self.assertRaisesRegex(AnsibleFailJson, "Key algorithm mismatch"):
            module_main()

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

        self.assertFalse(exc.exception.args[0]['changed'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "Check mode: All validations passed successfully")

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_certificate_checkend_failure(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
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
        mock_parse_certificate.return_value = mock_cert
        mock_read_cert_file.return_value = b'mock_cert_data'

        with self.assertRaisesRegex(AnsibleFailJson, "Certificate will expire within 86400 seconds"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_invalid_certificate(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                      mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function with invalid certificate file."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.check_mode = False
        mock_module.fail_json = fail_json
        mock_read_cert_file.return_value = b'invalid_cert_data'
        mock_parse_certificate.side_effect = AnsibleFailJson(
            {'msg': 'Failed to parse certificate: Invalid format'})
        with self.assertRaisesRegex(AnsibleFailJson, r"Failed to parse certificate"):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_issuer_validation(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                    mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function with issuer certificate validation."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params['chain_path'] = None
        mock_module.params['key_algo'] = 'ec'
        mock_module.params['key_size'] = 256
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')

        def read_cert_side_effect(path, module):
            if path == '/path/to/cert.pem':
                return b'mock_cert_data'
            elif path == '/path/to/issuer.pem':
                return b'mock_issuer_data'
            else:
                raise FileNotFoundError(f"Unexpected path: {path}")

        mock_read_cert_file.side_effect = read_cert_side_effect
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertTrue(exc.exception.args[0]['valid_signature'])
        self.assertEqual(
            exc.exception.args[0]['msg'], "All certificate validations passed successfully")

    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_no_verification_params(self, mock_ansible_module):
        """Test main function failure when no verification properties are provided."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = {
            'path': '/path/to/cert.pem',
            'chain_path': None,
            'issuer_path': None,
            'common_name': None,
            'organization': None,
            'organizational_unit': None,
            'country': None,
            'state_or_province': None,
            'locality': None,
            'email_address': None,
            'key_algo': None,
            'key_size': None,
            'validate_expired': False,
            'validate_checkend': False,
            'checkend_value': 86400,
        }
        mock_module.fail_json = fail_json
        with self.assertRaisesRegex(AnsibleFailJson, "At least one verification property must be provided."):
            module_main()

    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.X509StoreContext")
    @patch("OpenSSL.crypto.X509Store")
    @patch(f"{MODULE_PATH}._parse_certificate")
    @patch(f"{MODULE_PATH}._read_cert_file")
    @patch(f"{MODULE_PATH}.AnsibleModule")
    def test_main_success_with_chain(self, mock_ansible_module, mock_read_cert_file, mock_parse_certificate,
                                     mock_x509_store, mock_x509_store_context, mock_load_certificate):
        """Test main function success scenario with chain certificates."""
        mock_module = MagicMock()
        mock_ansible_module.return_value = mock_module
        mock_module.params = self.all_params
        mock_module.params['key_algo'] = 'ec'
        mock_module.params['key_size'] = 256
        mock_module.check_mode = False
        mock_module.exit_json = exit_json
        mock_module.fail_json = fail_json

        mock_cert = MagicMock()
        self._setup_valid_cert_mock(mock_cert, key_type='ec')
        mock_issuer_cert = MagicMock()
        self._setup_valid_cert_mock(
            mock_issuer_cert, key_type='rsa', modulus='A1B2C3')
        mock_parse_certificate.side_effect = [mock_cert, mock_issuer_cert]

        def read_cert_side_effect(path, module):
            if path == '/path/to/cert.pem':
                return b'mock_cert_data'
            elif path == '/path/to/issuer.pem':
                return b'mock_issuer_data'
            elif path == '/path/to/chain.pem':
                return b'-----BEGIN CERTIFICATE-----\nmock_chain_cert\n-----END CERTIFICATE-----\n'
            else:
                raise FileNotFoundError(f"Unexpected path: {path}")

        mock_read_cert_file.side_effect = read_cert_side_effect

        mock_cert_openssl = MagicMock()
        mock_issuer_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='ca-root')
        mock_chain_openssl = self._setup_openssl_x509_mock(
            MagicMock(), subject_cn='intermediate-ca')
        mock_load_certificate.side_effect = [
            mock_cert_openssl, mock_issuer_openssl, mock_chain_openssl]

        mock_store = MagicMock()
        mock_x509_store.return_value = mock_store
        mock_store_ctx = MagicMock()
        mock_x509_store_context.return_value = mock_store_ctx
        mock_store_ctx.verify_certificate.return_value = None

        with self.assertRaises(AnsibleExitJson) as exc:
            module_main()

        self.assertTrue(exc.exception.args[0]['valid'])
        self.assertEqual(exc.exception.args[0]['msg'],
                         "All certificate validations passed successfully")
        self.assertTrue(exc.exception.args[0]['valid_signature'])
        self.assertIsNone(exc.exception.args[0]['modulus_match'])


if __name__ == '__main__':
    ModuleTestCase.main()
