#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: x509_certificate_verify
short_description: Verify X.509 certificate properties and signature
author:
  - "Lee Johnson (@lj020326)"
version_added: "2025.9.0"
description:
  - Verifies that a certificate is cryptographically signed by an issuer certificate and validates specified properties.
  - Checks certificate attributes like common name, organization, organizational unit, country, state or province, locality, and email address.
  - Validates certificate serial number, version, and signature algorithm if provided.
  - Validates certificate expiration and proximity to expiration using a checkend threshold.
  - Validates public key algorithm and size if provided.
  - Compares the modulus of RSA public keys between the certificate and issuer certificate (if provided and both are RSA).
  - Uses OpenSSL for cryptographic signature verification and Python's cryptography library for property validation.
options:
  path:
    description:
      - Path to the certificate file to verify (PEM or DER format).
    required: true
    type: path
  issuer_path:
    description:
      - Path to the issuer (CA) certificate file (PEM or DER format) used to verify the certificate's signature.
      - If this argument is provided, the module will automatically perform signature validation and modulus comparison (for RSA keys).
    type: path
  chain_path:
    description:
      - Path to a file containing intermediate certificates (PEM or DER format) to build the certificate chain for verification.
      - If provided, these certificates are added to the trust store for signature validation.
    type: path
  common_name:
    description:
      - Expected Common Name (CN) in the certificate's subject. If not provided, CN is not validated.
    type: str
  organization:
    description:
      - Expected Organization (O) in the certificate's subject. If not provided, O is not validated.
    type: str
  organizational_unit:
    description:
      - Expected Organizational Unit (OU) in the certificate's subject. If not provided, OU is not validated.
    type: str
  country:
    description:
      - Expected Country (C) in the certificate's subject. If not provided, Country is not validated.
    type: str
  state_or_province:
    description:
      - Expected State or Province (ST) in the certificate's subject. If not provided, State or Province is not validated.
    type: str
  locality:
    description:
      - Expected Locality (L) in the certificate's subject. If not provided, Locality is not validated.
    type: str
  email_address:
    description:
      - Expected Email Address in the certificate's subject. If not provided, Email Address is not validated.
    type: str
  serial_number:
    description:
      - Expected serial number of the certificate (decimal or hex string). If not provided, serial number is not validated.
    type: str
  version:
    description:
      - Expected version of the certificate (1 or 3). If not provided, version is not validated.
    type: int
  signature_algorithm:
    description:
      - Expected signature algorithm (e.g., sha256WithRSAEncryption). If not provided, signature algorithm is not validated.
    type: str
  key_algo:
    description:
      - Expected public key algorithm. If not provided, key algorithm is not validated.
    type: str
    choices:
      - rsa
      - ec
      - dsa
      - ed25519
  key_size:
    description:
      - Expected public key size in bits. If not provided, key size is not validated. (e.g., 2048 for RSA, 256 for EC).
    type: int
  validate_expired:
    description:
      - If set to true, the module will fail if the certificate has expired.
    type: bool
    default: true
  validate_checkend:
    description:
      - If set to true, the module will fail if the certificate expires within the checkend_value.
    type: bool
    default: false
  checkend_value:
    description:
      - The number of seconds before expiration to fail. Only effective if C(validate_checkend) is true.
    type: int
    default: 86400
  logging_level:
      description:
          - Parameter used to define the level of troubleshooting output.
      required: false
      choices: ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
      default: INFO
      type: str
requirements:
  - cryptography>=1.5
  - pyopenssl
notes:
  - The module works with both PEM and DER encoded certificates and keys.
  - At least one verification property must be provided.
  - Modulus comparison is performed only for RSA keys when issuer_path is provided.
  - Use chain_path to include intermediate certificates when verifying certificates not directly signed by the root CA.
  - For serial_number, provide as a decimal or hex string (with or without '0x').
  - For version, specify 1 for v1 or 3 for v3 certificates.
"""

EXAMPLES = r"""
- name: Verify certificate signature and properties
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/intermediate_ca.pem
    issuer_path: /etc/pki/ca-root.pem
    chain_path: /etc/pki/chain.pem
    common_name: foobar.example.int
    organization: MyOrg
    organizational_unit: IT
    country: US
    state_or_province: California
    locality: San Francisco
    email_address: admin@example.com
    serial_number: '12345'
    version: 3
    signature_algorithm: 'sha256WithRSAEncryption'
    key_algo: ec
    key_size: 256
    validate_expired: true
    validate_checkend: true
    checkend_value: 86400
    logging_level: INFO
  register: cert_verify_result

- name: Verify that a certificate has not expired
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
  register: verify_result

- name: Verify that a certificate will not expire in the next 30 days
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
    checkend_value: 2592000
  register: verify_result

- name: Validate public key details
  dettonville.utils.x509_certificate_verify:
    path: /etc/ssl/certs/service.pem
    key_algo: 'ec'
    key_size: 256
  register: key_validation
"""

RETURN = r"""
valid:
  description: Indicates if the certificate passed all validation checks.
  type: bool
  returned: always
  sample: true
failed:
  description: Indicates if the module task failed.
  type: bool
  returned: always
  sample: false
msg:
  description: Message indicating the result of the validation.
  type: str
  returned: always
  sample: "All certificate validations passed successfully"
details:
  description: Dictionary of validated certificate properties.
  type: dict
  returned: always
  sample: {"common_name": "my.example.com", "organization": "My Company", "key_algo": "rsa", "key_size": 2048}
verify_failed:
  description: Whether any verification checks failed.
  type: bool
  returned: always
  sample: false
verify_results:
  description: Dictionary of verification results with boolean values for each check.
  type: dict
  returned: always
  sample: {"common_name": true, "key_size": false}
valid_signature:
  description: Indicates if the certificate's signature was successfully verified against the issuer.
  type: bool
  returned: when issuer_path is provided
  sample: true
modulus_match:
  description: Indicates if the modulus of the certificate and issuer certificate match (only for RSA keys).
  type: bool
  returned: when issuer_path is provided and both certificates have RSA keys
  sample: false
cert_modulus:
  description: The modulus of the certificate's public key (hexadecimal string, only for RSA keys).
  type: str
  returned: when issuer_path is provided and the certificate has an RSA key
  sample: "a1b2c3..."
issuer_modulus:
  description: The modulus of the issuer certificate's public key (hexadecimal string, only for RSA keys).
  type: str
  returned: when issuer_path is provided and the issuer certificate has an RSA key
  sample: "a1b2c3..."
"""

from ansible.module_utils.basic import AnsibleModule
from datetime import datetime, timezone, timedelta
import logging
# import pprint
import traceback

# Handle cryptography imports
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.backends import default_backend
    import cryptography

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Handle pyOpenSSL imports
try:
    from OpenSSL import crypto

    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

HAS_LIBS = HAS_CRYPTOGRAPHY and HAS_PYOPENSSL


def _setup_logging(level):
    """Set up logging with the specified level."""
    logging.basicConfig(level=getattr(logging, level, logging.INFO))
    return logging.getLogger(__name__)

# Function to read certificate content


def _read_cert_file(path, module):
    """Read certificate file content."""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        module.fail_json(
            msg=f"Failed to read certificate file at {path}: {str(e)}")


# Function to parse certificate
def _parse_certificate(cert_content, module):
    """Parse certificate content as PEM or DER."""
    try:
        return x509.load_pem_x509_certificate(cert_content, default_backend())
    except ValueError:
        try:
            return x509.load_der_x509_certificate(cert_content, default_backend())
        except ValueError as e:
            module.fail_json(
                msg=f"Could not parse certificate. Must be PEM or DER format. Error: {e}")


# Function to load chain certificates
def _load_chain_certs(chain_content, module):
    """Load multiple certificates from a chain file (PEM or DER)."""
    chain_certs = []
    try:
        # Try PEM format
        pem_certs = chain_content.decode(
            'utf-8').split('-----END CERTIFICATE-----')
        for pem_cert in pem_certs:
            if pem_cert.strip():
                pem_cert = pem_cert + '-----END CERTIFICATE-----'
                try:
                    cert = crypto.load_certificate(
                        crypto.FILETYPE_PEM, pem_cert.encode('utf-8'))
                    chain_certs.append(cert)
                except crypto.Error:
                    continue  # Skip invalid PEM certificates
        if chain_certs:
            return chain_certs
    except UnicodeDecodeError:
        pass  # Fall back to DER if PEM decoding fails

    try:
        # Try DER format
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, chain_content)
        chain_certs.append(cert)
    except crypto.Error as e:
        module.fail_json(
            msg=f"Failed to load chain certificates. Ensure chain file is PEM or DER format. Error: {str(e)}")

    return chain_certs


# Function to verify certificate signature
def _verify_signature(cert, issuer_cert, chain_certs, module):
    """Verify certificate signature using issuer and chain."""
    if not HAS_PYOPENSSL:
        module.fail_json(
            msg="OpenSSL.crypto is required for signature verification but is not available. Ensure pyOpenSSL is installed.")
    try:
        store = crypto.X509Store()
        if issuer_cert:
            issuer_openssl = crypto.load_certificate(
                crypto.FILETYPE_PEM, issuer_cert.public_bytes(Encoding.PEM))
            store.add_cert(issuer_openssl)
        for chain_cert in chain_certs or []:
            chain_openssl = crypto.load_certificate(
                crypto.FILETYPE_PEM, chain_cert.public_bytes(Encoding.PEM))
            store.add_cert(chain_openssl)
        cert_openssl = crypto.load_certificate(
            crypto.FILETYPE_PEM, cert.public_bytes(Encoding.PEM))
        store_ctx = crypto.X509StoreContext(store, cert_openssl)
        store_ctx.verify_certificate()
        module.log.debug("Issuer signature valid!")
        return True
    except Exception as e:
        module.log.error(
            "Issuer signature invalid: %s (type: %s)", str(e), type(e).__name__)
        module.log.debug("Exception traceback: %s", traceback.format_exc())
        module.log.debug("Certificate issuer: %s", cert.issuer)
        module.log.debug("Issuer subject: %s",
                         issuer_cert.subject if issuer_cert else 'None')
        return False


def _get_modulus(public_key):
    """Extract modulus from an RSA public key, return None for non-RSA keys."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return hex(public_key.public_numbers().n)[2:].upper()
    return None


def parse_serial_number(serial_str):
    """Parse serial number string to integer, handling decimal or hex."""
    if serial_str.lower().startswith('0x'):
        serial_str = serial_str[2:]
        base = 16
    else:
        try:
            return int(serial_str)
        except ValueError:
            base = 16
    try:
        return int(serial_str, base)
    except ValueError:
        raise ValueError(f"Invalid serial number: {serial_str}")


# Main function
def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type="path", required=True),
            issuer_path=dict(type="path", required=False, default=None),
            chain_path=dict(type="path", required=False, default=None),
            common_name=dict(type="str", required=False, default=None),
            organization=dict(type="str", required=False, default=None),
            organizational_unit=dict(type="str", required=False, default=None),
            country=dict(type="str", required=False, default=None),
            state_or_province=dict(type="str", required=False, default=None),
            locality=dict(type="str", required=False, default=None),
            email_address=dict(type="str", required=False, default=None),
            serial_number=dict(type="str", required=False, default=None),
            version=dict(type="int", required=False, default=None),
            signature_algorithm=dict(type="str", required=False, default=None),
            key_algo=dict(
                type="str",
                required=False,
                default=None,
                choices=["rsa", "ec", "dsa", "ed25519"],
            ),
            key_size=dict(type="int", required=False, default=None),
            validate_expired=dict(type="bool", default=True),
            validate_checkend=dict(type="bool", default=False),
            checkend_value=dict(type="int", default=86400),
            logging_level=dict(
                type="str",
                choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                default="INFO"
            ),
        ),
        supports_check_mode=True,
    )

    if not HAS_LIBS:
        module.fail_json(
            msg="The 'pyopenssl' and 'cryptography' Python libraries are required."
        )

    log = _setup_logging(module.params['logging_level'])

    # Log cryptography version for debugging
    module.log(f"cryptography version: {cryptography.__version__}")
    log.info("cryptography version: %s", cryptography.__version__)

    # Warn if cryptography version is below 36.0.0
    version_parts = [int(part)
                     for part in cryptography.__version__.split(".")[:3]]
    if version_parts < [36, 0, 0]:
        module.warn(
            f"Cryptography version {cryptography.__version__} is below 36.0.0. Some features may not work correctly.")

    # Check if at least one verification property is provided
    verification_properties = [
        module.params.get('issuer_path'),
        module.params.get('chain_path'),
        module.params.get('common_name'),
        module.params.get('organization'),
        module.params.get('organizational_unit'),
        module.params.get('country'),
        module.params.get('state_or_province'),
        module.params.get('locality'),
        module.params.get('email_address'),
        module.params.get('serial_number'),
        module.params.get('version'),
        module.params.get('signature_algorithm'),
        module.params.get('key_algo'),
        module.params.get('key_size'),
    ]
    if module.params.get('validate_expired'):
        verification_properties.append(True)
    if module.params.get('validate_checkend'):
        verification_properties.append(True)
    if not any(verification_properties):
        module.fail_json(
            msg="At least one verification property must be provided.")

    if module.check_mode:
        module.exit_json(
            changed=False, msg="Check mode: All validations passed successfully")

    result = {
        'valid': True,
        'failed': False,
        'verify_failed': False,
        'msg': "All certificate validations passed successfully",
        'details': {},
    }
    verify_results = {}

    path = module.params['path']
    cert_content = _read_cert_file(path, module)
    cert = _parse_certificate(cert_content, module)

    issuer_path = module.params.get('issuer_path')
    chain_path = module.params.get('chain_path')

    issuer_crypto = None
    chain_certs = []
    if issuer_path:
        # Load issuer certificate
        issuer_content = _read_cert_file(issuer_path, module)
        issuer_crypto = _parse_certificate(issuer_content, module)

        if chain_path:
            chain_content = _read_cert_file(chain_path, module)
            chain_certs = _load_chain_certs(chain_content, module)

        # Verify certificate signature
        signature_valid = _verify_signature(
            cert, issuer_crypto, chain_certs, module)
        verify_results['signature_valid'] = signature_valid
        result["valid_signature"] = signature_valid
        if not signature_valid:
            result["valid"] = False
            result["verify_failed"] = True

        # Modulus comparison for RSA keys
        cert_modulus = _get_modulus(cert.public_key())
        issuer_modulus = _get_modulus(issuer_crypto.public_key())
        if cert_modulus is not None and issuer_modulus is not None:
            result['cert_modulus'] = cert_modulus
            result['issuer_modulus'] = issuer_modulus
            match = (cert_modulus == issuer_modulus)
            verify_results['modulus_match'] = match
            result['modulus_match'] = match
            log.debug("modulus_match => %s", match)
            if not match:
                result["valid"] = False
                result["verify_failed"] = True
        else:
            result['modulus_match'] = None
            result['cert_modulus'] = cert_modulus
            result['issuer_modulus'] = issuer_modulus

    log.debug("set timezone-aware validity dates")
    # Safely get timezone-aware validity dates
    try:
        valid_from = cert.not_valid_before_utc
        valid_until = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older versions
        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
        valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)

    result["details"]["valid_from"] = valid_from.isoformat()
    result["details"]["valid_until"] = valid_until.isoformat()

    # Extract details from the subject
    subject = cert.subject
    subject_dict = {
        attr.oid: attr.value
        for attr in subject
    }

    subject_fields = {
        'common_name': x509.NameOID.COMMON_NAME,
        'organization': x509.NameOID.ORGANIZATION_NAME,
        'organizational_unit': x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
        'country': x509.NameOID.COUNTRY_NAME,
        'state_or_province': x509.NameOID.STATE_OR_PROVINCE_NAME,
        'locality': x509.NameOID.LOCALITY_NAME,
        'email_address': x509.NameOID.EMAIL_ADDRESS,
    }

    for field, oid in subject_fields.items():
        expected = module.params.get(field)
        if expected is not None:
            actual = subject_dict.get(oid)
            match = (actual == expected)
            verify_results[field] = match
            result['details'][field] = actual
            if not match:
                result['valid'] = False
                result['verify_failed'] = True

    # Serial number validation
    expected_serial_str = module.params.get('serial_number')
    actual_serial = cert.serial_number
    result['details']['serial_number'] = str(actual_serial)
    if expected_serial_str is not None:
        try:
            expected_serial = parse_serial_number(expected_serial_str)
            match = (actual_serial == expected_serial)
            verify_results['serial_number'] = match
            if not match:
                result['valid'] = False
                result['verify_failed'] = True
        except ValueError as e:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = str(e)
            module.fail_json(**result)

    # Version validation
    cert_version_internal = cert.version.value
    cert_version_user = 1 if cert_version_internal == 0 else 3 if cert_version_internal == 2 else cert_version_internal
    result['details']['version'] = cert_version_user
    expected_version = module.params.get('version')
    if expected_version is not None:
        if expected_version not in [1, 3]:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Invalid version. Expected 1 or 3, found '{expected_version}'"
            module.fail_json(**result)
        expected_internal = 0 if expected_version == 1 else 2
        match = (cert_version_internal == expected_internal)
        verify_results['version'] = match
        if not match:
            result['valid'] = False
            result['verify_failed'] = True

    # Signature algorithm validation
    actual_sig_algo = cert.signature_algorithm_oid._name
    result['details']['signature_algorithm'] = actual_sig_algo
    expected_sig_algo = module.params.get('signature_algorithm')
    if expected_sig_algo is not None:
        match = (actual_sig_algo.lower() == expected_sig_algo.lower())
        verify_results['signature_algorithm'] = match
        if not match:
            result['valid'] = False
            result['verify_failed'] = True

    # Key algorithm and size validation
    public_key = cert.public_key()
    key_algo = None
    key_size = None
    if isinstance(public_key, rsa.RSAPublicKey):
        key_algo = 'rsa'
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algo = 'ec'
        key_size = public_key.curve.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_algo = 'dsa'
        key_size = public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_algo = 'ed25519'
        key_size = None  # Ed25519 has fixed size

    result['details']['key_algo'] = key_algo
    result['details']['key_size'] = key_size

    # Validate key algorithm
    expected_key_algo = module.params.get('key_algo')
    if expected_key_algo is not None:
        match = (key_algo is not None and key_algo.lower()
                 == expected_key_algo.lower())
        verify_results['key_algo'] = match
        if not match:
            result['valid'] = False
            result['verify_failed'] = True

    # Validate key size
    expected_key_size = module.params.get('key_size')
    if expected_key_size is not None:
        match = (key_size is not None and key_size == expected_key_size)
        verify_results['key_size'] = match
        if not match:
            result['valid'] = False
            result['verify_failed'] = True

    # Validate expiration
    if module.params["validate_expired"]:
        now = datetime.now(timezone.utc)
        module.log(f"now: {now}, not_valid_after: {valid_until}")
        expiry_valid = (valid_until > now)
        verify_results['expiry_valid'] = expiry_valid
        if not expiry_valid:
            result["valid"] = False
            result["verify_failed"] = True

    # Validate checkend (expiration proximity)
    if module.params["validate_checkend"]:
        checkend_time = now + \
            timedelta(seconds=module.params["checkend_value"])
        module.log(
            f"checkend_time: {checkend_time}, not_valid_after: {valid_until}")
        checkend_valid = (valid_until > checkend_time)
        verify_results['checkend_valid'] = checkend_valid
        if not checkend_valid:
            result["valid"] = False
            result["verify_failed"] = True

    if not result['valid']:
        result['msg'] = "Some certificate validations failed"

    result['verify_results'] = verify_results

    # If all validations pass
    module.exit_json(**result)


if __name__ == "__main__":
    main()
