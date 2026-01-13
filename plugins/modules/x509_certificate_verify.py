#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: x509_certificate_verify
short_description: Verify X.509 certificates
author:
  - "Lee Johnson (@lj020326)"
version_added: "2025.9.0"
description:
  - This module is intended for idempotent verification of certificates in playbooks.
  - This module verifies properties of an X.509 certificate, such as common name, organization,
    serial number, signature algorithm, key algorithm, and expiration status.
  - This module also can verify the certificate's signature against an issuer CA certificate, chain or CA bundle.
  - This module also can verify the certificate's private key matches the CA certificate.
options:
  path:
    description:
      - Path to the certificate file to verify (PEM or DER format).
    required: false
    type: path
  content:
    description:
      - Base64 encoded certificate content (PEM or DER format).
      - If provided, this takes precedence over C(path).
    required: false
    type: str
  ca_path:
    description:
      - Path to the issuer CA certificate, chain file (PEM or DER format), or bundle for signature verification.
    required: false
    type: path
  issuer_ca_path:
    description:
      - Deprecated. Use C(ca_path) instead. Path to the issuer CA certificate.
    required: false
    type: path
  private_key_path:
    description:
      - Path to the private key file to verify against the certificate's public key.
      - If specified, performs a match test between the certificate's public key and the private key.
    type: path
    default: null
  private_key_content:
    description:
      - Base64 encoded private key content (PEM format).
      - If provided, this takes precedence over C(private_key_path).
    type: str
    required: false
  private_key_password:
    type: str
    description:
      - Private key password.
    required: false
  common_name:
    description:
      - Expected Common Name (CN) of the certificate subject.
    required: false
    type: str
  organization:
    description:
      - Expected Organization (O) of the certificate subject.
    required: false
    type: str
  organizational_unit:
    description:
      - Expected Organizational Unit (OU) of the certificate subject.
    required: false
    type: str
  country:
    description:
      - Expected Country (C) of the certificate subject.
    required: false
    type: str
  state_or_province:
    description:
      - Expected State or Province (ST) of the certificate subject.
    required: false
    type: str
  locality:
    description:
      - Expected Locality (L) of the certificate subject.
    required: false
    type: str
  email_address:
    description:
      - Expected Email Address of the certificate subject.
    required: false
    type: str
  serial_number:
    description:
      - Expected serial number of the certificate (in decimal or hexadecimal format, e.g., '12345' or '0x3039').
    required: false
    type: str
  version:
    description:
      - Expected certificate version (1 or 3).
    required: false
    type: int
    choices: [1, 3]
  signature_algorithm:
    description:
      - Expected signature algorithm (e.g., 'sha256WithRSAEncryption').
    required: false
    type: str
  key_algo:
    description:
      - Expected public key algorithm (e.g., 'rsa', 'ec', 'dsa', 'ed25519').
    required: false
    type: str
    choices:
      - rsa
      - ec
      - dsa
      - ed25519
  key_size:
    description:
      - Expected key size in bits (e.g., 2048 for RSA/DSA, 256 for EC). Not applicable for Ed25519.
    required: false
    type: int
  validate_expired:
    description:
      - Whether to check if the certificate is expired.
    required: false
    type: bool
    default: true
  validate_checkend:
    description:
      - Whether to check if the certificate expires within a specified time (seconds).
    required: false
    type: bool
    default: true
  validate_is_ca:
    description:
      - Whether to validate that the certificate is a CA certificate by checking basicConstraints for CA=TRUE.
    required: false
    type: bool
    default: false
  validate_modulus_match:
    description:
      - Whether to verify if the certificate's modulus matches its direct issuer's modulus.
      - Only applies to RSA keys.
      - Logic will handle setting this to True if ca_path is present
      - default is true if ca_path is provided
    type: bool
  checkend_value:
    description:
      - Number of seconds to check for impending expiration (used with validate_checkend).
    required: false
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
  - Exactly one of C(path) or C(content) must be provided for the certificate.
  - At least one verification property must be provided (e.g., common_name, serial_number, validate_expired=True, or ca_path).
  - Modulus comparison is performed only for RSA keys when ca_path is provided.
  - Use ca_path to include the issuer certificate or certificate chain when verifying certificates.
  - For serial_number, provide as a decimal or hex string (with or without '0x').
  - For version, specify 1 for v1 or 3 for v3 certificates.
  - The issuer_ca_path parameter is deprecated in favor of ca_path.
  - When logging_level is set to DEBUG, a full stack trace is logged for any exceptions.
  - When logging_level is set to DEBUG, additional certificate metadata and environment details are included.
  - If not_valid_after_utc is unavailable in cryptography >= 41.0.0, an error is logged, indicating a potential library or environment issue.
  - If cryptography is loaded from a system-wide path in a virtual environment, a warning is logged to indicate potential version mismatches.
  - The module modifies sys.path to prioritize the virtual environment's cryptography installation over system-wide paths.
  - Certificate can be provided via C(path) or C(content) (base64 encoded). C(content) takes precedence.
  - Private key can be provided via C(private_key_path) or C(private_key_content) (base64 encoded). C(private_key_content) takes precedence.
"""

RETURN = r"""
failed:
  description: Indicates if the module failed.
  type: bool
  returned: always
valid:
  description: Whether all specified validations passed.
  type: bool
  returned: always
verify_failed:
  description: Whether any validation checks failed.
  type: bool
  returned: always
msg:
  description: A message describing the result of the verification.
  type: str
  returned: always
  sample: "All certificate validations passed successfully"
details:
  description: Details about the certificate's properties.
  type: dict
  returned: always
  contains:
    common_name:
      description: Common Name (CN) of the certificate.
      type: str
    organization:
      description: Organization (O) of the certificate.
      type: str
    organizational_unit:
      description: Organizational Unit (OU) of the certificate.
      type: str
    country:
      description: Country (C) of the certificate.
      type: str
    state_or_province:
      description: State or Province (ST) of the certificate.
      type: str
    locality:
      description: Locality (L) of the certificate.
      type: str
    email_address:
      description: Email Address of the certificate.
      type: str
    serial_number:
      description: Serial number of the certificate.
      type: str
    version:
      description: Version of the certificate.
      type: int
    signature_algorithm:
      description: Signature algorithm of the certificate.
      type: str
    key_algo:
      description: Public key algorithm of the certificate.
      type: str
    key_size:
      description: Key size in bits (if applicable).
      type: int
    ca_path:
      description: Path to the CA certificate, chain, or bundle used for verification (if provided).
      type: str
  sample: {"common_name": "my.example.com", "organization": "My Company", "key_algo": "rsa", "key_size": 2048}
verify_results:
  description: Results of individual verification checks.
  type: dict
  returned: always
  contains:
    common_name:
      description: Whether the common name matched.
      type: bool
    organization:
      description: Whether the organization matched.
      type: bool
    organizational_unit:
      description: Whether the organizational unit matched.
      type: bool
    country:
      description: Whether the country matched.
      type: bool
    state_or_province:
      description: Whether the state or province matched.
      type: bool
    locality:
      description: Whether the locality matched.
      type: bool
    email_address:
      description: Whether the email address matched.
      type: bool
    serial_number:
      description: Whether the serial number matched.
      type: bool
    version:
      description: Whether the version matched.
      type: bool
    signature_algorithm:
      description: Whether the signature algorithm matched.
      type: bool
    key_algo:
      description: Whether the key algorithm matched.
      type: bool
    key_size:
      description: Whether the key size matched.
      type: bool
    expiry_valid:
      description: Whether the certificate is not expired.
      type: bool
    checkend_valid:
      description: Whether the certificate does not expire within checkend_value seconds.
      type: bool
    is_ca:
      description: Whether the certificate has CA:TRUE in basicConstraints (if validate_is_ca is true).
      type: bool
    signature_valid:
      description: Whether the signature is valid (if ca_path is provided).
      type: bool
    modulus_match:
      description: Whether the certificate and issuer CA moduli match (if applicable).
      type: bool
    private_key_match:
      description: Whether the private key matches the certificate (only if private_key_path or private_key_content provided).
      type: bool
  sample: {"common_name": true, "key_size": false, "expiry_valid": true, "checkend_valid": true, "signature_valid": true, "modulus_match": true}
cert_modulus:
  description: Modulus of the certificate's public key (hexadecimal, if applicable).
  type: str
  returned: when ca_path is provided and the certificate has an RSA key
  sample: "a1b2c3..."
issuer_modulus:
  description: Modulus of the issuer CA's public key (hexadecimal, if applicable).
  type: str
  returned: when ca_path is provided and the issuer certificate has an RSA key
  sample: "a1b2c3..."
"""

EXAMPLES = r"""
- name: Verify certificate chain
  dettonville.utils.x509_certificate_verify:
    path: /path/to/cert.pem
    ca_path: /path/to/ca-bundle.pem

- name: Verify certificate with private key match
  dettonville.utils.x509_certificate_verify:
    path: /path/to/cert.pem
    private_key_path: /path/to/key.pem

- name: Verify certificate from base64 content
  dettonville.utils.x509_certificate_verify:
    content: "{{ cert_b64_content }}"
    common_name: test.example.com
    validate_expired: true

- name: Verify certificate with private key from content
  dettonville.utils.x509_certificate_verify:
    path: /path/to/cert.pem
    private_key_content: "{{ key_b64_content }}"
    private_key_password: "{{ key_pass }}"
    validate_expired: true

- name: Verify a root CA certificate
  dettonville.utils.x509_certificate_verify:
    path: /path/to/root-ca.pem
    validate_is_ca: true
    validate_checkend: true
    checkend_value: 2592000  # 30 days

- name: Verify a certificate's properties
  dettonville.utils.x509_certificate_verify:
    path: /path/to/cert.pem
    common_name: test.example.com
    organization: TestOrg
    validate_expired: true
    validate_checkend: true
    checkend_value: 86400

- name: Verify a certificate with CA signature
  dettonville.utils.x509_certificate_verify:
    path: /path/to/cert.pem
    ca_path: /path/to/ca.pem
    common_name: test.example.com
    serial_number: '12345'
    signature_algorithm: sha256WithRSAEncryption
    key_algo: rsa
    key_size: 2048

- name: Verify that a certificate will not expire in the next 30 days
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
    checkend_value: 2592000
    logging_level: DEBUG
  register: verify_result

- name: Validate public key details
  dettonville.utils.x509_certificate_verify:
    path: /etc/ssl/certs/service.pem
    key_algo: ec
    key_size: 256
  register: key_validation
"""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from datetime import datetime, timezone, timedelta
import os
import sys
import traceback
import logging

HAS_CRYPTOGRAPHY = False
cryptography_version = "0.0.0"  # Initialize with a default value

# Handle cryptography imports
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography import __version__ as cryptography_version

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

HAS_PYOPENSSL = False

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
def _read_cert_file(path):
    """Read certificate file content."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        raise Exception("Failed to read certificate file {}: {}".format(path, str(e)))


def _parse_certificate(data):
    """Parse certificate data (PEM or DER format)."""
    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
        if not isinstance(cert, x509.Certificate):
            raise ValueError(
                f"Parsed certificate is not a valid x509.Certificate object, got {type(cert)}"
            )
        return cert
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data, default_backend())
            if not isinstance(cert, x509.Certificate):
                raise ValueError(
                    f"Parsed certificate is not a valid x509.Certificate object, got {type(cert)}"
                )
            return cert
        except ValueError as e:
            raise ValueError(
                "Could not parse certificate. Must be PEM or DER format. Error: {}".format(
                    str(e)
                )
            )


def _load_ca_certs(path):
    try:
        data = _read_cert_file(path)
        certs = []
        if b"-----BEGIN CERTIFICATE-----" in data:
            # Handle PEM bundle/chain
            # Use a regex or better splitting to avoid empty segments
            import re
            pem_blocks = re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL)
            for cert_data in pem_blocks:
                certs.append(_parse_certificate(cert_data))
        else:
            # Handle single DER
            certs.append(_parse_certificate(data))
        return certs
    except Exception as e:
        raise Exception("Failed to load CA certificates from {}: {}".format(path, str(e)))


# Function to verify certificate signature
# Function to verify certificate signature
def _verify_signature(cert, ca_certs):
    # Try standard chain verification first
    store = crypto.X509Store()
    cert_openssl = crypto.load_certificate(
        crypto.FILETYPE_PEM, cert.public_bytes(serialization.Encoding.PEM)
    )

    for ca_cert in ca_certs:
        ca_openssl = crypto.load_certificate(
            crypto.FILETYPE_PEM, ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        store.add_cert(ca_openssl)

    try:
        store_ctx = crypto.X509StoreContext(store, cert_openssl)
        store_ctx.verify_certificate()
        return True
    except (crypto.Error, crypto.X509StoreContextError):
        # Fallback: Check if any individual cert in the bundle is the direct signer
        # This handles cases where the full chain to root isn't in the bundle
        for ca_cert in ca_certs:
            try:
                public_key = ca_cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm),
                    )
                elif isinstance(public_key, dsa.DSAPublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        dsa.DSA(cert.signature_hash_algorithm),
                    )
                elif isinstance(public_key, ed25519.Ed25519PublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                    )
                else:
                    # Unsupported key type
                    continue
                return True
            except Exception:
                continue
    return False


def _get_modulus(public_key):
    """Get the modulus of a public key (if applicable)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "{:X}".format(public_key.public_numbers().n)
        # return hex(public_key.public_numbers().n)[2:].upper()

    return None


def verify_private_key_match(cert, priv_key):
    try:
        pub_from_cert = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_from_key = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_from_cert == pub_from_key
    except Exception:
        return False


def main():
    """Main module function."""
    module_args = dict(
        path=dict(type='path', required=False),
        content=dict(type='str', required=False),
        ca_path=dict(type='path', required=False),
        issuer_ca_path=dict(type='path', required=False),
        private_key_path=dict(type='path', required=False),
        private_key_content=dict(type='str', required=False, no_log=True),
        private_key_password=dict(type='str', required=False, no_log=True),
        common_name=dict(type='str', required=False),
        organization=dict(type='str', required=False),
        organizational_unit=dict(type='str', required=False),
        country=dict(type='str', required=False),
        state_or_province=dict(type='str', required=False),
        locality=dict(type='str', required=False),
        email_address=dict(type='str', required=False),
        serial_number=dict(type='str', required=False),
        version=dict(type='int', required=False, choices=[1, 3]),
        signature_algorithm=dict(type='str', required=False),
        key_algo=dict(
            type='str',
            required=False,
            default=None,
            choices=["rsa", "ec", "dsa", "ed25519"],
        ),
        key_size=dict(type='int', required=False),
        validate_expired=dict(type='bool', required=False, default=True),
        validate_checkend=dict(type='bool', required=False, default=True),
        validate_is_ca=dict(type='bool', default=False),
        validate_modulus_match=dict(type='bool', default=None),
        checkend_value=dict(type='int', required=False, default=86400),
        logging_level=dict(
            type='str',
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
        ),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if not HAS_LIBS:
        module.fail_json(
            msg=missing_required_lib(
                "'pyopenssl' and 'cryptography' Python libraries are required."
            )
        )

    # Set up logging
    log = _setup_logging(module.params["logging_level"])

    # Prioritize virtual environment by removing system-wide paths
    # sys_path_removed = False
    # for path in sys.path[:]:
    #     if path.startswith("/usr/lib/python3/dist-packages"):
    #         sys.path.remove(path)
    #         sys_path_removed = True
    # if sys_path_removed:
    #     log.debug(
    #         "Removed system-wide path /usr/lib/python3/dist-packages from sys.path to prioritize virtual environment"
    #     )

    # # Re-import cryptography to ensure virtual environment version is used
    # try:
    #     from cryptography import x509
    #     from cryptography import __version__ as cryptography_version
    #     HAS_CRYPTOGRAPHY = True
    # except ImportError:
    #     HAS_CRYPTOGRAPHY = False
    #     module.fail_json(msg=missing_required_lib(
    #         "cryptography Python library is required after sys.path adjustment."))

    # Log environment details for debugging
    log.debug("Python version: %s", sys.version)
    log.debug("Python executable: %s", sys.executable)
    log.debug("cryptography module path: %s", os.path.dirname(x509.__file__))
    log.debug(
        "cryptography runtime version: %s", getattr(x509, "__version__", "Unknown")
    )

    # Log cryptography version for debugging
    module.log(f"cryptography version: {cryptography_version}")
    log.info("cryptography version: %s", cryptography_version)

    # Warn if cryptography version is below 36.0.0
    version_parts = [int(part) for part in cryptography_version.split(".")[:3]]
    if version_parts < [36, 0, 0]:
        module.warn(
            f"Cryptography version {cryptography_version} is below 36.0.0. Some features may not work correctly."
        )

    cert_path = module.params.get('path')
    content = module.params.get('content')
    if content and cert_path:
        module.warn("Both path and content provided; using content.")
    if not content and not cert_path:
        module.fail_json(msg="Exactly one of path or content must be provided for the certificate.")

    ca_path = module.params.get("ca_path")
    if module.params.get("issuer_ca_path"):
        module.warn("issuer_ca_path is deprecated. Use ca_path instead.")
        ca_path = module.params.get("issuer_ca_path")

    private_key_path = module.params.get("private_key_path")
    private_key_content = module.params.get("private_key_content")
    private_key_password = module.params.get("private_key_password")

    # Validate version parameter explicitly
    if module.params.get("version") is not None and module.params.get(
        "version"
    ) not in [1, 3]:
        module.fail_json(
            msg="Invalid version: {}. Must be 1 or 3.".format(
                module.params.get("version")
            )
        )

    # Check if at least one verification property is provided
    non_boolean_properties = [
        "common_name",
        "organization",
        "organizational_unit",
        "country",
        "state_or_province",
        "locality",
        "email_address",
        "serial_number",
        "version",
        "signature_algorithm",
        "key_algo",
        "key_size",
    ]
    boolean_properties = ["validate_expired", "validate_checkend", "validate_is_ca"]
    has_verification = (
        any(module.params.get(prop) is not None for prop in non_boolean_properties)
        or any(module.params.get(prop) is True for prop in boolean_properties)
        or ca_path is not None
        or private_key_path is not None
        or private_key_content is not None
    )
    if not has_verification:
        module.fail_json(msg="At least one verification property must be provided.")

    result = {
        "failed": False,
        "valid": True,
        "verify_failed": False,
        "msg": "All certificate validations passed successfully",
        "details": {},
        "verify_results": {},
        "cert_modulus": None,
        "issuer_modulus": None,
    }

    # In check mode, skip file operations and return success
    if module.check_mode:
        module.exit_json(**result)

    verify_results = {}

    try:
        # Read and parse the certificate
        if content:
            import base64
            try:
                cert_data = base64.b64decode(content)
            except Exception as e:
                module.fail_json(msg=f"Failed to decode certificate content: {to_native(e)}")
        else:
            cert_data = _read_cert_file(cert_path)
        log.debug(
            "Certificate data read from %s: %s bytes",
            cert_path if cert_path else "content",
            len(cert_data),
        )
        cert = _parse_certificate(cert_data)
        log.debug("Parsed certificate type: %s", type(cert))
        public_key = cert.public_key()
        try:
            log.debug("Certificate not_before: %s", cert.not_valid_before)
            log.debug("Certificate not_after: %s", cert.not_valid_after)
            log.debug(
                "Certificate not_before_utc: %s",
                getattr(cert, "not_valid_before_utc", "Not available"),
            )
            log.debug(
                "Certificate not_after_utc: %s",
                getattr(cert, "not_valid_after_utc", "Not available"),
            )
        except Exception as e:
            log.debug("Failed to log certificate validity dates: %s", str(e))

        # Extract certificate details
        result["details"] = {
            "common_name": None,
            "organization": None,
            "organizational_unit": None,
            "country": None,
            "state_or_province": None,
            "locality": None,
            "email_address": None,
            "serial_number": str(cert.serial_number),
            # cryptography uses 0-based, X.509 uses 1-based
            "version": cert.version.value + 1,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "key_algo": None,
            "key_size": None,
        }

        # Include ca_path in details if defined
        if ca_path:
            result["details"]["ca_path"] = ca_path

        # Extract subject attributes
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                result["details"]["common_name"] = attr.value
            elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                result["details"]["organization"] = attr.value
            elif attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                result["details"]["organizational_unit"] = attr.value
            elif attr.oid == x509.oid.NameOID.COUNTRY_NAME:
                result["details"]["country"] = attr.value
            elif attr.oid == x509.oid.NameOID.STATE_OR_PROVINCE_NAME:
                result["details"]["state_or_province"] = attr.value
            elif attr.oid == x509.oid.NameOID.LOCALITY_NAME:
                result["details"]["locality"] = attr.value
            elif attr.oid == x509.oid.NameOID.EMAIL_ADDRESS:
                result["details"]["email_address"] = attr.value

        # Determine key algorithm and size
        if isinstance(public_key, rsa.RSAPublicKey):
            result["details"]["key_algo"] = "rsa"
            result["details"]["key_size"] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            result["details"]["key_algo"] = "ec"
            result["details"]["key_size"] = public_key.curve.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            result["details"]["key_algo"] = "dsa"
            result["details"]["key_size"] = public_key.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            result["details"]["key_algo"] = "ed25519"
            result["details"]["key_size"] = None

        # Initialize verification results
        for prop in non_boolean_properties:
            verify_results[prop] = True

        # Perform property verifications
        if module.params.get("common_name"):
            verify_results["common_name"] = result["details"][
                "common_name"
            ] == module.params.get("common_name")
        if module.params.get("organization"):
            verify_results["organization"] = result["details"][
                "organization"
            ] == module.params.get("organization")
        if module.params.get("organizational_unit"):
            verify_results["organizational_unit"] = result["details"][
                "organizational_unit"
            ] == module.params.get("organizational_unit")
        if module.params.get("country"):
            verify_results["country"] = result["details"][
                "country"
            ] == module.params.get("country")
        if module.params.get("state_or_province"):
            verify_results["state_or_province"] = result["details"][
                "state_or_province"
            ] == module.params.get("state_or_province")
        if module.params.get("locality"):
            verify_results["locality"] = result["details"][
                "locality"
            ] == module.params.get("locality")
        if module.params.get("email_address"):
            verify_results["email_address"] = result["details"][
                "email_address"
            ] == module.params.get("email_address")
        if module.params.get("serial_number"):
            try:
                expected_serial = module.params.get("serial_number")
                if expected_serial.startswith("0x"):
                    expected_serial = str(int(expected_serial, 16))
                elif not expected_serial.isdigit():
                    raise ValueError(
                        "Serial number must be a valid decimal or hexadecimal number"
                    )
                verify_results["serial_number"] = (
                    result["details"]["serial_number"] == expected_serial
                )
            except ValueError:
                module.fail_json(
                    msg="Invalid serial number: {}. Must be a valid decimal or hexadecimal number.".format(
                        module.params.get("serial_number")
                    )
                )
        if module.params.get("version"):
            verify_results["version"] = result["details"][
                "version"
            ] == module.params.get("version")
        if module.params.get("signature_algorithm"):
            verify_results["signature_algorithm"] = result["details"][
                "signature_algorithm"
            ] == module.params.get("signature_algorithm")
        if module.params.get("key_algo"):
            verify_results["key_algo"] = result["details"][
                "key_algo"
            ] == module.params.get("key_algo")
        if module.params.get("key_size") and result["details"]["key_algo"] != "ed25519":
            verify_results["key_size"] = result["details"][
                "key_size"
            ] == module.params.get("key_size")
        elif (
            module.params.get("key_size") and result["details"]["key_algo"] == "ed25519"
        ):
            # Ed25519 has no key size
            verify_results["key_size"] = True

        # Check if it's a CA certificate
        if module.params.get("validate_is_ca"):
            is_ca = False
            try:
                bc_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
                is_ca = bc_ext.value.ca
                log.debug("basicConstraints CA: %s", is_ca)
            except x509.ExtensionNotFound:
                log.debug("basicConstraints extension not found; not a CA")
                is_ca = False
            except Exception as e:
                log.error("Error checking basicConstraints: %s", e)
                is_ca = False
            verify_results["is_ca"] = is_ca
        else:
            verify_results["is_ca"] = True

        # Check expiration with fallback for older cryptography versions
        try:
            not_valid_after = cert.not_valid_after_utc
            log.debug("Using not_valid_after_utc for expiration check")
        except AttributeError as e:
            if version_parts < [41, 0, 0]:
                log.warning(
                    "not_valid_after_utc not available in cryptography %s, falling back to not_valid_after",
                    cryptography_version,
                )
            not_valid_after = cert.not_valid_after
            if not_valid_after.tzinfo is None:
                # Convert naive datetime to UTC
                not_valid_after = not_valid_after.replace(tzinfo=timezone.utc)
            # Log additional diagnostics when falling back
            log.debug("Fallback not_valid_after: %s", not_valid_after)
            log.debug("Certificate object attributes: %s", dir(cert))

        if module.params.get("validate_expired"):
            verify_results["expiry_valid"] = not_valid_after >= datetime.now(
                timezone.utc
            )
        else:
            verify_results["expiry_valid"] = True

        # Check impending expiration
        if module.params.get("validate_checkend"):
            verify_results["checkend_valid"] = (
                not_valid_after
                >= datetime.now(timezone.utc)
                + timedelta(seconds=module.params.get("checkend_value"))
            )
        else:
            verify_results["checkend_valid"] = True

        validate_modulus_match = module.params.get('validate_modulus_match')
        if validate_modulus_match is None:
            validate_modulus_match = True if ca_path else False

        # Verify signature if ca_path is provided
        if ca_path:
            ca_certs = _load_ca_certs(ca_path)
            # 1. Cryptographic signature check (should be independent)
            verify_results["signature_valid"] = _verify_signature(
                cert, ca_certs
            )
            # 2. Modulus check logic
            if isinstance(public_key, rsa.RSAPublicKey) and ca_certs:
                cert_modulus = _get_modulus(cert.public_key())
                result["cert_modulus"] = cert_modulus
                # result["issuer_modulus"] = _get_modulus(ca_certs[0].public_key())
                # verify_results["modulus_match"] = (
                #     result["cert_modulus"] == result["issuer_modulus"]
                # )
            # else:
            #     verify_results["modulus_match"] = True

            # Modulus Match Logic
            if validate_modulus_match and isinstance(cert.public_key(), rsa.RSAPublicKey):
                modulus_match = False
                # cert_modulus = hex(cert.public_key().public_numbers().n)[2:].upper()

                # Traverse CA bundle to find the direct issuer by modulus
                issuer_cert = None
                issuer_modulus = None
                for ca in ca_certs:
                    # Match by Subject DN (Issuer of cert == Subject of CA)
                    issuer_modulus = _get_modulus(ca.public_key())
                    # if ca.subject == cert.issuer:
                    #    modulus_match = (cert_modulus == issuer_modulus)
                    if cert_modulus == issuer_modulus:
                        result["issuer_modulus"] = issuer_modulus
                        issuer_cert = ca
                        modulus_match = True
                        break

                # if issuer_cert:
                #     if isinstance(issuer_cert.public_key(), rsa.RSAPublicKey):
                #         issuer_modulus = hex(issuer_cert.public_key().public_numbers().n)[2:].upper()
                #         modulus_match = (cert_modulus == issuer_modulus)
                #         if not modulus_match:
                #             log.error("Modulus mismatch between leaf and direct issuer")
                #     else:
                #         log.info("Direct issuer found but does not use RSA; skipping modulus match")
                #         modulus_match = True  # Skip if not RSA
                # else:
                #     log.warning("Direct issuer not found in ca_path; skipping modulus match")
                #     modulus_match = True  # Skip if direct issuer not in bundle

                verify_results['modulus_match'] = modulus_match
        # else:
        #     verify_results["signature_valid"] = True
        #     # verify_results["modulus_match"] = True

        # Verify private key match if private_key_path or private_key_content provided
        if private_key_path or private_key_content:
            private_key_match = False
            private_key_verify_msg = None
            key_data = None
            if private_key_content:
                import base64
                try:
                    key_data = base64.b64decode(private_key_content)
                except Exception as e:
                    private_key_verify_msg = f"Failed to decode private key content: {to_native(e)}"
            elif private_key_path:
                if not os.path.exists(private_key_path):
                    private_key_verify_msg = f"Private key path {private_key_path} does not exist"
                else:
                    key_data = _read_cert_file(private_key_path)
            if key_data is not None:
                try:
                    priv_key = serialization.load_pem_private_key(
                        key_data,
                        password=private_key_password.encode() if private_key_password else None,
                        backend=default_backend()
                    )
                    private_key_match = verify_private_key_match(cert, priv_key)
                    if not private_key_match:
                        private_key_verify_msg = "Private key does not match certificate public key"
                except Exception as e:
                    private_key_verify_msg = f"Failed to load or verify private key: {to_native(e)}"
            verify_results['private_key_match'] = private_key_match
            if private_key_verify_msg:
                log.error(private_key_verify_msg)

    except Exception as e:
        log.error(
            "Exception occurred: %s\nStack trace:\n%s",
            str(e),
            "".join(traceback.format_tb(e.__traceback__)),
        )
        module.fail_json(msg=str(e), failed=True)

    # Update result based on verification results
    if not all(verify_results.values()):
        result["valid"] = False
        result["verify_failed"] = True
        result["msg"] = "One or more certificate validations failed"

    result["verify_results"] = verify_results

    module.exit_json(**result)


if __name__ == "__main__":
    main()
