#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: x509_certificate_verify
short_description: Verify X.509 certificate properties and signatures
author:
  - "Lee Johnson (@lj020326)"
version_added: "2025.9.0"
description:
  - This module verifies properties of an X.509 certificate, such as common name, organization,
    serial number, signature algorithm, key algorithm, and expiration status.
  - It can also verify the certificate's signature against an issuer CA certificate or chain.
options:
  path:
    description:
      - Path to the certificate file to verify (PEM or DER format).
    required: true
    type: path
  issuer_ca_path:
    description:
      - Path to the issuer CA certificate or chain file (PEM or DER format) for signature verification.
    required: false
    type: path
  issuer_path:
    description:
      - Deprecated. Use C(issuer_ca_path) instead. Path to the issuer CA certificate.
    required: false
    type: path
  chain_path:
    description:
      - Deprecated. Use C(issuer_ca_path) instead. Path to the certificate chain.
    required: false
    type: path
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
  - At least one verification property must be provided (e.g., common_name, serial_number, validate_expired=True, or issuer_ca_path).
  - Modulus comparison is performed only for RSA keys when issuer_ca_path is provided.
  - Use issuer_ca_path to include the issuer certificate or certificate chain when verifying certificates.
  - For serial_number, provide as a decimal or hex string (with or without '0x').
  - For version, specify 1 for v1 or 3 for v3 certificates.
  - The issuer_path and chain_path parameters are deprecated in favor of issuer_ca_path.
  - When logging_level is set to DEBUG, a full stack trace is logged for any exceptions.
  - When logging_level is set to DEBUG, additional certificate metadata and environment details are included.
  - If not_valid_after_utc is unavailable in cryptography >= 41.0.0, an error is logged, indicating a potential library or environment issue.
  - If cryptography is loaded from a system-wide path in a virtual environment, a warning is logged to indicate potential version mismatches.
  - The module modifies sys.path to prioritize the virtual environment's cryptography installation over system-wide paths.
"""

EXAMPLES = r"""
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
    issuer_ca_path: /path/to/ca.pem
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
    signature_valid:
      description: Whether the signature is valid (if issuer_ca_path is provided).
      type: bool
    modulus_match:
      description: Whether the certificate and issuer CA moduli match (if applicable).
      type: bool
  sample: {"common_name": true, "key_size": false, "expiry_valid": true, "checkend_valid": true, "signature_valid": true, "modulus_match": true}
cert_modulus:
  description: Modulus of the certificate's public key (hexadecimal, if applicable).
  type: str
  returned: when issuer_ca_path is provided and the certificate has an RSA key
  sample: "a1b2c3..."
issuer_modulus:
  description: Modulus of the issuer CA's public key (hexadecimal, if applicable).
  type: str
  returned: when issuer_ca_path is provided and the issuer certificate has an RSA key
  sample: "a1b2c3..."
"""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from datetime import datetime, timezone, timedelta
import os
import sys
import traceback
import logging

# Handle cryptography imports
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
    from cryptography import __version__ as cryptography_version

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
        cert = load_pem_x509_certificate(data, default_backend())
        if not isinstance(cert, x509.Certificate):
            raise ValueError(
                f"Parsed certificate is not a valid x509.Certificate object, got {type(cert)}"
            )
        return cert
    except ValueError:
        try:
            cert = load_der_x509_certificate(data, default_backend())
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
    """Load CA certificates from a file (single or chain)."""
    try:
        data = _read_cert_file(path)
        certs = []
        if b"-----BEGIN CERTIFICATE-----" in data:
            # Handle PEM chain
            pem_certs = data.decode("utf-8").split("-----END CERTIFICATE-----")
            for pem_cert in pem_certs:
                if "-----BEGIN CERTIFICATE-----" in pem_cert:
                    cert_data = (pem_cert + "-----END CERTIFICATE-----").encode("utf-8")
                    cert = _parse_certificate(cert_data)
                    certs.append(cert)
        else:
            # Handle single DER or PEM certificate
            certs.append(_parse_certificate(data))
        return certs
    except Exception as e:
        raise Exception(
            "Failed to load CA certificates from {}: {}".format(path, str(e))
        )


# Function to verify certificate signature
def _verify_signature(cert, ca_certs):
    """Verify certificate signature against CA certificates."""
    store = crypto.X509Store()
    logging.debug("Certificate issuer: %s", cert.issuer)
    cert_openssl = crypto.load_certificate(
        crypto.FILETYPE_PEM, cert.public_bytes(Encoding.PEM)
    )
    for ca_cert in ca_certs:
        logging.debug("CA subject: %s", ca_cert.subject)
        ca_openssl = crypto.load_certificate(
            crypto.FILETYPE_PEM, ca_cert.public_bytes(Encoding.PEM)
        )
        store.add_cert(ca_openssl)
    store_ctx = crypto.X509StoreContext(store, cert_openssl)
    try:
        store_ctx.verify_certificate()
        logging.debug("Issuer signature valid!")
        return True
    except (crypto.Error, crypto.X509StoreContextError) as e:
        logging.debug("Certificate signature verification failed: %s", str(e))
        logging.error(
            "Issuer signature invalid: %s (type: %s)", str(e), type(e).__name__
        )
        logging.debug("Exception traceback: %s", traceback.format_exc())
        return False
    # except Exception as e:
    #     logging.debug("Certificate signature verification failed: %s", str(e))
    #     logging.error(
    #         "Issuer signature invalid: %s (type: %s)", str(e), type(e).__name__)
    #     logging.debug("Exception traceback: %s", traceback.format_exc())
    #     return False


def _get_modulus(public_key):
    """Get the modulus of a public key (if applicable)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "{:X}".format(public_key.public_numbers().n)
    return None


def main():
    """Main module function."""
    module_args = dict(
        path=dict(type="path", required=True),
        issuer_ca_path=dict(type="path", required=False),
        issuer_path=dict(type="path", required=False),
        chain_path=dict(type="path", required=False),
        common_name=dict(type="str", required=False),
        organization=dict(type="str", required=False),
        organizational_unit=dict(type="str", required=False),
        country=dict(type="str", required=False),
        state_or_province=dict(type="str", required=False),
        locality=dict(type="str", required=False),
        email_address=dict(type="str", required=False),
        serial_number=dict(type="str", required=False),
        version=dict(type="int", required=False, choices=[1, 3]),
        signature_algorithm=dict(type="str", required=False),
        key_algo=dict(
            type="str",
            required=False,
            default=None,
            choices=["rsa", "ec", "dsa", "ed25519"],
        ),
        key_size=dict(type="int", required=False),
        validate_expired=dict(type="bool", required=False, default=True),
        validate_checkend=dict(type="bool", required=False, default=True),
        checkend_value=dict(type="int", required=False, default=86400),
        logging_level=dict(
            type="str",
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
    if module.params.get("logging_level") == "DEBUG":
        sys_path_removed = False
        for path in sys.path[:]:
            if path.startswith("/usr/lib/python3/dist-packages"):
                sys.path.remove(path)
                sys_path_removed = True
        if sys_path_removed:
            log.debug(
                "Removed system-wide path /usr/lib/python3/dist-packages from sys.path to prioritize virtual environment"
            )

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
    if module.params.get("logging_level") == "DEBUG":
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

    # Handle deprecated parameters
    ca_path = module.params.get("issuer_ca_path")
    if module.params.get("issuer_path"):
        module.warn("issuer_path is deprecated. Use issuer_ca_path instead.")
        ca_path = module.params.get("issuer_path")
    elif module.params.get("chain_path"):
        module.warn("chain_path is deprecated. Use issuer_ca_path instead.")
        ca_path = module.params.get("chain_path")

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
    boolean_properties = ["validate_expired", "validate_checkend"]
    has_verification = (
        any(module.params.get(prop) is not None for prop in non_boolean_properties)
        or any(module.params.get(prop) is True for prop in boolean_properties)
        or ca_path is not None
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

    try:
        # Read and parse the certificate
        cert_data = _read_cert_file(module.params.get("path"))
        log.debug(
            "Certificate data read from %s: %s bytes",
            module.params.get("path"),
            len(cert_data),
        )
        cert = _parse_certificate(cert_data)
        log.debug("Parsed certificate type: %s", type(cert))
        public_key = cert.public_key()

        # Log certificate validity dates in debug mode
        if module.params.get("logging_level") == "DEBUG":
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

        # Extract subject attributes
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                result["details"]["common_name"] = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                result["details"]["organization"] = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                result["details"]["organizational_unit"] = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                result["details"]["country"] = attr.value
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                result["details"]["state_or_province"] = attr.value
            elif attr.oid == NameOID.LOCALITY_NAME:
                result["details"]["locality"] = attr.value
            elif attr.oid == NameOID.EMAIL_ADDRESS:
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
        for prop in non_boolean_properties + boolean_properties:
            if prop not in ["validate_expired", "validate_checkend"]:
                result["verify_results"][prop] = True

        # Perform property verifications
        if module.params.get("common_name"):
            result["verify_results"]["common_name"] = result["details"][
                "common_name"
            ] == module.params.get("common_name")
        if module.params.get("organization"):
            result["verify_results"]["organization"] = result["details"][
                "organization"
            ] == module.params.get("organization")
        if module.params.get("organizational_unit"):
            result["verify_results"]["organizational_unit"] = result["details"][
                "organizational_unit"
            ] == module.params.get("organizational_unit")
        if module.params.get("country"):
            result["verify_results"]["country"] = result["details"][
                "country"
            ] == module.params.get("country")
        if module.params.get("state_or_province"):
            result["verify_results"]["state_or_province"] = result["details"][
                "state_or_province"
            ] == module.params.get("state_or_province")
        if module.params.get("locality"):
            result["verify_results"]["locality"] = result["details"][
                "locality"
            ] == module.params.get("locality")
        if module.params.get("email_address"):
            result["verify_results"]["email_address"] = result["details"][
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
                result["verify_results"]["serial_number"] = (
                    result["details"]["serial_number"] == expected_serial
                )
            except ValueError:
                module.fail_json(
                    msg="Invalid serial number: {}. Must be a valid decimal or hexadecimal number.".format(
                        module.params.get("serial_number")
                    )
                )
        if module.params.get("version"):
            result["verify_results"]["version"] = result["details"][
                "version"
            ] == module.params.get("version")
        if module.params.get("signature_algorithm"):
            result["verify_results"]["signature_algorithm"] = result["details"][
                "signature_algorithm"
            ] == module.params.get("signature_algorithm")
        if module.params.get("key_algo"):
            result["verify_results"]["key_algo"] = result["details"][
                "key_algo"
            ] == module.params.get("key_algo")
        if module.params.get("key_size") and result["details"]["key_algo"] != "ed25519":
            result["verify_results"]["key_size"] = result["details"][
                "key_size"
            ] == module.params.get("key_size")
        elif (
            module.params.get("key_size") and result["details"]["key_algo"] == "ed25519"
        ):
            # Ed25519 has no key size
            result["verify_results"]["key_size"] = True

        # Check expiration with fallback for older cryptography versions
        try:
            not_valid_after = cert.not_valid_after_utc
            log.debug("Using not_valid_after_utc for expiration check")
        except AttributeError as e:
            if version_parts >= [41, 0, 0]:
                if module.params.get("logging_level") == "DEBUG":
                    log.warning(
                        "not_valid_after_utc unavailable in cryptography %s, expected to be present. Falling back to not_valid_after. Stack trace:\n%s",
                        cryptography_version,
                        "".join(traceback.format_tb(e.__traceback__)),
                    )
                else:
                    log.warning(
                        "not_valid_after_utc unavailable in cryptography %s, expected to be present. Falling back to not_valid_after.",
                        cryptography_version,
                    )
            else:
                log.warning(
                    "not_valid_after_utc not available in cryptography %s, falling back to not_valid_after",
                    cryptography_version,
                )
            not_valid_after = cert.not_valid_after
            if not_valid_after.tzinfo is None:
                # Convert naive datetime to UTC
                not_valid_after = not_valid_after.replace(tzinfo=timezone.utc)
            # Log additional diagnostics when falling back
            if module.params.get("logging_level") == "DEBUG":
                log.debug("Fallback not_valid_after: %s", not_valid_after)
                log.debug("Certificate object attributes: %s", dir(cert))

        if module.params.get("validate_expired"):
            result["verify_results"]["expiry_valid"] = not_valid_after >= datetime.now(
                timezone.utc
            )
        else:
            result["verify_results"]["expiry_valid"] = True

        # Check impending expiration
        if module.params.get("validate_checkend"):
            result["verify_results"]["checkend_valid"] = (
                not_valid_after
                >= datetime.now(timezone.utc)
                + timedelta(seconds=module.params.get("checkend_value"))
            )
        else:
            result["verify_results"]["checkend_valid"] = True

        # Verify signature if issuer_ca_path is provided
        if ca_path:
            ca_certs = _load_ca_certs(ca_path)
            result["verify_results"]["signature_valid"] = _verify_signature(
                cert, ca_certs
            )
            if isinstance(public_key, rsa.RSAPublicKey) and ca_certs:
                result["cert_modulus"] = _get_modulus(public_key)
                result["issuer_modulus"] = _get_modulus(ca_certs[0].public_key())
                result["verify_results"]["modulus_match"] = (
                    result["cert_modulus"] == result["issuer_modulus"]
                )
            else:
                result["verify_results"]["modulus_match"] = True
        else:
            result["verify_results"]["signature_valid"] = True
            result["verify_results"]["modulus_match"] = True

    except Exception as e:
        if module.params.get("logging_level") == "DEBUG":
            log.error(
                "Exception occurred: %s\nStack trace:\n%s",
                str(e),
                "".join(traceback.format_tb(e.__traceback__)),
            )
        module.fail_json(msg=str(e), failed=True)

    # Update result based on verification results
    if not all(result["verify_results"].values()):
        result["valid"] = False
        result["verify_failed"] = True
        result["msg"] = "One or more certificate validations failed"

    module.exit_json(**result)


if __name__ == "__main__":
    main()
