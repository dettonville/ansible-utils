#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license[](https://opensource.org/license/mit/)

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
      - Expected public key size in bits. If not provided, key size is not validated.
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
      choices: [NOTSET, DEBUG, INFO, ERROR]
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
    key_algo: ec
    key_size: 256
    validate_expired: true
  register: cert_verify_result

- name: Verify an unexpired certificate with specific properties
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    common_name: 'www.example.com'
    validate_expired: true
  register: verify_result

- name: Verify that a certificate will not expire in the next 30 days
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
    checkend_value: 2592000
  register: verify_result

- name: Verify a certificate's public key algorithm and size
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    key_algo: 'rsa'
    key_size: 2048
  register: verify_result
"""

RETURN = r"""
valid:
  description: A boolean indicating if the certificate passed all validation checks.
  type: bool
  returned: always
  sample: true
failed:
  description: A boolean indicating if the module task failed.
  type: bool
  returned: always
  sample: false
msg:
  description: A message indicating the result of the validation.
  type: str
  returned: always
  sample: "All certificate validations passed successfully"
details:
  description: A dictionary containing the validated certificate properties.
  type: dict
  returned: always
  sample: {
    "common_name": "my.example.com",
    "organization": "My Company",
    "organizational_unit": "IT",
    "country": "US",
    "state_or_province": "California",
    "locality": "San Francisco",
    "email_address": "admin@example.com",
    "key_algo": "rsa",
    "key_size": 2048,
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2026-01-01T00:00:00Z"
  }
valid_signature:
  description: A boolean indicating if the certificate's signature was successfully verified against the issuer.
  type: bool
  returned: when issuer_path is provided
  sample: true
modulus_match:
  description: A boolean indicating if the modulus of the certificate and issuer certificate match (only for RSA keys).
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

import traceback
import pprint
import logging

from datetime import datetime, timezone, timedelta
from ansible.module_utils.basic import AnsibleModule

# Handle cryptography import
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.backends import default_backend
    from OpenSSL import crypto
    import cryptography

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False


# Function to read certificate content
def _read_cert_file(path, module):
    """Read certificate file content."""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        module.fail_json(msg=f"Failed to read certificate file at {path}: {str(e)}")


# Function to parse certificate
def _parse_certificate(cert_content, module):
    """Parse certificate content as PEM or DER."""
    try:
        return x509.load_pem_x509_certificate(cert_content, default_backend())
    except ValueError:
        try:
            return x509.load_der_x509_certificate(
                cert_content, default_backend())
        except ValueError as e:
            module.fail_json(msg=f"Could not parse certificate. Must be PEM or DER format. Error: {e}")


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


def _get_modulus(public_key):
    """Extract modulus from an RSA public key, return None for non-RSA keys."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return hex(public_key.public_numbers().n)[2:].upper()
    return None


# Main function
def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type="path", required=True),
            issuer_path=dict(type="path", required=False),
            chain_path=dict(type="path", required=False),
            common_name=dict(type="str", required=False, default=None),
            organization=dict(type="str", required=False, default=None),
            organizational_unit=dict(type="str", required=False, default=None),
            country=dict(type="str", required=False, default=None),
            state_or_province=dict(type="str", required=False, default=None),
            locality=dict(type="str", required=False, default=None),
            email_address=dict(type="str", required=False, default=None),
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
                type="str", choices=["NOTSET", "DEBUG", "INFO", "ERROR"], default="INFO"
            ),
        ),
        supports_check_mode=True,
    )

    if not HAS_LIBS:
        module.fail_json(
            msg="The 'pyopenssl' and 'cryptography' Python libraries are required."
        )

    loglevel = module.params.get("logging_level")
    logging.basicConfig(level=loglevel)

    # Log cryptography version for debugging
    module.log(f"cryptography version: {cryptography.__version__}")
    logging.info("cryptography version: %s", cryptography.__version__)

    # Warn if cryptography version is below 36.0.0
    version_parts = [int(part)
                     for part in cryptography.__version__.split(".")[:3]]
    if version_parts < [36, 0, 0]:
        module.warn(
            f"Cryptography version {cryptography.__version__} is below 36.0.0, consider updating for latest features and security fixes.")

    # Enforce at least one verification property
    verification_params = [
        module.params["issuer_path"],
        module.params["chain_path"],
        module.params["common_name"],
        module.params["organization"],
        module.params["organizational_unit"],
        module.params["country"],
        module.params["state_or_province"],
        module.params["locality"],
        module.params["email_address"],
        module.params["key_algo"],
        module.params["key_size"],
    ]
    verification_booleans = [
        module.params["validate_expired"],
        module.params["validate_checkend"],
    ]
    if not (any(verification_params) or any(verification_booleans)):
        module.fail_json(
            msg="At least one verification property must be provided."
        )

    if module.check_mode:
        module.exit_json(
            valid=True,
            failed=False,
            msg="Check mode: All validations passed successfully",
        )

    path = module.params["path"]
    issuer_path = module.params["issuer_path"]
    chain_path = module.params["chain_path"]

    # Read and parse certificate
    cert_content = _read_cert_file(path, module)
    cert = _parse_certificate(cert_content, module)

    result = dict(
        valid=True,
        changed=False,
        failed=False,
        msg="All certificate validations passed successfully",
        details={},
    )
    result["details"]["common_name"] = None
    result["details"]["organization"] = None
    result["details"]["organizational_unit"] = None
    result["details"]["country"] = None
    result["details"]["state_or_province"] = None
    result["details"]["locality"] = None
    result["details"]["email_address"] = None
    result["details"]["key_algo"] = None
    result["details"]["key_size"] = None

    # Issuer validation if issuer_path provided
    if issuer_path:
        result["details"]["valid_signature"] = False
        logging.debug("issuer_path: %s", issuer_path)
        # Load and verify certificate signature using pyopenssl
        issuer_content = _read_cert_file(issuer_path, module)
        logging.debug("issuer_content => %s", pprint.pformat(issuer_content))
        issuer_crypto = _parse_certificate(issuer_content, module)
        cert_openssl = crypto.load_certificate(
            crypto.FILETYPE_ASN1, cert.public_bytes(Encoding.DER))
        logging.debug("cert_openssl => %s", pprint.pformat(cert_openssl))
        try:
            issuer_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, issuer_content
            )
            logging.debug("issuer_cert => %s", pprint.pformat(issuer_cert))
        except crypto.Error as e:
            # Retry with ASN1 format if PEM fails
            try:
                issuer_cert = crypto.load_certificate(
                    crypto.FILETYPE_ASN1, issuer_content
                )
                logging.debug(
                    "issuer_cert* => %s",
                    pprint.pformat(issuer_cert))
            except crypto.Error as e:
                logging.error("could not load cert content!")
                module.fail_json(
                    msg=f"Failed to load certificate or issuer. Ensure files are PEM or DER format. Error: {e}")

        logging.debug("validating issuer signature...")
        logging.debug("Certificate issuer: %s", cert.issuer)
        logging.debug("Issuer subject: %s", issuer_crypto.subject)
        try:
            store = crypto.X509Store()
            store.add_cert(issuer_cert)
            # Add intermediate certificates if chain_path is provided
            if chain_path:
                logging.debug("chain_path: %s", chain_path)
                chain_content = _read_cert_file(chain_path, module)
                logging.debug(
                    "chain_content => %s",
                    pprint.pformat(chain_content))
                chain_certs = _load_chain_certs(chain_content, module)
                for chain_cert in chain_certs:
                    logging.debug(
                        "Adding chain certificate: %s",
                        chain_cert.get_subject())
                    store.add_cert(chain_cert)
            store_ctx = crypto.X509StoreContext(store, cert_openssl)
            logging.debug("verify issuer signature...")
            store_ctx.verify_certificate()
            result["valid_signature"] = True
            logging.debug("issuer signature valid!")
        except Exception as e:
            result["valid"] = False
            result["failed"] = True
            result["msg"] = f"Certificate signature validation failed: {str(e)}. Certificate issuer: {cert.issuer}, Issuer subject: {issuer_crypto.subject}"
            logging.error(
                "issuer signature invalid: %s (type: %s)",
                str(e),
                type(e).__name__)
            logging.debug("Exception traceback: %s", traceback.format_exc())
            module.fail_json(**result)

        # Modulus comparison for RSA keys
        # _get_modulus checks if cert has RSA key before attempting modulus comparison
        cert_modulus = _get_modulus(cert.public_key())
        issuer_modulus = _get_modulus(issuer_crypto.public_key())
        if cert_modulus is not None and issuer_modulus is not None:
            result['cert_modulus'] = cert_modulus
            result['issuer_modulus'] = issuer_modulus
            modulus_match = (cert_modulus == issuer_modulus)
            result['modulus_match'] = modulus_match
            logging.debug("modulus_match => %s", modulus_match)
            if not modulus_match:
                result["valid"] = False
                result["failed"] = True
                result["msg"] = "Modulus comparison mismatch."
                result["msg"] = (
                    f"Modulus mismatch. Expected modulus '{issuer_modulus}', "
                    f"found '{cert_modulus}'"
                )
                module.fail_json(**result)
        else:
            result['modulus_match'] = None
            result['cert_modulus'] = cert_modulus
            result['issuer_modulus'] = issuer_modulus
            if cert_modulus is None and issuer_modulus is None:
                logging.debug(
                    "Modulus comparison skipped: both keys are not RSA")
            elif cert_modulus is None:
                logging.debug(
                    "Modulus comparison skipped: certificate key is not RSA")
            else:  # issuer_modulus is None
                logging.debug(
                    "Modulus comparison skipped: issuer key is not RSA")

    logging.debug("set timezone-aware validity dates")
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

    # Common Name validation
    if module.params.get('common_name'):
        common_name = subject_dict.get(x509.NameOID.COMMON_NAME)
        result['details']['common_name'] = common_name
        if common_name is None or common_name != module.params['common_name']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Common name mismatch. Expected '{module.params['common_name']}', found '{common_name}'"
            module.fail_json(**result)

    # Organization validation
    if module.params.get('organization'):
        organization = subject_dict.get(x509.NameOID.ORGANIZATION_NAME)
        result['details']['organization'] = organization
        if organization is None or organization != module.params['organization']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Organization mismatch. Expected '{module.params['organization']}', found '{organization}'"
            module.fail_json(**result)

    # Organizational Unit validation
    if module.params.get('organizational_unit'):
        organizational_unit = subject_dict.get(
            x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        result['details']['organizational_unit'] = organizational_unit
        if organizational_unit is None or organizational_unit != module.params['organizational_unit']:
            result['valid'] = False
            result['failed'] = True
            result[
                'msg'] = f"Organizational unit mismatch. Expected '{module.params['organizational_unit']}', found '{organizational_unit}'"
            module.fail_json(**result)

    # Country validation
    if module.params.get('country'):
        country = subject_dict.get(x509.NameOID.COUNTRY_NAME)
        result['details']['country'] = country
        if country is None or country != module.params['country']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Country mismatch. Expected '{module.params['country']}', found '{country}'"
            module.fail_json(**result)

    # State or Province validation
    if module.params.get('state_or_province'):
        state_or_province = subject_dict.get(x509.NameOID.STATE_OR_PROVINCE_NAME)
        result['details']['state_or_province'] = state_or_province
        if state_or_province is None or state_or_province != module.params['state_or_province']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"State or Province mismatch. Expected '{module.params['state_or_province']}', found '{state_or_province}'"
            module.fail_json(**result)

    # Locality validation
    if module.params.get('locality'):
        locality = subject_dict.get(x509.NameOID.LOCALITY_NAME)
        result['details']['locality'] = locality
        if locality is None or locality != module.params['locality']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Locality mismatch. Expected '{module.params['locality']}', found '{locality}'"
            module.fail_json(**result)

    # Email Address validation
    if module.params.get('email_address'):
        email_address = subject_dict.get(x509.NameOID.EMAIL_ADDRESS)
        result['details']['email_address'] = email_address
        if email_address is None or email_address != module.params['email_address']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Email Address mismatch. Expected '{module.params['email_address']}', found '{email_address}'"
            module.fail_json(**result)

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
    if module.params.get('key_algo'):
        if key_algo is None or key_algo.upper() != module.params['key_algo'].upper():
            result['valid'] = False
            result['failed'] = True
            result['msg'] = (
                f"Key algorithm mismatch. Expected '{module.params['key_algo']}', "
                f"found '{key_algo}'"
            )
            module.fail_json(**result)

    # Validate key size
    if module.params.get("key_size"):
        if key_size is None or key_size != module.params["key_size"]:
            result["valid"] = False
            result["failed"] = True
            result["msg"] = (
                f"Key size mismatch. Expected '{module.params['key_size']}', "
                f"found '{key_size}'"
            )
            module.fail_json(**result)

    # Validate expiration
    if module.params["validate_expired"]:
        now = datetime.now(timezone.utc)
        module.log(f"now: {now}, not_valid_after: {valid_until}")
        if valid_until <= now:
            result["valid"] = False
            result["failed"] = True
            result["msg"] = "Certificate has expired"
            module.fail_json(**result)

    # Validate checkend (expiration proximity)
    if module.params["validate_checkend"]:
        checkend_time = datetime.now(timezone.utc) + timedelta(
            seconds=module.params["checkend_value"]
        )
        module.log(
            f"checkend_time: {checkend_time}, not_valid_after: {valid_until}")
        if valid_until <= checkend_time:
            result["valid"] = False
            result["failed"] = True
            result["msg"] = (
                f"Certificate will expire within {module.params['checkend_value']} seconds "
                f"(expires at {valid_until})"
            )
            module.fail_json(**result)

    # If all validations pass
    module.exit_json(**result)


if __name__ == "__main__":
    main()
