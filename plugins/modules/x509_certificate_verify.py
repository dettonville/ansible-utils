#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license[](https://opensource.org/license/mit/)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: x509_certificate_verify
short_description: Verify X.509 certificate properties and signature
author:
  - "Lee Johnson (@lj020326)"
version_added: "2025.9.0"
description:
  - Verifies that a certificate is cryptographically signed by an issuer certificate and validates specified properties.
  - Checks certificate attributes like common name, organization, and organizational unit.
  - Validates certificate expiration and proximity to expiration using a checkend threshold.
  - Validates public key algorithm and size if provided.
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
      - If this argument is provided, the module will automatically perform signature validation.
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
requirements:
  - cryptography>=1.5
  - pyopenssl
notes:
  - The module works with both PEM and DER encoded certificates and keys.
'''

EXAMPLES = r'''
- name: Verify certificate signature and properties
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/intermediate_ca.pem
    issuer_path: /etc/pki/ca-root.pem
    common_name: foobar.example.int
    organization: MyOrg
    organizational_unit: IT
    key_algo: rsa
    key_size: 2048
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
    key_algo: 'RSA'
    key_size: 2048
  register: verify_result
'''

RETURN = r'''
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
    "key_algo": "rsa",
    "key_size": 2048,
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2026-01-01T00:00:00Z"
  }
'''

from datetime import datetime, timezone, timedelta
from ansible.module_utils.basic import AnsibleModule

# Handle cryptography import
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    from OpenSSL import crypto
    import cryptography

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False


# Function to read certificate content
def _read_cert_file(path, module):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        module.fail_json(msg=f"Failed to read certificate file at {path}: {e}")


# Function to parse certificate
def _parse_certificate(cert_content, module):
    try:
        return x509.load_pem_x509_certificate(cert_content, default_backend())
    except ValueError:
        try:
            return x509.load_der_x509_certificate(cert_content, default_backend())
        except ValueError as e:
            module.fail_json(msg=f"Could not parse certificate. Must be PEM or DER format. Error: {e}")


# Main function
def main():
    module_args = dict(
        path=dict(type='path', required=True),
        issuer_path=dict(type='path', required=False),
        common_name=dict(type='str', required=False, default=None),
        organization=dict(type='str', required=False, default=None),
        organizational_unit=dict(type='str', required=False, default=None),
        key_algo=dict(type='str', required=False, default=None,
                      choices=['rsa', 'ec', 'dsa', 'ed25519']),
        key_size=dict(type='int', required=False, default=None),
        validate_expired=dict(type='bool', required=False, default=True),
        validate_checkend=dict(type='bool', required=False, default=False),
        checkend_value=dict(type='int', required=False, default=86400),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # In check mode, do not perform actions that modify the system.
    # This module is idempotent and does not modify the system, so we can always return a success.
    if module.check_mode:
        module.exit_json(changed=False, valid=True, failed=False, msg="Check mode: All validations passed.")

    if not HAS_LIBS:
        module.fail_json(msg="The 'pyopenssl' and 'cryptography' Python libraries are required.")

    path = module.params['path']
    issuer_path = module.params['issuer_path']

    # Only perform signature validation if an issuer_path is provided
    if issuer_path:
        # Load and verify certificate signature using pyopenssl
        cert_content = _read_cert_file(path, module)
        issuer_content = _read_cert_file(issuer_path, module)

        try:
            cert_openssl = crypto.load_certificate(crypto.FILETYPE_PEM, cert_content)
            issuer_cert_openssl = crypto.load_certificate(crypto.FILETYPE_PEM, issuer_content)
        except crypto.Error as e:
            # Retry with DER format if PEM fails
            try:
                cert_openssl = crypto.load_certificate(crypto.FILETYPE_DER, cert_content)
                issuer_cert_openssl = crypto.load_certificate(crypto.FILETYPE_DER, issuer_content)
            except crypto.Error as e:
                module.fail_json(
                    msg=f"Failed to load certificate or issuer. Ensure files are PEM or DER format. Error: {e}")

        try:
            store = crypto.X509Store()
            store.add_cert(issuer_cert_openssl)
            store_ctx = crypto.X509StoreContext(store, cert_openssl)
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError as e:
            module.fail_json(msg=f"Certificate signature verification failed: {e}")

    # Parse and validate certificate properties using cryptography library
    cert = _parse_certificate(_read_cert_file(path, module), module)

    # Log cryptography version for debugging
    module.log(f"cryptography version: {cryptography.__version__}")

    # Warn if cryptography version is below 36.0.0
    version_parts = [int(part) for part in cryptography.__version__.split('.')[:3]]
    if version_parts < [36, 0, 0]:
        module.warn(f"Cryptography version {cryptography.__version__} is below 36.0.0, consider updating for latest features and security fixes.")

    # Safely get timezone-aware validity dates
    try:
        valid_from = cert.not_valid_before_utc
        valid_until = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older versions
        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
        valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)

    result = {
        'valid': True,
        'failed': False,
        'msg': 'All certificate validations passed successfully',
        'details': {
            'common_name': None,
            'organization': None,
            'organizational_unit': None,
            'key_algo': None,
            'key_size': None,
            'valid_from': valid_from.isoformat(),
            'valid_until': valid_until.isoformat(),
        }
    }

    # Extract details from the subject
    subject = cert.subject
    subject_dict = {
        attr.oid: attr.value
        for attr in subject
    }

    # Common Name validation
    if module.params.get('common_name'):
        common_name = subject_dict.get(x509.OID_COMMON_NAME)
        result['details']['common_name'] = common_name
        if common_name is None or common_name != module.params['common_name']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Common name mismatch. Expected '{module.params['common_name']}', found '{common_name}'"
            module.fail_json(**result)

    # Organization validation
    if module.params.get('organization'):
        organization = subject_dict.get(x509.OID_ORGANIZATION_NAME)
        result['details']['organization'] = organization
        if organization is None or organization != module.params['organization']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = f"Organization mismatch. Expected '{module.params['organization']}', found '{organization}'"
            module.fail_json(**result)

    # Organizational Unit validation
    if module.params.get('organizational_unit'):
        organizational_unit = subject_dict.get(x509.OID_ORGANIZATIONAL_UNIT_NAME)
        result['details']['organizational_unit'] = organizational_unit
        if organizational_unit is None or organizational_unit != module.params['organizational_unit']:
            result['valid'] = False
            result['failed'] = True
            result[
                'msg'] = f"Organizational unit mismatch. Expected '{module.params['organizational_unit']}', found '{organizational_unit}'"
            module.fail_json(**result)

    # Key algorithm and size validation
    public_key = cert.public_key()
    actual_key_type = None
    actual_key_size = None

    if isinstance(public_key, rsa.RSAPublicKey):
        actual_key_type = 'rsa'
        actual_key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        actual_key_type = 'ec'
        actual_key_size = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        actual_key_type = 'dsa'
        actual_key_size = public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        actual_key_type = 'ed25519'

    result['details']['key_algo'] = actual_key_type
    result['details']['key_size'] = actual_key_size

    # Validate key algorithm
    if module.params.get('key_algo'):
        if actual_key_type is None or actual_key_type.upper() != module.params['key_algo'].upper():
            result['valid'] = False
            result['failed'] = True
            result['msg'] = (
                f"Key algorithm mismatch. Expected '{module.params['key_algo']}', "
                f"found '{actual_key_type}'"
            )
            module.fail_json(**result)

    # Validate key size
    if module.params.get('key_size'):
        if actual_key_size is None or actual_key_size != module.params['key_size']:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = (
                f"Key size mismatch. Expected '{module.params['key_size']}', "
                f"found '{actual_key_size}'"
            )
            module.fail_json(**result)

    # Validate expiration
    if module.params['validate_expired']:
        now = datetime.now(timezone.utc)
        module.log(f"now: {now}, not_valid_after: {valid_until}")
        if valid_until <= now:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = "Certificate has expired"
            module.fail_json(**result)

    # Validate checkend (expiration proximity)
    if module.params['validate_checkend']:
        checkend_time = datetime.now(timezone.utc) + timedelta(seconds=module.params['checkend_value'])
        module.log(f"checkend_time: {checkend_time}, not_valid_after: {valid_until}")
        if valid_until <= checkend_time:
            result['valid'] = False
            result['failed'] = True
            result['msg'] = (
                f"Certificate will expire within {module.params['checkend_value']} seconds "
                f"(expires at {valid_until})"
            )
            module.fail_json(**result)

    # If all validations pass
    module.exit_json(**result)


if __name__ == '__main__':
    main()
