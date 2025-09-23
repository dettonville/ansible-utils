# Module: x509_certificate_verify

The `x509_certificate_verify` module verifies X.509 certificate properties and signatures. It checks attributes such as the common name, organization, organizational unit, country, state or province, locality, email address, public key algorithm, key size, and expiration status. It also supports cryptographic signature verification using an issuer certificate.

For a detailed motivational case study on the `x509_certificate_verify` module, including before-and-after comparisons for PKI workflows, see [x509_certificate_verify_detailed.md](x509_certificate_verify_detailed.md).

## Features

- Validates certificate properties including:
  - Common Name (CN)
  - Organization (O)
  - Organizational Unit (OU)
  - Country (C)
  - State or Province (ST)
  - Locality (L)
  - Email Address (emailAddress)
  - Public key algorithm (RSA, EC, DSA, Ed25519)
  - Public key size
  - Expiration status
  - Proximity to expiration (checkend threshold)
- Verifies certificate signatures against an issuer certificate using OpenSSL.
- Supports both PEM and DER certificate formats.
- Provides detailed output on validated properties.

---

## Requirements

- Python 3.6+
- `cryptography>=1.5`
- `pyopenssl`
- Ansible 2.10 or later

---

## Installation

Install the collection using Ansible Galaxy:

```bash
ansible-galaxy collection install dettonville.utils
```

Ensure the required Python libraries are installed on the target system:

```bash
pip install cryptography>=1.5 pyopenssl
```

## Usage

The module requires a certificate file path and at least one verification property to check. Below are some example playbooks demonstrating its use.

### Example 1: Verify Certificate Signature and Properties

This example verifies a certificate's signature against a provided issuer and validates its common name and key algorithm.

```yaml
- name: Verify certificate signature and properties
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/intermediate/cert.pem
    issuer_path: /etc/pki/ca/root-ca.pem
    common_name: 'server.example.com'
    key_algo: 'rsa'
  register: cert_validation
```

This example verifies more certificate properties.

```yaml
- name: Verify certificate signature and properties
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/intermediate_ca.pem
    issuer_path: /etc/pki/ca-root.pem
    common_name: foobar.example.int
    organization: MyOrg
    organizational_unit: IT
    country: US
    state_or_province: California
    locality: San Francisco
    email_address: admin@example.com
    key_algo: rsa
    key_size: 2048
    validate_expired: true
  register: cert_verify_result
- debug:
    msg: "{{ cert_verify_result }}"
```

### Example 2: Check Certificate Expiration

This will verify if the certificate has expired.

```yaml
- name: Verify that a certificate has not expired
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
  register: verify_result
- debug:
    msg: "{{ verify_result }}"
```

This will verify if the certificate expires within 30 days

```yaml
- name: Verify that a certificate will not expire in the next 30 days
  dettonville.utils.x509_certificate_verify:
    path: /etc/pki/certs/mycert.pem
    validate_checkend: true
    checkend_value: 2592000
  register: verify_result
- debug:
    msg: "{{ verify_result }}"
```

### Example 3: Verify a Certificate Chain

This example validates a certificate chain by providing a chain_path containing the intermediate certificates.

```yaml
- name: Verify a certificate chain
  dettonville.utils.x509_certificate_verify:
    path: /etc/certs/leaf.pem
    chain_path: /etc/certs/chain.pem
    validate_expired: true
  register: chain_validation
```

### Example 4: Verify Public Key Details

This example verifies that a certificate uses a specific key algorithm and key size. This is useful for enforcing security policies.

```yaml
- name: Validate public key details
  dettonville.utils.x509_certificate_verify:
    path: /etc/ssl/certs/service.pem
    key_algo: 'ec'
    key_size: 256
  register: key_validation
```

## Parameters

| Parameter             | Description | Type | Required | Default |
|-----------------------|-------------|------|----------|---------|
| `path`                | Path to the certificate file (PEM or DER format). | Path | Yes | - |
| `issuer_path`         | Path to the issuer certificate file for signature verification. | Path | No | - |
| `chain_path`          | Path to a file containing intermediate certificates (PEM or DER format) to build the certificate chain for verification. | Path | No | - |
| `common_name`         | Expected Common Name (CN) in the certificate's subject. | String | No | - |
| `organization`        | Expected Organization (O) in the certificate's subject. | String | No | - |
| `organizational_unit` | Expected Organizational Unit (OU) in the certificate's subject. | String | No | - |
| `country`             | Expected Country (C) in the certificate's subject. | String | No | - |
| `state_or_province`             | Expected State or Province (ST) in the certificate's subject. | String | No | - |
| `locality`             | Expected Locality (L) in the certificate's subject. | String | No | - |
| `email_address`             | Expected Email Address in the certificate's subject. | String | No | - |
| `key_algo`            | Expected public key algorithm (rsa, ec, dsa, ed25519). | String | No | - |
| `key_size`            | Expected public key size in bits. | Integer | No | - |
| `validate_expired`    | Fail if the certificate has expired. | Boolean | No | `true` |
| `validate_checkend`   | Fail if the certificate expires within `checkend_value` seconds. | Boolean | No | `false` |
| `checkend_value`      | Seconds before expiration to fail (if `validate_checkend` is `true`). | Integer | No | `86400` |


**Note**: At least one verification property (`issuer_path`, `chain_path`, `common_name`, `organization`, `organizational_unit`, `country`, `state_or_province`, `locality`, `email_address`, `key_algo`, `key_size`, `validate_expired=true`, or `validate_checkend=true`) must be provided.

## Return Values

| Key | Description | Type | Returned | Sample |
|-----|-------------|------|----------|--------|
| `valid` | Indicates if the certificate passed all validation checks. | Boolean | Always | `true` |
| `failed` | Indicates if the module task failed. | Boolean | Always | `false` |
| `msg` | Message indicating the result of the validation. | String | Always | `"All certificate validations passed successfully"` |
| `details` | Dictionary of validated certificate properties. | Dictionary | Always | `{"common_name": "my.example.com", "organization": "My Company", "key_algo": "rsa", "key_size": 2048, "country": "US", "state_or_province": "California", "locality": "San Francisco", "email_address": "admin@example.com"}` |

## Notes

- The module supports check mode, returning a success message without performing actual validation. 
- Ensure the target system has the required Python libraries installed. 
- The module fails if the required libraries (cryptography or pyopenssl) are not present. 
- At least one verification property (issuer_path, common_name, organization, organizational_unit, country, state_or_province, locality, email_address, key_algo, key_size, validate_expired=true, or validate_checkend=true) must be provided.
