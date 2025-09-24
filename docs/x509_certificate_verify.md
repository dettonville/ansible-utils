

```shell
$ ansible --version
ansible [core 2.19.2]
  config file = None
  configured module search path = [/Users/ljohnson/.ansible/plugins/modules, /usr/share/ansible/plugins/modules]
  ansible python module location = /Users/ljohnson/.pyenv/versions/3.13.5/lib/python3.13/site-packages/ansible
  ansible collection location = /Users/ljohnson/.ansible/collections:/usr/share/ansible/collections
  executable location = /Users/ljohnson/.pyenv/versions/3.13.5/bin/ansible
  python version = 3.13.5 (main, Sep 18 2025, 19:11:35) [Clang 16.0.0 (clang-1600.0.26.6)] (/Users/ljohnson/.pyenv/versions/3.13.5/bin/python3.13)
  jinja version = 3.1.6
  pyyaml version = 6.0.2 (with libyaml v0.2.5)
$
$ REPO_DIR="$( git rev-parse --show-toplevel )"
$ cd ${REPO_DIR}
$
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.x509_certificate_verify | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/x509_certificate_verify.md
> MODULE dettonville.utils.x509_certificate_verify (/Users/ljohnson/tmp/_lRlHig/ansible_collections/dettonville/utils/plugins/modules/x509_certificate_verify.py)

  Verifies that a certificate is cryptographically signed by an issuer
  certificate and validates specified properties.
  Checks certificate attributes like common name, organization,
  organizational unit, country, state or province, locality, and email
  address.
  Validates certificate serial number, version, and signature
  algorithm if provided.
  Validates certificate expiration and proximity to expiration using a
  checkend threshold.
  Validates public key algorithm and size if provided.
  Compares the modulus of RSA public keys between the certificate and
  issuer certificate (if provided and both are RSA).
  Uses OpenSSL for cryptographic signature verification and Python's
  cryptography library for property validation.

OPTIONS (= indicates it is required):

- chain_path  Path to a file containing intermediate certificates
               (PEM or DER format) to build the certificate chain for
               verification.
               If provided, these certificates are added to the trust
               store for signature validation.
        default: null
        type: path

- checkend_value  The number of seconds before expiration to fail.
                   Only effective if `validate_checkend' is true.
        default: 86400
        type: int

- common_name  Expected Common Name (CN) in the certificate's
                subject. If not provided, CN is not validated.
        default: null
        type: str

- country  Expected Country (C) in the certificate's subject. If not
            provided, Country is not validated.
        default: null
        type: str

- email_address  Expected Email Address in the certificate's subject.
                  If not provided, Email Address is not validated.
        default: null
        type: str

- issuer_path  Path to the issuer (CA) certificate file (PEM or DER
                format) used to verify the certificate's signature.
                If this argument is provided, the module will
                automatically perform signature validation and modulus
                comparison (for RSA keys).
        default: null
        type: path

- key_algo  Expected public key algorithm. If not provided, key
             algorithm is not validated.
        choices: [rsa, ec, dsa, ed25519]
        default: null
        type: str

- key_size  Expected public key size in bits. If not provided, key
             size is not validated. (e.g., 2048 for RSA, 256 for EC).
        default: null
        type: int

- locality  Expected Locality (L) in the certificate's subject. If
             not provided, Locality is not validated.
        default: null
        type: str

- logging_level  Parameter used to define the level of
                  troubleshooting output.
        choices: [DEBUG, INFO, WARNING, ERROR, CRITICAL]
        default: INFO
        type: str

- organization  Expected Organization (O) in the certificate's
                 subject. If not provided, O is not validated.
        default: null
        type: str

- organizational_unit  Expected Organizational Unit (OU) in the
                        certificate's subject. If not provided, OU is
                        not validated.
        default: null
        type: str

= path    Path to the certificate file to verify (PEM or DER format).
        type: path

- serial_number  Expected serial number of the certificate (decimal
                  or hex string). If not provided, serial number is
                  not validated.
        default: null
        type: str

- signature_algorithm  Expected signature algorithm (e.g.,
                        sha256WithRSAEncryption). If not provided,
                        signature algorithm is not validated.
        default: null
        type: str

- state_or_province  Expected State or Province (ST) in the
                      certificate's subject. If not provided, State or
                      Province is not validated.
        default: null
        type: str

- validate_checkend  If set to true, the module will fail if the
                      certificate expires within the checkend_value.
        default: false
        type: bool

- validate_expired  If set to true, the module will fail if the
                     certificate has expired.
        default: true
        type: bool

- version  Expected version of the certificate (1 or 3). If not
            provided, version is not validated.
        default: null
        type: int

NOTES:
      * The module works with both PEM and DER encoded
        certificates and keys.
      * At least one verification property must be provided.
      * Modulus comparison is performed only for RSA keys when
        issuer_path is provided.
      * Use chain_path to include intermediate certificates when
        verifying certificates not directly signed by the root
        CA.
      * For serial_number, provide as a decimal or hex string
        (with or without '0x').
      * For version, specify 1 for v1 or 3 for v3 certificates.

REQUIREMENTS:  cryptography>=1.5, pyopenssl


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
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

RETURN VALUES:

- cert_modulus  The modulus of the certificate's public key
                 (hexadecimal string, only for RSA keys).
        returned: when issuer_path is provided and the certificate has an RSA key
        sample: a1b2c3...
        type: str

- details  Dictionary of validated certificate properties.
        returned: always
        sample:
          common_name: my.example.com
          key_algo: rsa
          key_size: 2048
          organization: My Company
        type: dict

- failed  Indicates if the module task failed.
        returned: always
        sample: false
        type: bool

- issuer_modulus  The modulus of the issuer certificate's public key
                   (hexadecimal string, only for RSA keys).
        returned: when issuer_path is provided and the issuer certificate has an RSA key
        sample: a1b2c3...
        type: str

- modulus_match  Indicates if the modulus of the certificate and
                  issuer certificate match (only for RSA keys).
        returned: when issuer_path is provided and both certificates have RSA keys
        sample: false
        type: bool

- msg     Message indicating the result of the validation.
        returned: always
        sample: All certificate validations passed successfully
        type: str

- valid   Indicates if the certificate passed all validation checks.
        returned: always
        sample: true
        type: bool

- valid_signature  Indicates if the certificate's signature was
                    successfully verified against the issuer.
        returned: when issuer_path is provided
        sample: true
        type: bool

- verify_failed  Whether any verification checks failed.
        returned: always
        sample: false
        type: bool

- verify_results  Dictionary of verification results with boolean
                   values for each check.
        returned: always
        sample:
          common_name: true
          key_size: false
        type: dict

```
