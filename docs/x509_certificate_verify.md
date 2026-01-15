

```shell
$ ansible --version
ansible [core 2.20.1]
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
> MODULE dettonville.utils.x509_certificate_verify (/Users/ljohnson/tmp/_Yk77wR/ansible_collections/dettonville/utils/plugins/modules/x509_certificate_verify.py)

  This module is intended for idempotent verification of certificates
  in playbooks.
  This module verifies properties of an X.509 certificate, such as
  common name, organization, serial number, signature algorithm, key
  algorithm, and expiration status.
  This module also can verify the certificate's signature against an
  issuer CA certificate, chain or CA bundle.
  This module also can verify the certificate's private key matches
  the CA certificate.

OPTIONS (= indicates it is required):

- ca_path  Path to the issuer CA certificate, chain file (PEM or DER
            format), or bundle for signature verification.
        default: null
        type: path

- checkend_value  Number of seconds to check for impending expiration
                   (used with validate_checkend).
        default: 86400
        type: int

- common_name  Expected Common Name (CN) of the certificate subject.
        default: null
        type: str

- content  Base64 encoded certificate content (PEM or DER format).
            If provided, this takes precedence over `path'.
        default: null
        type: str

- country  Expected Country (C) of the certificate subject.
        default: null
        type: str

- email_address  Expected Email Address of the certificate subject.
        default: null
        type: str

- issuer_ca_path  Deprecated. Use `ca_path' instead. Path to the
                   issuer CA certificate.
        default: null
        type: path

- key_algo  Expected public key algorithm (e.g., 'rsa', 'ec', 'dsa',
             'ed25519').
        choices: [rsa, ec, dsa, ed25519]
        default: null
        type: str

- key_size  Expected key size in bits (e.g., 2048 for RSA/DSA, 256
             for EC). Not applicable for Ed25519.
        default: null
        type: int

- locality  Expected Locality (L) of the certificate subject.
        default: null
        type: str

- logging_level  Parameter used to define the level of
                  troubleshooting output.
        choices: [DEBUG, INFO, WARNING, ERROR, CRITICAL]
        default: INFO
        type: str

- organization  Expected Organization (O) of the certificate subject.
        default: null
        type: str

- organizational_unit  Expected Organizational Unit (OU) of the
                        certificate subject.
        default: null
        type: str

- path    Path to the certificate file to verify (PEM or DER format).
        default: null
        type: path

- private_key_content  Base64 encoded private key content (PEM
                        format).
                        If provided, this takes precedence over
                        `private_key_path'.
        default: null
        type: str

- private_key_password  Private key password.
        default: null
        type: str

- private_key_path  Path to the private key file to verify against
                     the certificate's public key.
                     If specified, performs a match test between the
                     certificate's public key and the private key.
        default: null
        type: path

- serial_number  Expected serial number of the certificate (in
                  decimal or hexadecimal format, e.g., '12345' or
                  '0x3039').
        default: null
        type: str

- signature_algorithm  Expected signature algorithm (e.g.,
                        'sha256WithRSAEncryption').
        default: null
        type: str

- state_or_province  Expected State or Province (ST) of the
                      certificate subject.
        default: null
        type: str

- validate_checkend  Whether to check if the certificate expires
                      within a specified time (seconds).
        default: true
        type: bool

- validate_expired  Whether to check if the certificate is expired.
        default: true
        type: bool

- validate_is_ca  Whether to validate that the certificate is a CA
                   certificate by checking basicConstraints for
                   CA=TRUE.
        default: false
        type: bool

- validate_modulus_match  Whether to verify if the certificate's
                           modulus matches its direct issuer's
                           modulus.
                           Only applies to RSA keys.
                           Logic will handle setting this to True if
                           ca_path is present
                           default is true if ca_path is provided
        default: null
        type: bool

- version  Expected certificate version (1 or 3).
        choices: [1, 3]
        default: null
        type: int

NOTES:
      * The module works with both PEM and DER encoded
        certificates and keys.
      * Exactly one of `path' or `content' must be provided for
        the certificate.
      * At least one verification property must be provided
        (e.g., common_name, serial_number,
        validate_expired=True, or ca_path).
      * Modulus comparison is performed only for RSA keys when
        ca_path is provided.
      * Use ca_path to include the issuer certificate or
        certificate chain when verifying certificates.
      * For serial_number, provide as a decimal or hex string
        (with or without '0x').
      * For version, specify 1 for v1 or 3 for v3 certificates.
      * The issuer_ca_path parameter is deprecated in favor of
        ca_path.
      * When logging_level is set to DEBUG, a full stack trace
        is logged for any exceptions.
      * When logging_level is set to DEBUG, additional
        certificate metadata and environment details are
        included.
      * If not_valid_after_utc is unavailable in cryptography >=
        41.0.0, an error is logged, indicating a potential
        library or environment issue.
      * If cryptography is loaded from a system-wide path in a
        virtual environment, a warning is logged to indicate
        potential version mismatches.
      * The module modifies sys.path to prioritize the virtual
        environment's cryptography installation over system-wide
        paths.
      * Certificate can be provided via `path' or `content'
        (base64 encoded). `content' takes precedence.
      * Private key can be provided via `private_key_path' or
        `private_key_content' (base64 encoded).
        `private_key_content' takes precedence.

REQUIREMENTS:  cryptography>=1.5, pyopenssl


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
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

RETURN VALUES:

- cert_modulus  Modulus of the certificate's public key (hexadecimal,
                 if applicable).
        returned: when ca_path is provided and the certificate has an RSA key
        sample: a1b2c3...
        type: str

- details  Details about the certificate's properties.
        returned: always
        sample:
          common_name: my.example.com
          key_algo: rsa
          key_size: 2048
          organization: My Company
        type: dict
        contains:

        - common_name  Common Name (CN) of the certificate.
          type: str

        - country  Country (C) of the certificate.
          type: str

        - email_address  Email Address of the certificate.
          type: str

        - key_algo  Public key algorithm of the certificate.
          type: str

        - key_size  Key size in bits (if applicable).
          type: int

        - locality  Locality (L) of the certificate.
          type: str

        - organization  Organization (O) of the certificate.
          type: str

        - organizational_unit  Organizational Unit (OU) of the
                                certificate.
          type: str

        - serial_number  Serial number of the certificate.
          type: str

        - signature_algorithm  Signature algorithm of the
                                certificate.
          type: str

        - state_or_province  State or Province (ST) of the
                              certificate.
          type: str

        - version  Version of the certificate.
          type: int

- failed  Indicates if the module failed.
        returned: always
        type: bool

- issuer_modulus  Modulus of the issuer CA's public key (hexadecimal,
                   if applicable).
        returned: when ca_path is provided and the issuer certificate has an RSA key
        sample: a1b2c3...
        type: str

- item    The input parameters provided to the module.
        returned: always
        sample:
          '...': null
          common_name: test.example.com
          path: /path/to/cert.pem
        type: dict

- msg     A message describing the result of the verification.
        returned: always
        sample: All certificate validations passed successfully
        type: str

- valid   Whether all specified validations passed.
        returned: always
        type: bool

- verify_failed  Whether any validation checks failed.
        returned: always
        type: bool

- verify_results  Results of individual verification checks.
        returned: always
        sample:
          checkend_valid: true
          common_name: true
          expiry_valid: true
          key_size: false
          modulus_match: true
          signature_valid: true
        type: dict
        contains:

        - checkend_valid  Whether the certificate does not expire
                           within checkend_value seconds.
          type: bool

        - common_name  Whether the common name matched.
          type: bool

        - country  Whether the country matched.
          type: bool

        - email_address  Whether the email address matched.
          type: bool

        - expiry_valid  Whether the certificate is not expired.
          type: bool

        - is_ca  Whether the certificate has CA:TRUE in
                  basicConstraints (if validate_is_ca is true).
          type: bool

        - key_algo  Whether the key algorithm matched.
          type: bool

        - key_size  Whether the key size matched.
          type: bool

        - locality  Whether the locality matched.
          type: bool

        - modulus_match  Whether the certificate and issuer CA moduli
                          match (if applicable).
          type: bool

        - organization  Whether the organization matched.
          type: bool

        - organizational_unit  Whether the organizational unit
                                matched.
          type: bool

        - private_key_match  Whether the private key matches the
                              certificate (only if private_key_path or
                              private_key_content provided).
          type: bool

        - serial_number  Whether the serial number matched.
          type: bool

        - signature_algorithm  Whether the signature algorithm
                                matched.
          type: bool

        - signature_valid  Whether the signature is valid (if ca_path
                            is provided).
          type: bool

        - state_or_province  Whether the state or province matched.
          type: bool

        - version  Whether the version matched.
          type: bool

```
