

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
> MODULE dettonville.utils.x509_certificate_verify (/Users/ljohnson/tmp/_0iIScH/ansible_collections/dettonville/utils/plugins/modules/x509_certificate_verify.py)

  Verifies that a certificate is cryptographically signed by an issuer
  certificate and validates specified properties.
  Checks certificate attributes like common name, organization, and
  organizational unit.
  Validates certificate expiration and proximity to expiration using a
  checkend threshold.
  Validates public key algorithm and size if provided.
  Uses OpenSSL for cryptographic signature verification and Python's
  cryptography library for property validation.

OPTIONS (= indicates it is required):

- checkend_value  The number of seconds before expiration to fail.
                   Only effective if `validate_checkend' is true.
        default: 86400
        type: int

- common_name  Expected Common Name (CN) in the certificate's
                subject. If not provided, CN is not validated.
        default: null
        type: str

- issuer_path  Path to the issuer (CA) certificate file (PEM or DER
                format) used to verify the certificate's signature.
                If this argument is provided, the module will
                automatically perform signature validation.
        default: null
        type: path

- key_algo  Expected public key algorithm. If not provided, key
             algorithm is not validated.
        choices: [rsa, ec, dsa, ed25519]
        default: null
        type: str

- key_size  Expected public key size in bits. If not provided, key
             size is not validated.
        default: null
        type: int

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

- validate_checkend  If set to true, the module will fail if the
                      certificate expires within the checkend_value.
        default: false
        type: bool

- validate_expired  If set to true, the module will fail if the
                     certificate has expired.
        default: true
        type: bool

NOTES:
      * The module works with both PEM and DER encoded
        certificates and keys.
      * At least one verification property must be provided.

REQUIREMENTS:  cryptography>=1.5, pyopenssl


AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
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
    key_algo: 'rsa'
    key_size: 2048
  register: verify_result

RETURN VALUES:

- details  A dictionary containing the validated certificate
            properties.
        returned: always
        sample:
          common_name: my.example.com
          key_algo: rsa
          key_size: 2048
          organization: My Company
          valid_from: '2025-01-01T00:00:00Z'
          valid_until: '2026-01-01T00:00:00Z'
        type: dict

- failed  A boolean indicating if the module task failed.
        returned: always
        sample: false
        type: bool

- msg     A message indicating the result of the validation.
        returned: always
        sample: All certificate validations passed successfully
        type: str

- valid   A boolean indicating if the certificate passed all
           validation checks.
        returned: always
        sample: true
        type: bool

```
