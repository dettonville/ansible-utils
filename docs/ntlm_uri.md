

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
$ env ANSIBLE_NOCOLOR=True ansible-doc -t module dettonville.utils.ntlm_uri | tee /Users/ljohnson/repos/ansible/ansible_collections/dettonville/utils/docs/ntlm_uri.md
> MODULE dettonville.utils.ntlm_uri (/Users/ljohnson/tmp/_FoCaV2/ansible_collections/dettonville/utils/plugins/modules/ntlm_uri.py)

  Interacts with HTTP and HTTPS web services with NTLM authentication.

OPTIONS (= indicates it is required):

- body    The body of the http request/response to the web service.
           If `body_format' is set to `json' it will take an already
           formatted JSON string or convert a data structure into
           JSON.
        default: null
        type: raw

- body_format  The serialization format of the body. When set to
                `json', encodes the body argument, if needed, and
                automatically sets the Content-Type header
                accordingly.
        choices: [raw, json]
        default: raw
        type: str

- headers  Add custom HTTP headers to a request in the format of a
            YAML hash.
        default: {}
        type: dict

- method  The HTTP method of the request or response.
        default: GET
        type: str

= password  A password for the module to use for NTLM authentication.
        aliases: [url_password]
        type: str

- return_content  Whether or not to return the body of the response
                   as a "content" key in the dictionary result no
                   matter it succeeded or failed.
        default: false
        type: bool

- status_code  A list of valid, numeric, HTTP status codes that
                signifies success of the request.
        default: [200]
        elements: int
        type: list

= url     HTTP or HTTPS URL in the form
           (http|https)://host.domain[:port]/path
        type: str

= user    A username for the module to use for NTLM authentication.
        aliases: [url_username]
        type: str

- validate_certs  If `false', SSL certificates will not be validated.
                   This should only set to `false' used on personally
                   controlled sites using self-signed certificates.
        default: true
        type: bool

NOTES:
      * Windows targets are not supported.

AUTHOR: Lee Johnson (@lj020326)

EXAMPLES:
- name: Check that you can connect (GET) to a page and it returns a status 200
  dettonville.utils.ntlm_uri:
    url: http://www.example.com
    user: your_username
    password: p@ssw0rd

- name: Check that a page returns successfully but fail if the word AWESOME is not in the page contents
  dettonville.utils.ntlm_uri:
    url: http://www.example.com
    return_content: true
    user: your_username
    password: your_pass
  register: __response
  failed_when: __response is failed or "'AWESOME' not in __response.content"

- name: Create a JIRA issue
  dettonville.utils.ntlm_uri:
    url: https://your.jira.example.com/rest/api/2/issue/
    user: your_username
    password: your_pass
    method: POST
    body: "{{ lookup('ansible.builtin.file','issue.json') }}"
    status_code: 201
    body_format: json

RETURN VALUES:

- headers  The headers used in the request.
        returned: on success
        sample:
          Content-Type: application/json; charset=utf-8
          Server: Microsoft-HTTPAPI/2.0
        type: dict

- json    The json response from the request.
        returned: return_content set to true
        sample: {}
        type: dict

- msg     Generic message from the request.
        returned: always
        sample: OK
        type: str

- status  The HTTP status code from the request.
        returned: always
        sample: 200
        type: int

- url     The actual URL used for the request.
        returned: always
        sample: https://www.ansible.com/
        type: str

```
