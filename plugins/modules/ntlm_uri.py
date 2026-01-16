#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Lee Johnson (ljohnson@dettonville.com)
# MIT license

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ntlm_uri
author:
  - "Lee Johnson (@lj020326)"
version_added: "2.20.0"
short_description: Interacts with webservices via NTLM
description:
  - Interacts with HTTP and HTTPS web services with NTLM authentication.
options:
  body:
    description:
      - The body of the http request/response to the web service. If O(body_format) is set
        to V(json) it will take an already formatted JSON string or convert a data structure
        into JSON.
    type: raw
    required: false
  body_format:
    description:
      - The serialization format of the body. When set to V(json), encodes the body argument,
        if needed, and automatically sets the Content-Type header accordingly.
    type: str
    choices: [ raw, json ]
    default: raw
    required: false
  headers:
    description:
      - Add custom HTTP headers to a request in the format of a YAML hash.
    type: dict
    default: {}
    required: false
  method:
    description:
      - The HTTP method of the request or response.
    type: str
    default: GET
    required: false
  password:
    description:
      - A password for the module to use for NTLM authentication.
    type: str
    required: true
    aliases: [ url_password ]
  return_content:
    description:
      - Whether or not to return the body of the response as a "content" key in
        the dictionary result no matter it succeeded or failed.
    type: bool
    required: false
    default: false
  status_code:
    description:
      - A list of valid, numeric, HTTP status codes that signifies success of the request.
    type: list
    elements: int
    default: [ 200 ]
    required: false
  url:
    description:
      - HTTP or HTTPS URL in the form (http|https)://host.domain[:port]/path
    type: str
    required: true
  user:
    description:
      - A username for the module to use for NTLM authentication.
    type: str
    aliases: [ url_username ]
    required: true
  validate_certs:
    description:
      - If V(false), SSL certificates will not be validated.
      - This should only set to V(false) used on personally controlled sites using self-signed certificates.
    type: bool
    default: true
    required: false

notes:
  - Windows targets are not supported.

seealso: []
"""

EXAMPLES = r"""
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
"""

RETURN = r"""
headers:
  description: The headers used in the request.
  returned: on success
  type: dict
  sample: {"Content-Type": "application/json; charset=utf-8", "Server": "Microsoft-HTTPAPI/2.0"}
json:
  description: The json response from the request.
  returned: return_content set to true
  type: dict
  sample: {}
msg:
  description: Generic message from the request.
  returned: always
  type: str
  sample: OK
status:
  description: The HTTP status code from the request.
  returned: always
  type: int
  sample: 200
url:
  description: The actual URL used for the request.
  returned: always
  type: str
  sample: https://www.ansible.com/
"""

from ansible.module_utils.basic import AnsibleModule

import re
import json

try:
    import requests

    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    from requests_ntlm import HttpNtlmAuth
except ImportError:
    HttpNtlmAuth = None


def main():
    argument_spec = {
        "body": {"type": "raw", "required": False},
        "body_format": {"type": "str", "default": "raw", "choices": ["raw", "json"], "required": False},
        "headers": {"type": "dict", "default": {}, "required": False},
        "method": {"type": "str", "default": "GET", "required": False},
        "password": {"type": "str", "aliases": ["url_password"], "no_log": True, "required": True},
        "return_content": {"type": "bool", "default": False, "required": False},
        "status_code": {"type": "list", "elements": "int", "default": [200], "required": False},
        "url": {"type": "str", "required": True},
        "user": {"type": "str", "aliases": ["url_username"], "required": True},
        "validate_certs": {"type": "bool", "default": True, "required": False}
    }

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    if requests is None or HttpNtlmAuth is None:
        module.fail_json(
            msg="Missing required libraries: requests and/or requests-ntlm. Install with 'pip install requests requests-ntlm'.")

    result = {"changed": False}

    body = module.params["body"]
    body_format = module.params["body_format"].lower()
    headers = module.params["headers"]
    method = module.params["method"].upper()
    password = module.params["password"]
    return_content = module.params["return_content"]
    status_code = [int(x) for x in list(module.params["status_code"])]
    url = module.params["url"]
    user = module.params["user"]
    validate_certs = module.params["validate_certs"]

    if module.check_mode and method != 'GET':
        if isinstance(status_code, list):
            status_code = status_code[0]
        result.update({
            "headers": headers,
            "json": {"content": "sample content for check mode"},
            "msg": "OK",
            "status": status_code,
            "url": url
        })
        module.exit_json(**result)

    if not re.match('^[A-Z]+$', method):
        module.fail_json(msg="Parameter 'method' needs to be a single word in uppercase, like GET or POST.")

    # Encode the body unless its a string, then assume it is pre-formatted JSON
    if body_format == "json":
        if not isinstance(body, str):
            body = json.dumps(body)
        if "content-type" not in [header.lower() for header in headers]:
            headers["Content-Type"] = "application/json"

    auth = HttpNtlmAuth(user, password)
    response = requests.request(
        method=method,
        url=url,
        auth=auth,
        verify=validate_certs,
        headers=headers,
        json=body
    )

    if return_content:
        result["json"] = response.json()

    result.update({
        "headers": dict(response.headers),
        "msg": "OK",
        "status": response.status_code,
        "url": url
    })

    if response.status_code not in status_code:
        result['msg'] = f"Status code {response.status_code} not in accepted status codes {status_code}"
        module.fail_json(**result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
