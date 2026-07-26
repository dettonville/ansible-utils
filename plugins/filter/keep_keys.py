# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
import re
import copy
from ansible.errors import AnsibleFilterError
from ansible.module_utils.common._collections_compat import Mapping, Sequence

__metaclass__ = type

DOCUMENTATION = """
  name: keep_keys
  short_description: Keep only specified key names from a dict or list of dicts
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Traverses a dictionary or a list of dictionaries and retains only the keys that match the provided list of regex patterns.
    - Can operate recursively or only on the first level of the data structure.
  positional: key_patterns
  options:
    _input:
      description: Dictionary or list of dictionaries to filter.
      type: any
      required: true
    key_patterns:
      description: List of regex patterns representing the keys to keep.
      type: list
      required: true
    recursive:
      description: Whether to apply the filter recursively to nested dictionaries.
      type: boolean
      default: false
"""

EXAMPLES = """
- name: Keep only specific keys at the top level (Default behavior)
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.keep_keys(['name', 'status']) }}"
  vars:
    my_dict:
      name: production-cluster
      status: active
      credentials:
        token: secret123
        ssh_key: private_key

- name: Keep keys recursively using regex matching
  ansible.builtin.debug:
    msg: "{{ my_list | dettonville.utils.keep_keys(['(?i).*id.*', 'name'], recursive=true) }}"
  vars:
    my_list:
      - account_id: 12345
        name: main
        meta: some_meta
      - user_id: 67890
        name: admin
        roles: ['admin', 'user']
"""

RETURN = """
  _value:
    description: A dict or list containing only the retained keys.
    type: any
"""


class FilterModule(object):
    def filters(self):
        return {"keep_keys": self.keep_keys}

    def keep_keys(
        self, input_object: any, key_patterns: list, recursive: bool = False
    ) -> any:
        if not isinstance(key_patterns, list):
            raise AnsibleFilterError("The 'key_patterns' option must be a list.")

        # Compile regex patterns
        compiled_patterns = []
        for pattern in key_patterns:
            try:
                compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                raise AnsibleFilterError(f"Invalid regex pattern '{pattern}': {e}")

        def _should_keep(key: str) -> bool:
            return any(pattern.match(str(key)) for pattern in compiled_patterns)

        def _process_object(obj, is_recursive, parent_matched=True):
            if isinstance(obj, Mapping):
                new_dict = {}
                for k, v in obj.items():
                    matched = _should_keep(k)

                    if matched:
                        if is_recursive:
                            new_dict[k] = _process_object(
                                v, is_recursive, parent_matched=True
                            )
                        else:
                            new_dict[k] = copy.deepcopy(v)
                    elif is_recursive:
                        if isinstance(v, (Mapping, Sequence)) and not isinstance(
                            v, (str, bytes)
                        ):
                            res = _process_object(v, is_recursive, parent_matched=False)
                            if res or res == {} or res == []:
                                new_dict[k] = res
                return new_dict

            elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
                new_list = []
                for item in obj:
                    res = _process_object(item, is_recursive, parent_matched)
                    if (
                        res
                        or isinstance(res, (bool, int, float))
                        or res == {}
                        or res == []
                    ):
                        new_list.append(res)
                return new_list

            return obj if parent_matched else None

        # Root invocation defaults parent_matched to True so top-level primitives pass out cleanly
        return _process_object(input_object, recursive, parent_matched=True)
