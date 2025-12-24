# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
from importlib import import_module
from functools import cmp_to_key
from operator import itemgetter as i
from collections import OrderedDict
import logging
import pprint

__metaclass__ = type

import json
import os
import re
import traceback
from typing import Any, List, Union

YAML_IMPORT_ERROR = None

# import yaml
try:
    import yaml
except ImportError:
    YAML_IMPORT_ERROR = traceback.format_exc()
else:
    YAML_IMPORT_ERROR = None

# import copy


FQCN_RE = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")


class UtilsModuleException(Exception):
    def __init__(self, message):
        super(UtilsModuleException, self).__init__()

        self._message = message

    def __str__(self):
        return "[UtilsModuleException] message=%s" % self._message


def load_collection_meta_manifest(manifest_path):
    with open(manifest_path, "rb") as f:
        meta = json.load(f)
    return {
        "version": meta["collection_info"]["version"],
    }


def load_collection_meta_galaxy(galaxy_path, no_version="*"):
    if YAML_IMPORT_ERROR:
        raise UtilsModuleException(
            "missing_required_lib = PyYAML, exception=%s" % YAML_IMPORT_ERROR
        )

    with open(galaxy_path, "rb") as f:
        meta = yaml.safe_load(f)
    return {
        "version": meta.get("version") or no_version,
    }


def load_collection_meta(collection_pkg, no_version="*"):
    path = os.path.dirname(collection_pkg.__file__)

    # Try to load MANIFEST.json
    manifest_path = os.path.join(path, "MANIFEST.json")
    if os.path.exists(manifest_path):
        return load_collection_meta_manifest(manifest_path)

    # Try to load galaxy.y(a)ml
    galaxy_path = os.path.join(path, "galaxy.yml")
    galaxy_alt_path = os.path.join(path, "galaxy.yaml")
    # galaxy.yaml was only supported in ansible-base 2.10 and ansible-core 2.11. Support was removed
    # in https://github.com/ansible/ansible/commit/595413d11346b6f26bb3d9df2d8e05f2747508a3 for
    # ansible-core 2.12.
    for path in (galaxy_path, galaxy_alt_path):
        if os.path.exists(path):
            return load_collection_meta_galaxy(path, no_version=no_version)

    return {}


def get_collection_version(fqcn, not_found=None, no_version="*"):
    if not FQCN_RE.match(fqcn):
        # raise AnsibleLookupError('"{fqcn}" is not a FQCN'.format(fqcn=fqcn))
        raise UtilsModuleException('"{fqcn}" is not a FQCN'.format(fqcn=fqcn))

    try:
        collection_pkg = import_module("ansible_collections.{fqcn}".format(fqcn=fqcn))
    except ImportError as exc:
        # Collection not found
        raise UtilsModuleException(
            "import_module(ansible_collections.{fqcn}): {error}".format(
                fqcn=fqcn, error=exc
            )
        )

    try:
        data = load_collection_meta(collection_pkg, no_version=no_version)
    except Exception as exc:
        # raise AnsibleLookupError('Error while loading metadata for {fqcn}: {error}'.format(fqcn=fqcn, error=exc))
        raise UtilsModuleException(
            "Error while loading metadata for {fqcn}: {error}".format(
                fqcn=fqcn, error=exc
            )
        )

    return data.get("version", no_version)


# ref: https://stackoverflow.com/questions/20692710/python-recursively-deleting-dict-keys#20692955
# ref:
# https://stackoverflow.com/questions/13183501/staticmethod-and-recursion#13183523
# -*- coding: utf-8 -*-
"""
Utility functions for dettonville.utils collection.
"""

import re


def remove_keys_from_object(obj: Any, key_patterns: List[str], log_level: str = "INFO") -> Any:
    """
    Recursively traverse the object and remove keys matching the patterns.
    Modifies the object in place.
    """
    if isinstance(obj, dict):
        # Use a copy of items to avoid modification during iteration
        items_to_process = list(obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                del obj[key]
                if log_level == "INFO":
                    # Optional logging; adjust as needed
                    pass  # Could add print or logging here if required
            # Recurse if value is a container (even if key was deleted, value reference is still valid)
            if isinstance(value, (dict, list)):
                remove_keys_from_object(value, key_patterns, log_level)
    elif isinstance(obj, list):
        for item in obj:
            remove_keys_from_object(item, key_patterns, log_level)
    return obj


def remove_keys_from_object_orig(
    object: any, key_patterns: list, log_level: str = "INFO"
) -> any:
    logging.basicConfig(level=log_level)

    logging.debug("key_patterns=%s", key_patterns)

    # ref:
    # https://stackoverflow.com/questions/3040716/python-elegant-way-to-check-if-at-least-one-regex-in-list-matches-a-string

    # regex_pattern_list = map(re.compile, key_patterns)
    # print("regex_pattern_list=%s" % regex_pattern_list)

    if isinstance(object, dict):
        # the call to `list` is useless for py2 but makes
        # the code py2/py3 compatible
        for key in list(object.keys()):
            # print("key=%s" % key)
            # if any(regex.match(key) for regex in regex_pattern_list):
            # if any(re.match(regex, key) for regex in key_patterns):
            if any(re.search(regex, key) for regex in key_patterns):
                logging.debug("*** regex=%s", key)
                logging.debug("*** remove key=%s", key)
                del object[key]
            else:
                remove_keys_from_object(object[key], key_patterns, log_level)
    elif isinstance(object, list):
        for i in reversed(range(len(object))):
            if isinstance(object[i], dict):
                remove_keys_from_object(object[i], key_patterns, log_level)
    else:
        # neither a dict nor a list, do nothing
        pass
    return


def redact_sensitive_values_from_object(obj: Any, key_patterns: list, log_level: str = "INFO") -> Any:
    """
    Recursively traverse the object and redact values for keys matching the patterns.
    """
    if isinstance(obj, dict):
        items_to_process = list(obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                obj[key] = f"<redacted_{key}>"
                if log_level == "INFO":
                    # Optional logging; adjust as needed
                    pass  # Could add print or logging here if required
            if isinstance(value, (dict, list)):
                redact_sensitive_values_from_object(value, key_patterns, log_level)
    elif isinstance(obj, list):
        for item in obj:
            redact_sensitive_values_from_object(item, key_patterns, log_level)
    return obj


# ref: https://stackoverflow.com/questions/9001509/how-do-i-sort-a-dictionary-by-key
# ref:
# https://stackoverflow.com/questions/72899/how-to-sort-a-list-of-dictionaries-by-a-value-of-the-dictionary-in-python


def sort_dict_keys(obj: Any, reverse: bool = False) -> Any:
    """
    Recursively sort dictionary keys in the object.
    Returns a new object with sorted keys.
    """
    if isinstance(obj, dict):
        # Sort the current dict's items
        sorted_items = sorted(obj.items(), key=lambda x: x[0], reverse=reverse)
        new_dict = {}
        for key, value in sorted_items:
            new_dict[key] = sort_dict_keys(value, reverse) if isinstance(value, (dict, list)) else value
        return new_dict
    elif isinstance(obj, list):
        return [sort_dict_keys(item, reverse) for item in obj]
    else:
        # Primitives remain unchanged
        return obj


def sort_dict_keys_orig(my_dict, reverse=False):
    return dict(sorted(my_dict.items(), reverse=reverse))


def sort_dict_list(dict_list: Any, sort_keys: Union[str, List[str]]) -> Any:
    """
    Sort a list of dictionaries by one or more keys.
    Raises TypeError if input is not a list.
    """
    if not isinstance(dict_list, list):
        raise TypeError("Input must be a list of dictionaries")

    if isinstance(sort_keys, str):
        return sort_single_key(dict_list, sort_keys)
    elif isinstance(sort_keys, list):
        return sort_multi_key(dict_list, sort_keys)
    else:
        raise TypeError("sort_keys must be a string or list of strings")


def sort_dict_list_orig(dict_list, sort_keys):
    if isinstance(sort_keys, list):
        return sort_multi_key(dict_list, sort_keys)
    else:
        return sort_single_key(dict_list, sort_keys)


def sort_single_key(dict_list: List[dict], sort_key: str) -> List[dict]:
    """
    Sort a list of dicts by a single key.
    Handles missing keys by treating them as empty string.
    """
    def get_key(item: dict) -> str:
        value = item.get(sort_key)
        return value if value is not None else ''

    return sorted(dict_list, key=get_key)


def sort_multi_key(dict_list: List[dict], sort_keys: List[str]) -> List[dict]:
    """
    Sort a list of dicts by multiple keys.
    Handles missing keys by treating them as empty string.
    """
    def get_multi_key(item: dict) -> tuple:
        return tuple(item.get(key, '') for key in sort_keys)

    return sorted(dict_list, key=get_multi_key)


# ref:
# https://stackoverflow.com/questions/1143671/how-to-sort-objects-by-multiple-keys#1144405
def sort_multi_key_orig(dict_list: list, sort_keys: list) -> list:
    comparers = [
        ((i(col[1:].strip()), -1) if col.startswith("-") else (i(col.strip()), 1))
        for col in sort_keys
    ]

    def cmp(x, y):
        """
        Replacement for built-in function cmp that was removed in Python 3

        Compare the two objects x and y and return an integer according to
        the outcome. The return value is negative if x < y, zero if x == y
        and strictly positive if x > y.

        https://portingguide.readthedocs.io/en/latest/comparisons.html#the-cmp-function
        """

        return (x > y) - (x < y)

    def comparer(left, right):
        comparer_iter = (cmp(fn(left), fn(right)) * mult for fn, mult in comparers)
        return next((result for result in comparer_iter if result), 0)

    return sorted(dict_list, key=cmp_to_key(comparer))


def flatten_dict(d: dict, parent_key: str = '', sep: str = '.') -> dict:
    """
    Flatten a nested dict with dot notation for keys.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def dict_to_markdown_table(d: dict) -> str:
    """
    Convert a flat dict to Markdown table.
    """
    if not d:
        return "| Key | Value |\n|-----|-------|"
    headers = "| Key | Value |\n|-----|-------|"
    rows = []
    for k, v in d.items():
        row = f"| {k} | {v} |"
        rows.append(row)
    return headers + "\n" + "\n".join(rows)


def list_of_dicts_to_markdown(lst: list) -> str:
    """
    Convert list of dicts to Markdown table.
    Assumes all dicts have same keys.
    """
    if not lst:
        return "|  |  |\n|---|----|"
    if not isinstance(lst[0], dict):
        return "\n".join(str(item) for item in lst)
    keys = list(lst[0].keys())
    headers = "| " + " | ".join(keys) + " |\n| " + " | ".join(["---"] * len(keys)) + " |"
    rows = []
    for item in lst:
        row = "| " + " | ".join(str(item.get(k, '')) for k in keys) + " |"
        rows.append(row)
    return headers + "\n" + "\n".join(rows)


def to_markdown(data: Any, flatten_nested: bool = True) -> str:
    """
    Main conversion function.
    """
    if isinstance(data, dict):
        if flatten_nested:
            flat_data = flatten_dict(data)
            return dict_to_markdown_table(flat_data)
        else:
            # For non-flattened, could implement recursive tables, but for simplicity, flatten
            return dict_to_markdown_table(data)
    elif isinstance(data, list):
        return list_of_dicts_to_markdown(data)
    else:
        # Primitives
        return str(data)


# ref: https://dave.dkjones.org/posts/2013/pretty-print-log-python/
# ref: https://realpython.com/python-pretty-print/
class PrettyLog:
    def __init__(self, obj):
        self.obj = obj

    def __repr__(self):
        # ref: https://stackoverflow.com/questions/21420243/pretty-printing-ordereddicts-using-pprint
        # ref:
        # https://stackoverflow.com/questions/4301069/any-way-to-properly-pretty-print-ordereddict
        if isinstance(object, OrderedDict):
            return pprint.pformat(dict(self.obj))
        return pprint.pformat(self.obj)
