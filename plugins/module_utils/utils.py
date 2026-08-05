# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

import base64
import binascii
import logging
import pprint
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from functools import cmp_to_key
from importlib import import_module
from operator import itemgetter as i

__metaclass__ = type

import json
import os
import re
import traceback
from typing import Any, List, Union

YAML_IMPORT_ERROR = None

try:
    # noinspection PyPackageRequirements
    import yaml
except ImportError:
    yaml = None
    YAML_IMPORT_ERROR = traceback.format_exc()
else:
    YAML_IMPORT_ERROR = None


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

    if yaml is None:
        raise UtilsModuleException("PyYAML is not available")

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
    for path in (galaxy_path, galaxy_alt_path):
        if os.path.exists(path):
            return load_collection_meta_galaxy(path, no_version=no_version)

    return {}


def get_collection_version(fqcn, not_found=None, no_version="*"):
    unused_not_found = not_found  # noqa: F841
    if not FQCN_RE.match(fqcn):
        raise UtilsModuleException('"{fqcn}" is not a FQCN'.format(fqcn=fqcn))

    try:
        collection_pkg = import_module(
            "ansible_collections.{fqcn}".format(fqcn=fqcn)
        )
    except ImportError as exc:
        # Collection not found
        # noqa: B904
        raise UtilsModuleException(
            f"import_module(ansible_collections.{fqcn}): {exc}"
        ) from exc

    try:
        data = load_collection_meta(collection_pkg, no_version=no_version)
    except Exception as exc:
        # noqa: B904
        raise UtilsModuleException(
            f"Error while loading metadata for {fqcn}: {exc}"
        ) from exc

    return data.get("version", no_version)


# ref: https://stackoverflow.com/questions/20692710/python-recursively-deleting-dict-keys#20692955
# ref:
# https://stackoverflow.com/questions/13183501/staticmethod-and-recursion#13183523
# -*- coding: utf-8 -*-
"""
Utility functions for dettonville.utils collection.
"""


def remove_keys_from_object(
    obj: Any, key_patterns: List[str], log_level: str = "INFO"
) -> Any:
    """
    Recursively traverse the object and remove keys matching the patterns.
    Modifies the object in place.
    """
    logging.basicConfig(level=log_level)
    logging.debug("key_patterns=%s", key_patterns)

    if isinstance(obj, dict):
        # Use a copy of items to avoid modification during iteration
        items_to_process = list(obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                del obj[key]
                if log_level == "INFO":
                    # Optional logging; adjust as needed
                    pass
            if isinstance(value, (Mapping, Sequence)) and not isinstance(
                value, (str, bytes)
            ):
                remove_keys_from_object(value, key_patterns, log_level)
    elif isinstance(obj, Mapping):
        # Fallback for generic Mappings that do not support item
        # deletion (__delitem__)
        new_obj = dict(obj)
        items_to_process = list(new_obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                del new_obj[key]
            if isinstance(value, (Mapping, Sequence)) and not isinstance(
                value, (str, bytes)
            ):
                remove_keys_from_object(value, key_patterns, log_level)
        return new_obj
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
        for item in obj:
            remove_keys_from_object(item, key_patterns, log_level)
    return obj


def redact_sensitive_values_from_object(
    obj: Any, key_patterns: list, log_level: str = "INFO"
) -> Any:
    """
    Recursively traverse the object and redact values for matching keys.
    """
    if isinstance(obj, dict):
        items_to_process = list(obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                obj[key] = f"<redacted_{key}>"
                if log_level == "INFO":
                    # Optional logging; adjust as needed
                    pass
            if isinstance(value, (Mapping, Sequence)) and not isinstance(
                value, (str, bytes)
            ):
                redact_sensitive_values_from_object(
                    value, key_patterns, log_level
                )
    elif isinstance(obj, Mapping):
        new_obj = dict(obj)
        items_to_process = list(new_obj.items())
        for key, value in items_to_process:
            if any(re.match(pattern, key) for pattern in key_patterns):
                new_obj[key] = f"<redacted_{key}>"
            if isinstance(value, (Mapping, Sequence)) and not isinstance(
                value, (str, bytes)
            ):
                redact_sensitive_values_from_object(
                    value, key_patterns, log_level
                )
        return new_obj
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
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
    if isinstance(obj, Mapping):
        # Sort the current dict's items
        sorted_items = sorted(obj.items(), key=lambda x: x[0], reverse=reverse)
        new_dict = {}
        for key, value in sorted_items:
            new_dict[key] = (
                sort_dict_keys(value, reverse)
                if isinstance(value, (Mapping, Sequence))
                and not isinstance(value, (str, bytes))
                else value
            )
        return new_dict
    elif isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
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
        (
            (i(col[1:].strip()), -1)
            if col.startswith("-")
            else (i(col.strip()), 1)
        )
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
        comparer_iter = (
            cmp(fn(left), fn(right)) * mult for fn, mult in comparers
        )
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
    headers = (
        "| "
        + " | ".join(keys)
        + " |\n| "
        + " | ".join(["---"] * len(keys))
        + " |"
    )
    rows = []
    for item in lst:
        row = "| " + " | ".join(str(item.get(k, '')) for k in keys) + " |"
        rows.append(row)
    return headers + "\n" + "\n".join(rows)


def to_markdown(data: Any, flatten_nested: bool = True) -> str:
    """
    Main conversion function.
    """
    if isinstance(data, Mapping):
        if flatten_nested:
            flat_data = flatten_dict(data)
            return dict_to_markdown_table(flat_data)
        else:
            return dict_to_markdown_table(data)
    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        return list_of_dicts_to_markdown(data)
    else:
        # Primitives
        return str(data)


def _fold_line(line, width=76):
    """Strict RFC 2849 line folding implementation.

    Folds any line exceeding `width` characters and prepends a single space to
    continuation lines.
    """
    if len(line) <= width:
        return line

    chunks = [line[:width]]
    remaining = line[width:]
    chunk_size = width - 1

    for idx in range(0, len(remaining), chunk_size):
        chunks.append(" " + remaining[idx : idx + chunk_size])

    return "\n".join(chunks)


def to_ldif(entry):
    """Converts a dictionary representing an LDAP entry into an LDIF record
    string.

    Ensures safe handling of base64-encoded values, list/multivalued
    attributes, applies RFC 2849 line folding, and returns a clean format
    terminated by a newline.
    """
    if not isinstance(entry, dict):
        raise ValueError(
            "to_ldif requires a dictionary representing an LDAP entry."
        )

    ldif_lines = []

    # Enforce order of structural markers for standard parsing
    ordered_keys = []
    if 'dn' in entry:
        ordered_keys.append('dn')
    if 'changetype' in entry:
        ordered_keys.append('changetype')

    for k in entry.keys():
        if k not in ordered_keys:
            ordered_keys.append(k)

    for key in ordered_keys:
        value = entry[key]
        if value is None:
            continue

        # Normalize values into an iterable list to handle
        # multivalued keys seamlessly
        if isinstance(value, list):
            values = value
        elif isinstance(value, (set, tuple)):
            values = list(value)
        else:
            values = [value]

        for val in values:
            if val is None:
                continue

            val_str = str(val)

            # Determine if this key explicitly requires double-colon
            # base64 notation
            if key.endswith('::'):
                attr_name = key[:-2].strip()
                b64_val = base64.b64encode(val_str.encode('utf-8')).decode(
                    'utf-8'
                )
                line_content = "{0}:: {1}".format(attr_name, b64_val)
            else:
                # Auto-encode unsafe string elements if they contain
                # non-printable or non-ASCII characters
                if any(
                    ord(c) < 32 or ord(c) > 126 for c in val_str
                ) or val_str.startswith((':', ' ')):
                    b64_val = base64.b64encode(val_str.encode('utf-8')).decode(
                        'utf-8'
                    )
                    line_content = "{0}:: {1}".format(key, b64_val)
                else:
                    line_content = "{0}: {1}".format(key, val_str)

            # Wrap line using RFC-compliant folding rule
            # before extending content blocks
            ldif_lines.append(_fold_line(line_content))

    return "\n".join(ldif_lines) + "\n"


def from_ldif(ldif_str):
    """Converts a standard raw string LDIF block record back into a Python
    dictionary object.

    Handles unfolding of continuous lines starting with leading spaces or tabs
    gracefully.
    """
    if not isinstance(ldif_str, str):
        raise ValueError(
            "from_ldif requires a string argument representing an LDIF record."
        )

    entry = {}
    lines = ldif_str.splitlines()
    unfolded_lines = []

    # 1. Unfold lines wrapped by strict line-length limitations
    # (lines starting with a space/tab)
    for line in lines:
        if not line.strip() or line.startswith('#'):
            continue
        if line.startswith(' ') or line.startswith('\t'):
            if unfolded_lines:
                unfolded_lines[-1] += line[1:]
        else:
            unfolded_lines.append(line)

    # 2. Parse attributes out of the unfolded strings
    for line in unfolded_lines:
        if ':' not in line:
            continue

        # Split exactly once at the first colon separator
        key, rest = line.split(':', 1)
        key = key.strip()

        # Check if the remaining part starts with a second colon
        # (indicating base64 encoding)
        if rest.startswith(':'):
            is_base64 = True
            raw_val = rest[1:].strip()
        else:
            is_base64 = False
            raw_val = rest.strip()

        # Handle base64 parsing values safely
        if is_base64:
            try:
                val = base64.b64decode(raw_val.encode('utf-8')).decode('utf-8')
            except (binascii.Error, UnicodeDecodeError) as err:
                # Log the issue in a real Ansible filter if possible
                # For now, fallback gracefully
                val = raw_val
                # Optionally use err to satisfy strict linter checks
                # if needed
                unused_err = err  # noqa: F841
                # Optionally:
                # import warnings
                # warnings.warn(f"Base64 decode failed for {key}: {e}")
        else:
            val = raw_val

        # 3. Assemble and normalize single vs multivalued properties
        if key in entry:
            if isinstance(entry[key], list):
                entry[key].append(val)
            else:
                entry[key] = [entry[key], val]
        else:
            entry[key] = val

    return entry


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
