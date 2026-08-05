# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# noinspection PyPackageRequirements
from ansible.plugins.action import ActionBase

# noinspection PyPackageRequirements
from ansible.utils.display import Display

# Import the core sanitization logic directly from
# your collection's module_utils
# noinspection PyUnresolvedReferences,PyPackageRequirements
from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    redact_sensitive_values_from_object,
)

display = Display()

_SENSITIVE_KEYS_DEFAULT = [
    "(?i).*vault.*",
    "(?i).*token.*",
    "(?i).*password.*",
    "(?i).*key.*",
    "(?i).*ssh.*",
]


class ActionModule(ActionBase):
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        # Explicitly pass the playbook variables
        # to the template coordinator engine
        self._templar.available_variables = task_vars

        result = super(ActionModule, self).run(tmp, task_vars)
        result['changed'] = False

        # 1. Check core verbosity parameter threshold early
        verbosity = int(self._task.args.get('verbosity', 0))

        # If the display verbosity level isn't high enough,
        # skip execution silently
        if self._display.verbosity < verbosity:
            result['skipped'] = True
            result['skipped_reason'] = (
                "Verbosity threshold not met. "
                f"(Requires {verbosity}, "
                f"currently {self._display.verbosity})"
            )
            return result

        # 2. Parse arguments safely out of the task spec definition
        msg = self._task.args.get('msg', None)
        var = self._task.args.get('var', None)
        key_patterns = self._task.args.get('key_patterns', None)
        additional_key_patterns = self._task.args.get(
            'additional_key_patterns', None
        )

        if msg is not None and var is not None:
            result['failed'] = True
            result['msg'] = (
                "The options 'msg' and 'var' are mutually exclusive"
            )
            return result

        # 3. Replicate default filter arrays if no custom collection
        # overrides them
        if key_patterns is None:
            key_patterns = list(_SENSITIVE_KEYS_DEFAULT)
        elif not isinstance(key_patterns, list):
            key_patterns = [key_patterns]

        if additional_key_patterns and isinstance(
            additional_key_patterns, list
        ):
            key_patterns.extend(additional_key_patterns)

        # 4. Handle data structure resolution and execute
        # the deep in-place sanitization
        if var is not None:
            # If a raw string variable name was passed,
            # resolve its data out of task_vars
            if isinstance(var, str):
                # FIX: First check if the string passed
                # is a plain variable name in task_vars
                if var in task_vars:
                    resolved_var = task_vars[var]
                else:
                    try:
                        # Template out the bare variable name
                        # to extract the underlying object data
                        resolved_var = self._templar.template(
                            f"{{{{ {var} }}}}"
                        )
                    except Exception as e:
                        result['failed'] = True
                        result['msg'] = (
                            f"Failed to template variable '{var}': {e}"
                        )
                        return result
            else:
                # If they passed an already-templated
                # or inline literal dictionary/list
                resolved_var = self._templar.template(var)

            # Apply the sanitizing in-place mutation function
            # directly to the resolved structure
            redact_sensitive_values_from_object(
                resolved_var, key_patterns, log_level="INFO"
            )
            result[var if isinstance(var, str) else 'var'] = resolved_var

        else:
            # Handle the standard text 'msg' pathway fallback path
            if msg is None:
                msg = ""

            resolved_msg = self._templar.template(msg)

            # If the evaluated message block maps down
            # into a dict or array context, scrub it
            if isinstance(resolved_msg, (dict, list)):
                redact_sensitive_values_from_object(
                    resolved_msg, key_patterns, log_level="INFO"
                )
            elif isinstance(resolved_msg, str):
                # If a single string contains embedded passwords
                # or matching secrets directly, we also scrub any strings
                # if your utility layout allows, otherwise keep string
                # handling clean:
                pass

            result['msg'] = resolved_msg

        return result
