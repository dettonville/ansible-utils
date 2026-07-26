# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
import io
from collections.abc import Mapping, Sequence
from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

try:
    from ruamel import yaml

    HAS_RUAMEL = True
except ImportError:
    try:
        import ruamel_yaml as yaml

        HAS_RUAMEL = True
    except ImportError:
        HAS_RUAMEL = False

__metaclass__ = type

DOCUMENTATION = """
  name: to_nice_yaml
  short_description: Convert data structure to custom-indented YAML using ruamel.yaml
  version_added: "2.20.0"
  author: Lee Johnson (@lj020326)
  description:
    - Serializes an input data object down to a cleanly formatted YAML string representation.
    - Exposes configuration control for explicit mapping spaces, sequence blocks, and indicator offsets.
    - Supports common serialization flags such as key sorting, unicode preservation, and explicit document boundaries.
  positional: mapping, sequence, offset
  options:
    _input:
      description: The data object (dict, list, etc.) to serialize.
      type: any
      required: true
    mapping:
      description: Number of spaces for mapping indentations.
      type: integer
      default: 2
    sequence:
      description: Number of spaces for sequence indentations (including prefix spacing).
      type: integer
      default: 4
    offset:
      description: Number of spaces to offset the sequence dash indicator token inside the block.
      type: integer
      default: 2
    width:
      description: Maximum line width limit for wrapped lines.
      type: integer
      default: 120
    explicit_start:
      description: Whether to include an explicit document start marker (---).
      type: boolean
      default: false
    sort_keys:
      description: Whether to sort dictionary keys alphabetically.
      type: boolean
      default: false
    allow_unicode:
      description: Whether to allow unicode characters directly instead of escaping them to ASCII.
      type: boolean
      default: true
"""

EXAMPLES = """
- name: Format nested configurations with custom structural spacing
  ansible.builtin.debug:
    msg: "{{ my_dict | dettonville.utils.to_nice_yaml(mapping=4, sequence=6, offset=3) }}"
  vars:
    my_dict:
      config:
        services:
          - name: nginx
            port: 80

- name: Enforce alphabetized dictionary keys and document start directives
  ansible.builtin.debug:
    msg: >-
      {{ my_dict | dettonville.utils.to_nice_yaml(
          explicit_start=true,
          sort_keys=true,
          width=80
      ) }}
  vars:
    my_dict:
      z_environment: production
      b_region: us-east-1
      a_cluster_id: k8s-01

- name: Preserve native Unicode text configurations without escaping
  ansible.builtin.debug:
    msg: "{{ item | dettonville.utils.to_nice_yaml(allow_unicode=true) }}"
  vars:
    item:
      description: "Automated deployment configuration for Tokyo datacenter"
      tags: ["東京", "本番"]
"""

RETURN = """
  _value:
    description: Customized formatted YAML text block string representation.
    type: string
"""


class FilterModule(object):
    def filters(self):
        return {"to_nice_yaml": self.to_nice_yaml}

    @staticmethod
    def _check_ruamel_version():
        """Check for legacy ruamel library versions and log an Ansible display warning if found."""
        if not HAS_RUAMEL or not hasattr(yaml, '__version__'):
            return

        try:
            # Parse version into comparable integers (e.g., "0.17.4" -> [0, 17, 4])
            version_parts = [int(p) for p in yaml.__version__.split('.') if p.isdigit()]
            if version_parts and version_parts < [0, 17, 22]:
                Display().warning(
                    f"The installed 'ruamel.yaml' version ({yaml.__version__}) is a legacy version. "
                    "Custom block sequence indentation options ('mapping', 'sequence', 'offset') may exhibit layout formatting anomalies. "
                    "Upgrading to 'ruamel.yaml>=0.17.22' is recommended for consistent geometry engine outputs."
                )
        except Exception:
            # Fallback defensively if version string parsing encounters unexpected vendor modifications
            pass

    def _normalize_data(self, data: any, sort_keys: bool = False) -> any:
        """
        Recursively unpacks internal Ansible/Jinja wrapper proxy objects
        into standard, primitive Python built-in types.
        """
        if isinstance(data, Mapping):
            items = sorted(data.items()) if sort_keys else data.items()
            return {str(k): self._normalize_data(v, sort_keys) for k, v in items}

        elif isinstance(data, (str, bytes)):
            return str(data)

        elif isinstance(data, Sequence):
            return [self._normalize_data(item, sort_keys) for item in data]

        elif isinstance(data, bool):
            # Check bool first because isinstance(True, int) evaluates to True in Python
            return bool(data)

        elif isinstance(data, int):
            return int(data)

        elif isinstance(data, float):
            return float(data)

        elif data is None:
            return None

        # Absolute fallback: cast to string if it's an unrecognized object type
        return str(data)

    def to_nice_yaml(
        self,
        input_object: any,
        mapping: int = 2,
        sequence: int = 4,
        offset: int = 2,
        width: int = 120,
        explicit_start: bool = False,
        sort_keys: bool = False,
        allow_unicode: bool = True,
    ) -> str:
        if not HAS_RUAMEL:
            raise AnsibleFilterError(
                "The 'ruamel.yaml' library is required to use the custom dettonville.utils.to_nice_yaml filter plugin."
            )

        # Notify user if their execution environment runs an old version
        self._check_ruamel_version()

        m = int(mapping)
        s = int(sequence)
        o = int(offset)

        try:
            # 1. Cleanse and normalize the data first to strip all proxy wrappers
            clean_object = self._normalize_data(input_object, sort_keys=sort_keys)

            # 2. Configure the safe Pure-YAML block engine
            ryaml = yaml.YAML(typ='safe')
            ryaml.default_flow_style = False
            ryaml.width = int(width)
            ryaml.explicit_start = bool(explicit_start)
            ryaml.allow_unicode = bool(allow_unicode)

            # Since _normalize_data handled sort-ordering at the dict level,
            # we tell ruamel's internal constructor engine to maintain that order
            if sort_keys:
                ryaml.constructor.setting_to_sort_keys = True

            # Set exact layout structure configurations
            ryaml.indent(mapping=m, sequence=s, offset=o)

            stream = io.StringIO()
            ryaml.dump(clean_object, stream)
            raw_yaml = stream.getvalue()

            # Handle the ruamel block mapping layout anomaly where nested sequence blocks
            # are aligned flat against their mapping keys when offset fits inside mapping boundary.
            if m == 2 and s == 4 and o == 2:
                lines = raw_yaml.splitlines()
                idx = 0

                while idx < len(lines):
                    line = lines[idx]
                    current_indent = len(line) - len(line.lstrip(' '))

                    # Look for map keys ending in ':' that contain a nested sequence right below them
                    if line.rstrip().endswith(':') and idx + 1 < len(lines):
                        next_line = lines[idx + 1]
                        next_indent = len(next_line) - len(next_line.lstrip(' '))

                        # If the list hyphen starts flat at the exact same margin level as its parent key,
                        # it means ruamel dropped the hanging block list formatting.
                        if (
                            next_line.lstrip().startswith('- ')
                            and next_indent == current_indent
                        ):
                            lookahead_idx = idx + 1

                            # Shift the initial list entry and EVERYTHING nested underneath it
                            while lookahead_idx < len(lines):
                                check_line = lines[lookahead_idx]
                                if not check_line.strip():
                                    lookahead_idx += 1
                                    continue

                                check_indent = len(check_line) - len(
                                    check_line.lstrip(' ')
                                )

                                # Break out if we hit a line that belongs to an outer context boundary
                                if check_indent < current_indent:
                                    break

                                # If it's at the same indentation level but NOT a list item,
                                # we have hit a sibling dictionary key under the original parent map.
                                if (
                                    check_indent == current_indent
                                    and not check_line.lstrip().startswith('- ')
                                ):
                                    break

                                # Shift the sequence line or its nested dictionary child lines forward cleanly by 2 spaces
                                lines[lookahead_idx] = "  " + check_line
                                lookahead_idx += 1

                    idx += 1

                return "\n".join(lines) + "\n"

            return raw_yaml

        except Exception as e:
            raise AnsibleFilterError(
                f"Failed parsing and formatting object into customized YAML: {e}"
            )
