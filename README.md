[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.md)

# Dettonville Ansible Utilities Collection

The Ansible `dettonville.utils` collection includes plugins and modules that aid management, manipulation, and visibility of data for Ansible playbooks. This collection provides tools to streamline complex workflows, such as certificate validation, data export, and git operations, with a focus on simplicity and reliability.

## CI Status

[![🧪 GitHub Actions CI/CD workflow tests badge]][GHA workflow runs list]
[![pre-commit.ci status badge]][pre-commit.ci results page]

## Detailed Test / Use Case Examples

The integration tests performed regularly on the main branch **demonstrate use case examples supported by plugins**.

A short/brief description overview of the [tested use cases can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/README.md#testuse-case-example-index).

A summary table of test results for [each module/filter can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/test-results.md).

The [`x509_certificate_verify` module README.md](docs/readme.x509_certificate_verify.md) can be found at [docs/readme.x509_certificate_verify.md](docs/readme.x509_certificate_verify.md).

## Requirements

The host running the tasks must have the python requirements described in [requirements.txt](https://github.com/dettonville/ansible-utils/blob/main/requirements.txt). Once the collection is installed, you can install them into a python environment using pip: `pip install -r requirements.txt`

<!--start requires_ansible-->

## Ansible Version Compatibility

This collection has been tested against the following Ansible versions: **>=2.16.0**.

Plugins and modules within a collection may be tested with only specific Ansible versions. A collection may contain metadata that identifies these versions. PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Included Content

<!--start collection content-->
### Filter Plugins

| Documentation                                              | Source code                                                                                                                    | Description                                                                                                                  |
|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| [debug_sanitized](docs/debug_sanitized.md)                 | [debug_sanitized.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/action/debug_sanitized.py)                 | Print sanitized debug statements with automated regex redactions.                                                            |
| [keep_keys](docs/keep_keys.md)                             | [keep_keys.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/keep_keys.py)                             | Keep only specified key names from a dict or list of dicts.                                                                  |
| [remove_dict_keys](docs/remove_dict_keys.md)               | [remove_dict_keys.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_dict_keys.py)               | Remove key(s) with specified list of regex patterns from nested dict/array.                                                  |
| [remove_sensitive_keys](docs/remove_sensitive_keys.md)     | [remove_sensitive_keys.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_sensitive_keys.py)     | Remove sensitive key(s) with specified list of regex patterns from nested dict/array.                                        |
| [redact_sensitive_values](docs/redact_sensitive_values.md) | [redact_sensitive_values.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/redact_sensitive_values.py) | Redact values for key(s) with specified list of regex patterns from nested dict/array by replacing them with a redacted tag. |
| [sort_dict_list](docs/sort_dict_list.md)                   | [sort_dict_list.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_list.py)                   | Sort list of dicts using specified sort key(s).                                                                              |
| [sort_dict_keys](docs/sort_dict_keys.md)                   | [sort_dict_keys.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_keys.py)                   | Sort dictionary keys by specified key(s).                                                                                    |
| [from_ldif](docs/from_ldif.md)                             | [from_ldif.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/from_ldif.py)                             | Convert LDIF to dictionary format.                                                                                           |
| [to_ldif](docs/to_ldif.md)                                 | [to_ldif.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_ldif.py)                                 | Convert dictionary to LDIF format.                                                                                           |
| [to_markdown](docs/to_markdown.md)                         | [to_markdown.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_markdown.py)                         | Convert list of flat dictionaries to markdown format.                                                                        |
| [to_nice_yaml](docs/to_nice_yaml.md)                       | [to_nice_yaml_utils.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_nice_yaml_utils.py)           | Convert data structure to custom-indented YAML using `ruamel.yaml`.                                                          |
| [to_key_value](docs/to_key_value.md)                       | [to_key_value.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_key_value.py)                       | Convert list of flat dictionaries to key=value format.                                                                       |

### Modules

| Documentation                                              | Source code                                                                                                                     | Description                                                                                       |
|------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| [export_dicts](docs/export_dicts.md)                       | [export_dicts.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/export_dicts.py)                       | Export list of dicts to markdown or csv formatted file.                                           |
| [git_pacp](docs/git_pacp.md)                               | [git_pacp.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/git_pacp.py)                               | Perform git actions, including clone, add, commit, push, or combined add+commit+push (ACP).       |
| [htpasswd](docs/htpasswd.md)                               | [htpasswd.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/htpasswd.py)                               | Manage single or multiple user credentials in an htpasswd file with backup and overwrite support. |
| [test_results_logger](docs/test_results_logger.md)         | [test_results_logger.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/test_results_logger.py)         | Renders test results specified in dict format into JUnit XML.                                     |
| [x509_certificate_verify](docs/x509_certificate_verify.md) | [x509_certificate_verify.py](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/x509_certificate_verify.py) | Verify X.509 certificate properties and signature.                                                |

<!--end collection content-->

## Installing This Collection

You can install the `dettonville.utils` collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install dettonville.utils

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: dettonville.utils
```

## Using This Collection

A comprehensive set
of [tested use cases/examples can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/README.md#testuse-case-example-index).

### See Also:

* [Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) in the Ansible documentation for more details.

## Contributing to This Collection

This collection is intended for plugins that are not platform or discipline specific. Simple plugin examples should be generic in nature. More complex examples can include real-world platform modules to demonstrate the utility of the plugin in a playbook.

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [dettonville.utils collection repository](https://github.com/dettonville/ansible-utils). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

---

## Testing

All releases will meet the following test criteria:

* 100% success for [Unit](https://github.com/dettonville/ansible-utils/blob/main/tests/unit) tests.
* 100% success for [Sanity](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/index.html#all-sanity-tests) tests as
  part of [ansible-test](https://docs.ansible.com/ansible/latest/dev_guide/testing.html#run-sanity-tests).
* 100% success for [ansible-lint](https://ansible.readthedocs.io/projects/lint/) allowing only false positives.

### Developer Notes

- Include unit tests with all PRs. PRs should not decrease code coverage.
- Filter plugins should be 1 per file, with an included DOCUMENTATION string, or reference a lookup plugin with the same name.

### How to run tests

See the [TESTING.md](TESTING.md) for information on how to run the necessary tests.

---

## Code of Conduct

This collection follows the Ansible project's [Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

---

## 🛡️ Identity & Maintainer

* **Maintainer:** Lee Johnson
* **Contact:** <ljohnson@dettonville.org>
* **LinkedIn:** https://www.linkedin.com/in/leejjohnson/
* **System Framework:** [Dettonville Cloud Infrastructure Services](https://dettonville.org)

---

## More Information

- [Dettonville Cloud Infrastructure Services](https://dettonville.org)
- [Dettonville Git Inventory Collection](https://github.com/dettonville/ansible-git-inventory)
- [Dettonville LLM Collection](https://github.com/dettonville/ansible-llm)
- [**Ansible Datacenter Site Example**](https://github.com/lj020326/ansible-datacenter) - An actual datacenter site.yml
  repository featuring roles that demonstrate
  practical usage of the collection modules.
- [Ansible Collection Overview](https://github.com/ansible-collections/overview)
- [Ansible User Guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer Guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

[🧪 GitHub Actions CI/CD workflow tests badge]:
https://github.com/dettonville/ansible-utils/actions/workflows/all_green_publish.yml/badge.svg?branch=main&event=push
[GHA workflow runs list]: https://github.com/dettonville/ansible-utils/actions/workflows/all_green_publish.yml?query=branch%3Amain

[pre-commit.ci status badge]:
https://results.pre-commit.ci/badge/github/dettonville/ansible-utils/main.svg
[pre-commit.ci results page]:
https://results.pre-commit.ci/latest/github/dettonville/ansible-utils/main
