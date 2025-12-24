[![ansible-test sanity](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-sanity.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-sanity.yml)
[![ansible-test units](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-units.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-units.yml)
[![ansible-lint](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-lint.yml)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.md)

# Dettonville Ansible Utilities Collection

The Ansible `dettonville.utils` collection includes plugins and modules that aid management, manipulation, and visibility of data for Ansible playbooks. This collection provides tools to streamline complex workflows, such as certificate validation, data export, and git operations, with a focus on simplicity and reliability.

## Detailed Test / Use Case Examples

The integration tests performed regularly on the main branch demonstrate the use case examples supported by the **modules and plugins**.

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
Name | Description
--- | ---
[remove_dict_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_dict_keys.py) | Remove key(s) with specified list of regex patterns from nested dict/array.
[remove_sensitive_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_sensitive_keys.py) | Remove sensitive key(s) with specified list of regex patterns from nested dict/array.
[redact_sensitive_values](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/redact_sensitive_values.py) | Redact values for key(s) with specified list of regex patterns from nested dict/array by replacing them with a redacted tag.
[sort_dict_list](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_list.py) | Sort a list of dicts using specified sort key(s).
[sort_dict_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_keys.py) | Sort dictionary keys by specified key(s).
[to_markdown](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_markdown.py) | Converts a list of flat dictionaries to markdown format.

### Modules
Name | Description
--- | ---
[export_dicts](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/export_dicts.py) | Export a list of dicts to markdown or csv formatted file.
[git_pacp](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/git_pacp.py) | Perform git actions, including clone, add, commit, push, or combined add+commit+push (ACP).
[test_results_logger](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/test_results_logger.py) | Renders test results specified in dict format into JUnit XML.
[x509_certificate_verify](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/x509_certificate_verify.py) | Verify X.509 certificate properties and signature.

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

A comprehensive set of [tested use cases/examples can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/README.md#testuse-case-example-index).

### See Also:

* [Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) in the Ansible documentation for more details.

## Contributing to This Collection

This collection is intended for plugins that are not platform or discipline specific. Simple plugin examples should be generic in nature. More complex examples can include real-world platform modules to demonstrate the utility of the plugin in a playbook.

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [dettonville.utils collection repository](https://github.com/dettonville/ansible-utils). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

## Testing

All releases will meet the following test criteria:

* 100% success for [Integration](https://github.com/dettonville/ansible-utils/blob/main/tests/integration) tests.
* 100% success for [Unit](https://github.com/dettonville/ansible-utils/blob/main/tests/unit) tests.
* 100% success for [Sanity](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/index.html#all-sanity-tests) tests as part of [ansible-test](https://docs.ansible.com/ansible/latest/dev_guide/testing.html#run-sanity-tests).
* 100% success for [ansible-lint](https://ansible.readthedocs.io/projects/lint/) allowing only false positives.

### Developer Notes

- 100% code coverage is the goal, although it's not always possible. Please include unit and integration tests with all PRs. PRs should not cause a decrease in code coverage.
- Filter plugins should be 1 per file, with an included DOCUMENTATION string, or reference a lookup plugin with the same name.
- This collection should not depend on other collections for imported code.
- Use of the latest version of black is required for formatting (black -l79).
- The README contains a table of plugins. Use the [collection_prep](https://github.com/ansible-network/collection_prep) utilities to maintain this.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release Notes
Release notes are available [here](https://github.com/dettonville/ansible-utils/blob/main/changelogs/CHANGELOG.rst).
For automated release announcements, refer [here](https://twitter.com/AnsibleContent).

## Roadmap
For information on releasing, versioning, and deprecation, see the [strategy document](https://access.redhat.com/articles/4993781).

In general, major versions can contain breaking changes, while minor versions only contain new features (like new plugin addition) and bugfixes. The releases will be done on an as-needed basis when new features and/or bugfixes are done.

## More Information

- [Ansible Collection Overview](https://github.com/ansible-collections/overview)
- [Ansible User Guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer Guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
