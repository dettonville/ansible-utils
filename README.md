
[![ansible-test sanity](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-sanity.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-sanity.yml)
[![ansible-test units](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-units.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-test-units.yml)
[![ansible-lint](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/dettonville/ansible-utils/actions/workflows/ansible-lint.yml)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.md)

# Dettonville Ansible Utilities Collection

The Ansible ``dettonville.utils`` collection includes plugins/filters that aid management, manipulation and visibility of data for Ansible playbooks.

## Detailed test / use case examples

The integration tests performed regularly on the main branch demonstrate the use case examples supported by the **module**.

A short/brief description overview of the [tested use cases can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/README.md#testuse-case-example-index).

A summary table summary of test results for [each module/filter can be found here](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/test-results.md).

## Requirements

The host running the tasks must have the python requirements described in [requirements.txt](https://github.com/dettonville/ansible-utils/blob/main/requirements.txt)
Once the collection is installed, you can install them into a python environment using pip: `pip install -r ~/.ansible/collections/ansible_collections/dettonville/utils/requirements.txt`

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.16.0**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Included content

<!--start collection content-->
### Filter plugins
Name | Description
--- | ---
[remove_dict_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_dict_keys.py) | Remove key(s) with specified list of regex patterns from nested dict/array.
[remove_sensitive_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/remove_sensitive_keys.py) | Remove sensitive key(s) with specified list of regex patterns from nested dict/array.
[sort_dict_list](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_list.py) | Sort a list of dicts using specified sort key(s).
[sort_dict_keys](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/sort_dict_keys.py) | Sort dictionary keys by specified key(s).
[to_markdown](https://github.com/dettonville/ansible-utils/blob/main/plugins/filter/to_markdown.py) | Converts a list of flat dictionaries to markdown format.

### Modules

Name | Description
--- | ---
[export_dicts](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/export_dicts.py) | Export a list of dicts to markdown or csv formatted file.
[git_pacp](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/git_pacp.py) | Perform git actions, including, clone, add, commit, push, or combined add+commit+push(ACP).
[test_results_logger](https://github.com/dettonville/ansible-utils/blob/main/plugins/modules/test_results_logger.py) | Renders test results specified in dict format into junit xml.

<!--end collection content-->

## Installing this collection

You can install the ``dettonville.utils`` collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install dettonville.utils

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: dettonville.utils
```
## Using this collection

A comprehensive set of [tested use cases/examples can be found here.](https://github.com/dettonville/ansible-test-automation/blob/main/tests/dettonville/utils/main/README.md#testuse-case-example-index).


### See Also:

* [Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) in the Ansible documentation for more details.

## Contributing to this collection

This collection is intended for plugins that are not platform or discipline specific. Simple plugin examples should be generic in nature. More complex examples can include real world platform modules to demonstrate the utility of the plugin in a playbook.

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [dettonville.utils collection repository](https://github.com/dettonville/ansible-utils). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

## Testing

All releases will meet the following test criteria.

* 100% success for [Integration](https://github.com/dettonville/ansible-utils/blob/main/tests/integration) tests.
* 100% success for [Unit](https://github.com/dettonville/ansible-utils/blob/main/tests/unit) tests.
* 100% success for [Sanity](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/index.html#all-sanity-tests) tests as part of [ansible-test](https://docs.ansible.com/ansible/latest/dev_guide/testing.html#run-sanity-tests).
* 100% success for [ansible-lint](https://ansible.readthedocs.io/projects/lint/) allowing only false positives.

### Developer notes

- 100% code coverage is the goal, although it's not always possible. Please include unit and integration tests with all PRs. PRs should not cause a decrease in code coverage.
- Filter plugins should be 1 per file, with an included DOCUMENTATION string, or reference a lookup plugin with the same name.
- This collection should not depend on other collections for imported code
- Use of the latest version of black is required for formatting (black -l79)
- The README contains a table of plugins. Use the [collection_prep](https://github.com/ansible-network/collection_prep) utilities to maintain this.


### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Release notes
<!--Add a link to a changelog.md file or an external docsite to cover this information. -->
Release notes are available [here](https://github.com/dettonville/ansible-utils/blob/main/changelogs/CHANGELOG.rst)
For automated release announcements refer [here](https://twitter.com/AnsibleContent).


## Roadmap
For information on releasing, versioning and deprecation see the [stratergy document](https://access.redhat.com/articles/4993781).

In general, major versions can contain breaking changes, while minor versions only contain new features (like new plugin addition) and bugfixes.
The releases will be done on an as-needed basis when new features and/or bugfixes are done.

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
