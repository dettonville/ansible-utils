
Attached find the source code for the ansible "dettonville.utils" collection.

The file is a concatenation of all the source files into a single text file with the following file header/footer delimiters:
    - "### FILE: <relative_file_path> ###" 
    - "### END FILE: <relative_file_path> ###"

The current ansible module `x509_certificate_verify` currently passes all existing/regression "ansible-test unit" tests.

It also passes all "ansible-test sanity" tests.

## Motivation

Update Modulus Match Logic in x509_certificate_verify Module

The current modulus match logic should be updated.

Currently, it blindly compares the cert's public key modulus to the first CA cert in ca_path (assumed to be the direct issuer).

This fails for:

- Leaf certs verified against a bundle (roots ≠ direct issuers). 
- Chains where the bundle has multiple CAs.

Proposed Changes:

- Make modulus match optional via a new param: validate_modulus_match (default: true if ca_path provided).
- If enabled, traverse the CA bundle/chain to find the direct issuer by matching subject DN/serial, then compare moduli only if found.
- Skip for non-RSA keys or if no direct issuer match.
- Log details for failures.

The current logic passes all unit tests.

Enhance unit tests to accommodate the updated/enhanced modulus matching logic.

Make sure that the enhancement passes all new and regression unit and sanity tests.

### Update Tests

Enhance existing/regression tests if the new feature enhancement(s) necessitate impact to the respective regression feature and/or tests;
Remove existing/regression tests if the new feature enhancement(s) eliminate the need/purpose for regression feature;
Add new feature tests to verify the new features enhancement(s) work as intended / expected.

## Developer Notes/Prompts

- Only incrementally enhance the code necessary with minimal change(s) to the existing module source logic.
- Only incrementally enhance the unit test file logic in order to achieve the highest test pass rate with lowest regression fail rate
- Use a `test-driven-development` (`TDD`) approach
- Use `don't-repeat-yourself` (`DRY`) methods whenever possible
- The enhancement(s) should pass all existing unit tests to `validate regression feature success`. 
- The enhancement(s) should pass all new feature tests to `validate new feature success`.
- Only remove test cases if they are acceptably deemed functionally redundant
- Maintain all unit test functions in alphanumeric sort order facilitating ease of code-difference comparison between versions
- When enhancing `module_utils` class methods, maintain all class methods in alphanumeric sort order facilitating ease of diff comparison between versions 
- ONLY make minimal/incremental changes made to the existing regression unit tests.
- In most cases for minor enhancements, it is expected that there should be no or minimal changes to the existing unit tests. 
- Make the necessary updates to the module README.md to reflect the new argument(s) and feature(s). 
- Make sure all module source and unit test file changes sanity-test acceptable.
