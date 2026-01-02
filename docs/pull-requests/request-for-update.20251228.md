
Attached find the source code for the ansible "dettonville.utils" collection.

The file is a concatenation of all the source files into a single text file with the following file header/footer delimiters:
    - "### FILE: <relative_file_path> ###" 
    - "### END FILE: <relative_file_path> ###"

The current ansible module `x509_certificate_verify` currently passes all existing/regression "ansible-test unit" tests.

It also passes all "ansible-test sanity" tests.

## Motivation

Enhance / Update the module "x509_certificate_verify.py" to take a new optional parameter "private_key_path".
If specified, perform a test to verify that the private key is correct for the specified certificate. 
The return results "verify_results" dictionary should include a key for the key verification(s)/test(s) performed.

Also add the appropriate test cases for the new key verification logic in the "test_x509_certificate_verify.py" unit tests.

Make sure that the enhancement passes all new and regression unit and sanity tests.

## Proposed Enhancement

### Add new Parameters

Add `private_key_path` to the module's argument specification.

### Update Module Logic

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
