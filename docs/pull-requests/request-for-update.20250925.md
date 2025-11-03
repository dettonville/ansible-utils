
The attached `readme`, `module source`, and `module unit test file` for the ansible module `x509_certificate_verify` currently passes all 40 unit tests.
It also passes all sanity tests.

## Motivation

There module should also support verifying the certificate `key_usage` and `signature`.

## Proposed Enhancement

### Add new Parameters

Add `key_usage` and `signature` to the module's argument specification.

### Update Module Logic

### Update Tests

Enhance existing tests if the respective regression feature and/or tests are impacted by the new feature enhancement(s);
Remove existing tests if the regression feature has been eliminated by the new feature enhancement(s);
Add new tests to verify the new features enhancement(s) work as intended / expected.
    E.g., Add tests to verify that  `key_usage` and `signature` is correctly verified.

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
