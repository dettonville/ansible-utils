
The attached `readme`, `module source`, and `module unit test file` for the ansible module `x509_certificate_verify` currently passes all 20 unit tests.
It also passes all sanity tests.

Please enhance the module to:
(1) only set the `result['failed']` to `True` and invoke `module.fail_json(**result)` for logical exceptions.
    The `fail_json` should NOT occur upon cert property `verification` failures.
(2) The cert `verification` failures should set `result['valid'] = False` and `result['verify_failed'] = True`.
    Additionally, each `verification` should have a specific key with boolean return value set in a `verify_results` dictionary when tested.
    E.g., 
    `results['failed'] = False`
    `results['valid'] = False`
    `results['verify_failed'] = True`
    `verify_results['common_name'] = True`
    `verify_results['key_type'] = True`
    `verify_results['key_size'] = False`
(2) The logical certificate verifications should be performed according to the specified module arguments unless an exception prevents remaining tests from executing (e.g., "file does not exist").  For example, if the only module input argument specified was the `path` and `common_name`, the certificate "verification" tests results should only include and record for the 'common_name' test with example `successful` verification results as follows:
    `results['failed'] = False`
    `results['valid'] = True`
    `results['verify_failed'] = False`
    `verify_results['common_name'] = True`
    
(3) The module should only set `result['failed'] = True` whenever an unexpected logic exception occurs apart from the `verification` tests in the testing workflow.


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
