# AGENT.md - Development & Testing Guidelines for LLM Agents

Welcome, Agent. You are operating in an Ansible Collection repository structure. To ensure successful execution, zero-defect handoffs, and clean verification runs, you MUST strictly adhere to the guidelines, command invocation structures, and syntax guardrails outlined below.

---

## 1. Directory Structure & Layout Standards
Ansible collections follow a rigid layout. All modifications must conform to this schema:
*   **Filter Plugins:** Must be placed under `plugins/filter/` (e.g., `plugins/filter/my_custom_filters.py`).
*   **Action Plugins:** Must be placed under `plugins/action/` (e.g., `plugins/action/my_custom_action.py`).
*   **Module Plugins:** Must be placed under `plugins/modules/` (e.g., `plugins/modules/my_module.py`).
*   **Module Utilities:** Shared helpers must be placed under `plugins/module_utils/` (e.g., `plugins/module_utils/my_shared_utils.py`).

---

## 2. Syntax & Implementation Guardrails

### A. Crucial Python & YAML Syntax Rules
1.  **Never Nest Triple Quotes:** Do NOT wrap an entire Python file or Ansible module inside top-level triple quotes (`"""..."""`).
2.  **Ansible DOCUMENTATION Strings:** Define Ansible documentation strings (`DOCUMENTATION`, `EXAMPLES`, `RETURN`) as raw-string literals directly at the top-level of the file:
    ```python
    DOCUMENTATION = r'''
    ---
    module: my_module
    short_description: Do something useful
    '''
    ```
    Never nest this definition inside any outer Python triple-quoted block. Doing so corrupts the Python parser and yields `SyntaxError` crashes.
3.  **Module Utilities Requirements:** Helper files residing under `plugins/module_utils/` are standard python utility scripts. They do NOT require standard Ansible `DOCUMENTATION` or `EXAMPLES` blocks unless they serve as active, direct-entry modules.

### B. Remote Tracking Branch Definitions
*   The remote tracking setup on this repository tracks a remote branch named `main` on the `github` remote (rather than `origin`). Ensure all target branch alignment matches this standard.

---

## 3. Testing & Validation Workflow

You must strictly achieve a green exit status (**Exit Code 0**) on all sanity and unit tests before completing your handoff. 

### A. Execution Environment
Always use the localized repository test wrapper script `./run-tests.sh` to run execution sweeps. Do NOT attempt to run raw global binaries.

### B. Unit Testing Command
*   Run unit tests targeting your specific path or files:
    ```bash
    ./run-tests.sh units tests/unit/
    ```

### C. Sanity & Linting Command
*   Ansible sanity checks check Python version compatibility, schema format, compile correctness, and code standards:
    ```bash
    ./run-tests.sh sanity
    ```

---

## 4. Execution Step-by-Step Goal
1.  **Locate Context:** Scan the collection by running `list_repo_files` and searching via `query_repo_index`.
2.  **Develop:** Write clean, modular, and PEP8-compliant code.
3.  **Format:** Run `remedy_lint_errors_tool` to clean and format changes using Ruff.
4.  **Validate:** Run `./run-tests.sh sanity` and `./run-tests.sh units` to verify implementation before concluding tasks.
