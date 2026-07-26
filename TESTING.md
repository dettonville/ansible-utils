# Testing Guide

## Overview

This repository is organized as an official **Ansible Collection**. To maintain integration consistency with core frameworks and CI/CD pipelines, ensure source files and associated tests align with standard namespacing structural layouts.

### Source Code Structure
- **Actions**: `plugins/action/`
- **Filters**: `plugins/filter/`
- **Modules**: `plugins/modules/`
- **Module Utils**: `plugins/module_utils/`

### Unit Test Structure
- **Action tests**: `tests/unit/plugins/action/`
- **Filter tests**: `tests/unit/plugins/filter/`
- **Module tests**: `tests/unit/plugins/modules/`
- **Module Utils tests**: `tests/unit/plugins/module_utils/`

### Sanity / Integration Tests
See `tests/sanity/` and `tests/integration/` directories for additional test types.

### Running Tests

This project supports two primary testing workflows depending on your development needs:
1. **Direct Pytest Execution**: Lightweight and lightning-fast execution for rapid unit test iteration.
2. **`ansible-test` Suite**: The official Ansible test framework for running unit tests and sanity checks inside fully valid collection environments.

---

## 1. Fast Local Unit Testing (`pytest`)

Thanks to the root `conftest.py` setup, standalone Pytest runs out-of-the-box without requiring manual environment bootstrapping or custom path wrappers.

### Execution
Run unit tests directly from the repository root:

```bash
pytest tests/unit/
```

Or target a specific module:

```bash
pytest tests/unit/plugins/modules/test_export_dicts.py
```

#### Debugging & Logging using pytest
- Use `--tb=short` for concise errors.
- Enable logging: `pytest --log-cli-level=DEBUG -s ...`.

---

## 2. Ansible-Test Suite (`ansible-test`)

Passing execution utilizing the **`ansible-test`** framework is required before deploying modifications or merging pull requests. 

`ansible-test` strictly requires execution from within an Ansible Collection directory tree matching the Fully Qualified Collection Name (FQCN):
`.../ansible_collections/{namespace}/{collection}/`

Running `ansible-test` directly from a flat repo directory will fail with:
> `FATAL: The current working directory must be within the source tree being tested.`

To handle this, you can choose between two setup approaches:

### Approach A: Using the `run-tests.sh` Wrapper (Recommended for Agents & Automation)

The included `./run-tests.sh` script automatically handles setting up the required `ansible_collections` directory layout in a temporary workspace, executes `ansible-test`, and cleans up afterward. No manual directory or symlink setup is required.

Because `ansible-test` expects execution within a structured `ansible_collections/{namespace}/{name}/` path format, developers and automation agents should use the environment script wrapper for one-step execution.

#### Run Unit Tests via Wrapper:
```bash
./run-tests.sh units

# Run a specific test targeting a module file with pytest arguments
./run-tests.sh units tests/unit/plugins/modules/test_export_dicts.py
```

#### Run Sanity Checks via Wrapper:
```bash
./run-tests.sh sanity
```

---

### Approach B: Persistent Symlink Method (Best for Direct `ansible-test` CLI Use)

If you prefer calling `ansible-test` directly from your shell CLI (for flags, autocompletion, or specific python targets), create a persistent collection symlink path locally.

#### Step 1: Create the target collection path
```bash
mkdir -p ~/.ansible/collections/ansible_collections/dettonville
```

#### Step 2: Symlink your local repository root
```bash
ln -s "$(pwd)" ~/.ansible/collections/ansible_collections/dettonville/utils
```

#### Step 3: Navigate to the symlinked path and run tests
```bash
cd ~/.ansible/collections/ansible_collections/dettonville/utils
```

From this directory, direct `ansible-test` commands will execute seamlessly:

```bash
# Run unit tests on a specific module
ansible-test units -v --python 3.13 export_dicts

# Run all unit tests
ansible-test units -v --python 3.13

# Run collection sanity checks
ansible-test sanity --python 3.13
ansible-test sanity --python 3.13 <module_name>

# Targeted Sanity Matrix Linters
ansible-test sanity --python 3.13 --test pylint
ansible-test sanity --python 3.13 --test validate-modules

# Core Unit Tests
ansible-test units --python 3.13
ansible-test units --python 3.13 tests/units
ansible-test units --python 3.13 <module_name>

## To run tests within docker container runtime
ansible-test sanity --docker --python 3.13
```

> **MacOS Fork Note:** If encountering execution failures on macOS regarding `fork()` operations, export the initialization workaround bypass:
> `export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`

---

## Code Quality Standards & Auto-Formatting

Before dispatching validation testing passes, run standard linting formatters to automatically patch structural, variable formatting, or import style syntax exceptions:

```bash
# Format modules using Ruff
pip install ruff && ruff format plugins/

# Format modules using Black
pip install black && black plugins/

# Purge unused imports or variables via Autoflake
pip install autoflake && autoflake -r --in-place --remove-unused-variables --remove-all-unused-imports plugins/
```

## Quick Reference Summary

| Method | Execution Location | Bootstrapping Setup Required | Target Command |
| :--- | :--- | :--- | :--- |
| **Pytest** | Repo Root (`/path/to/repo`) | **None** (handled by root `conftest.py`) | `pytest tests/unit/` |
| **Script Wrapper** | Repo Root (`/path/to/repo`) | **Automated** (managed dynamically by script) | `./run-tests.sh units` |
| **Direct `ansible-test`** | Symlink Directory (`~/.ansible/.../utils`) | **One-time manual symlink** setup | `ansible-test units --python 3.13 [module]` |
