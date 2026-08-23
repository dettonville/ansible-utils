#!/usr/bin/env python
"""Script to automatically update Ansible plugin Markdown documentation."""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

VERSION = "2026.8.4"
NEWLINE_PATTERN = re.compile(r"[\r\n]+")

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)-5s]: ==> %(funcName)s(): %(message)s",
)
logger = logging.getLogger(__name__)


def get_repo_root() -> Path:
    """Return root directory of the repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(res.stdout.strip())
    except subprocess.CalledProcessError as err:
        logger.error("Failed to determine repository root: %s", err)
        sys.exit(1)


def get_ansible_version_info(env: dict[str, str]) -> str:
    """Capture raw output of `ansible --version` safely."""
    # noinspection PyDeprecation
    if not shutil.which("ansible"):
        return "ansible binary not found in PATH"
    try:
        res = subprocess.run(
            ["ansible", "--version"],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        if res.returncode == 0:
            return res.stdout.strip()
        return "ansible version unavailable"
    except Exception as err:  # pylint: disable=broad-exception-caught
        logger.warning("Could not capture ansible --version: %s", err)
        return "ansible version unavailable"


def get_collection_info(repo_root: Path) -> tuple[str, str]:
    """Parse namespace and name from galaxy.yml."""
    galaxy_path = repo_root / "galaxy.yml"
    if not galaxy_path.is_file():
        logger.error("galaxy.yml not found at %s", galaxy_path)
        sys.exit(1)

    with open(galaxy_path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    namespace = data.get("namespace", "dettonville")
    name = data.get("name", "utils")
    return namespace, name


def extract_plugin_names(src_path: Path, fallback_name: str) -> list[str]:
    """Extract plugin names from DOCUMENTATION string blocks in Python
    files."""
    try:
        content = src_path.read_text(encoding="utf-8")
        pattern = re.compile(r'DOCUMENTATION\w*\s*=\s*"""(.*?)"""', re.DOTALL)
        matches = pattern.findall(content)

        found_names = []
        for doc_str in matches:
            # noinspection PyBroadException
            try:
                data = yaml.safe_load(doc_str)
                if isinstance(data, dict) and "name" in data:
                    found_names.append(str(data["name"]).strip())
            except Exception:
                pass

        return found_names if found_names else [fallback_name]
    except Exception as e:
        logger.warning("Could not parse DOCUMENTATION in %s: %s", src_path, e)
        return [fallback_name]


def format_description(desc: str | list[str]) -> str:
    """Format description list or string into single paragraph with line
    breaks."""
    if isinstance(desc, list):
        # Join list items with <br> and sanitize any inner newlines
        cleaned_items = [
            NEWLINE_PATTERN.sub(" ", str(item)).strip() for item in desc
        ]
        return "<br>".join(cleaned_items)

    # Handle single string descriptions containing literal line breaks
    cleaned_desc = NEWLINE_PATTERN.sub(" ", str(desc))
    return cleaned_desc.strip()


def generate_markdown(
    doc_json: dict,
    fqcn: str,
    plugin_type: str,
    doc_path: Path,
    ansible_version_output: str,
    raw_ansible_doc_output: str,
) -> str:
    """Render JSON documentation dict into Galaxy-style Markdown
    with trailing CLI snippet."""
    plugin_data = doc_json.get(fqcn, {})
    doc = plugin_data.get("doc", {})
    examples = plugin_data.get("examples", "")

    # Handle both 'return' and 'returndocs' JSON key structures
    returns = plugin_data.get("return") or plugin_data.get("returndocs") or {}

    module_name = fqcn.split(".")[-1]
    short_desc = format_description(doc.get("short_description", ""))

    md = [f"## module > {module_name}\n"]

    # Title & Short Description
    if short_desc:
        md.append(f"{short_desc}\n")

    # Table of Contents / Anchors
    md.append("- [Synopsis](#synopsis)")
    md.append("- [Parameters](#parameters)")
    if examples:
        md.append("- [Examples](#examples)")
    if returns:
        md.append("- [Return Values](#return-values)")
    md.append(
        "- [CLI Reproducibility & Environment]"
        "(#cli-reproducibility--environment)"
    )
    md.append("\n## Synopsis\n")

    # Synopsis
    description = doc.get("description", [])
    if isinstance(description, list):
        for line in description:
            md.append(f"- {line}")
    elif description:
        md.append(f"- {description}")
    md.append("")

    # Parameters Table
    md.append("## Parameters\n")
    options = doc.get("options", {})
    if options:
        md.append("| Parameter | Choices / Defaults | Comments |")
        md.append("| :--- | :--- | :--- |")
        for opt_name, opt in options.items():
            opt_type = opt.get("type", "")
            elements = opt.get("elements", "")
            is_req = opt.get("required", False)

            type_str = opt_type
            if elements:
                type_str += f" / elements={elements}"
            if is_req:
                type_str += " / **required**"

            param_col = (
                f"**{opt_name}**<br>`{type_str}`"
                if type_str
                else f"**{opt_name}**"
            )

            choices = opt.get("choices", [])
            default = opt.get("default", None)
            choices_col = []
            if default is not None:
                choices_col.append(f"Default: `{json.dumps(default)}`")
            if choices:
                choices_col.append("Choices:")
                # Use bullet entity with <br> to prevent breaking
                # GFM table parsing
                choices_col.extend([f"&bull; `{c}`" for c in choices])
            choices_str = "<br>".join(choices_col)

            comments = format_description(opt.get("description", ""))
            aliases = opt.get("aliases", [])
            if aliases:
                comments += f"<br><br>*aliases:* `{', '.join(aliases)}`"

            md.append(f"| {param_col} | {choices_str} | {comments} |")
    else:
        md.append("No parameters specified.")
    md.append("")

    # Examples
    if examples:
        md.append("## Examples\n")
        md.append("```yaml")
        md.append(examples.strip())
        md.append("```\n")

    # Return Values Table
    if returns:
        md.append("## Return Values\n")
        md.append("| Key | Returned | Description |")
        md.append("| :--- | :--- | :--- |")
        for ret_name, ret in returns.items():
            ret_type = ret.get("type", "")
            key_col = (
                f"**{ret_name}**<br>`({ret_type})`"
                if ret_type
                else f"**{ret_name}**"
            )
            returned = ret.get("returned", "always")

            desc = format_description(ret.get("description", ""))
            sample = ret.get("sample", "")
            if sample:
                desc += f"<br><br>*sample:* `{sample}`"

            md.append(f"| {key_col} | {returned} | {desc} |")
        md.append("")

    # Trailing Section: CLI Reproducibility & Environment
    md.append("## CLI Reproducibility & Environment\n")
    md.append(
        "To view this module documentation directly in your terminal "
        "or replicate the output:"
    )
    md.append("")
    md.append("```shell")
    md.append("$ ansible --version")
    md.append(ansible_version_output)
    md.append('$ REPO_DIR="$( git rev-parse --show-toplevel )"')
    md.append("cd ${REPO_DIR}")
    md.append(
        f"$ env ANSIBLE_NOCOLOR=True ansible-doc -t "
        f"{plugin_type} {fqcn} | tee {doc_path}"
    )
    if raw_ansible_doc_output:
        md.append(raw_ansible_doc_output.strip())
    md.append("```\n")

    return "\n".join(md)


def resolve_target_files(
    targets: list[str], repo_root: Path, namespace: str, name: str
) -> list[Path]:
    """Resolve user-supplied targets into plugin Python file paths."""
    if not targets:
        plugin_files = []
        for plugin_type_dir in ["modules", "lookup", "filter"]:
            dir_path = repo_root / "plugins" / plugin_type_dir
            if dir_path.exists():
                plugin_files.extend(sorted(dir_path.glob("*.py")))
        return plugin_files

    resolved_files = set()
    for target in targets:
        clean_target = target.strip()

        # Strip FQCN prefix if provided
        # (e.g. dettonville.utils.x509_certificate_verify)
        fqcn_prefix = f"{namespace}.{name}."
        prefix_len = len(fqcn_prefix)
        if clean_target.startswith(fqcn_prefix):
            clean_target = clean_target[prefix_len:]

        target_path = Path(clean_target)
        if target_path.is_file():
            resolved_files.add(target_path.resolve())
            continue

        # Try matching plugin name across module, lookup,
        # and filter directories
        found = False
        stem = target_path.stem
        for plugin_type_dir in ["modules", "lookup", "filter"]:
            candidate = repo_root / "plugins" / plugin_type_dir / f"{stem}.py"
            if candidate.is_file():
                resolved_files.add(candidate.resolve())
                found = True
                break

        if not found:
            logger.warning("Could not resolve target: %s", target)

    return sorted(list(resolved_files))


def main():
    """Main execution entry point."""
    parser = argparse.ArgumentParser(
        description="Update Ansible Plugin Documentation"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional module/plugin file paths or names to process "
        "(e.g. plugins/modules/x509_certificate_verify.py "
        "or x509_certificate_verify)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="force update of plugin documentation",
    )
    parser.add_argument(
        "-L",
        "--loglevel",
        default="INFO",
        choices=["ERROR", "WARN", "INFO", "DEBUG"],
        help="set logging level",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    args = parser.parse_args()

    # Set Log Level
    log_level_map = {
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }
    logger.setLevel(log_level_map.get(args.loglevel, logging.INFO))

    # Pre-check required binaries
    # noinspection PyDeprecation
    if not shutil.which("ansible-doc"):
        logger.warning(
            "ansible-doc command not found in PATH. Skipping documentation "
            "update."
        )
        # Exit with 0 so non-ansible environments (or CI runners) do not
        # break commits
        sys.exit(0)

    repo_root = get_repo_root()
    namespace, name = get_collection_info(repo_root)
    docs_dir = repo_root / "docs"

    logger.debug("COLLECTION_NAMESPACE=[%s]", namespace)
    logger.debug("COLLECTION_NAME=[%s]", name)

    plugin_files = resolve_target_files(
        args.targets, repo_root, namespace, name
    )
    if not plugin_files:
        logger.error("No valid plugin files found to process.")
        sys.exit(1)

    # Setup isolated collections path for ansible-doc execution
    with tempfile.TemporaryDirectory(prefix="ansible_doc_") as temp_dir:
        temp_path = Path(temp_dir)
        target_dir = temp_path / "ansible_collections" / namespace / name
        target_dir.parent.mkdir(parents=True, exist_ok=True)

        # Create symlink:
        # temp_dir/ansible_collections/namespace/name -> repo_root
        os.symlink(repo_root, target_dir)

        # Set environment
        env = os.environ.copy()
        existing_path = env.get("ANSIBLE_COLLECTIONS_PATH", "")
        env["ANSIBLE_COLLECTIONS_PATH"] = (
            f"{temp_dir}:{existing_path}" if existing_path else temp_dir
        )
        env["ANSIBLE_NOCOLOR"] = "True"

        # Capture ansible --version context once
        ansible_ver_info = get_ansible_version_info(env)
        errors_found = False

        for src_path in plugin_files:
            if src_path.name == "__init__.py":
                continue

            plugin_type_dir = src_path.parent.name
            plugin_type = (
                "module" if plugin_type_dir == "modules" else plugin_type_dir
            )
            file_base_name = src_path.stem

            internal_names = extract_plugin_names(src_path, file_base_name)

            for plugin_name in internal_names:
                fqcn = f"{namespace}.{name}.{plugin_name}"
                doc_path = docs_dir / f"{plugin_name}.md"

                # Check modification timestamps unless --force is specified
                # or specific targets passed
                if (
                    not args.force
                    and not args.targets
                    and doc_path.is_file()
                    and src_path.is_file()
                ):
                    if src_path.stat().st_mtime < doc_path.stat().st_mtime:
                        logger.info(
                            "Skipping [%s.md]: Documentation is up to date.",
                            plugin_name,
                        )
                        continue

                # Command 1: Get JSON structured data
                cmd_json = ["ansible-doc", "-t", plugin_type, "--json", fqcn]
                logger.debug("Running JSON command: %s", " ".join(cmd_json))
                res_json = subprocess.run(
                    cmd_json,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )

                # Command 2: Get Raw Text output for trailing CLI snippet
                cmd_raw = ["ansible-doc", "-t", plugin_type, fqcn]
                logger.debug("Running Raw Command: %s", " ".join(cmd_raw))
                res_raw = subprocess.run(
                    cmd_raw,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )

                if res_json.returncode == 0 and res_json.stdout.strip():
                    try:
                        doc_json = json.loads(res_json.stdout)
                        raw_text = (
                            res_raw.stdout if res_raw.returncode == 0 else ""
                        )

                        markdown_content = generate_markdown(
                            doc_json=doc_json,
                            fqcn=fqcn,
                            plugin_type=plugin_type,
                            doc_path=doc_path,
                            ansible_version_output=ansible_ver_info,
                            raw_ansible_doc_output=raw_text,
                        )

                        docs_dir.mkdir(parents=True, exist_ok=True)
                        doc_path.write_text(markdown_content, encoding="utf-8")
                        logger.info(
                            "Successfully created [%s.md]", plugin_name
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to render Markdown for [%s]: %s", fqcn, e
                        )
                        errors_found = True
                else:
                    logger.error(
                        "Failed executing ansible-doc for [%s] "
                        "(exit code: %s)",
                        fqcn,
                        res_json.returncode,
                    )
                    if res_json.stderr:
                        logger.error(
                            "  ansible-doc stderr: %s",
                            res_json.stderr.strip(),
                        )
                    errors_found = True

        if errors_found:
            sys.exit(1)

    logger.info("Documentation generation complete.")


if __name__ == "__main__":
    main()
