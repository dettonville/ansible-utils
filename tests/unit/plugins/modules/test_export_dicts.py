"""
Unit tests for the export_dicts Ansible module.

This test suite covers the actual implementation of the export_dicts module
which exports lists of dictionaries to CSV or Markdown format files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import csv
import io
import os
import tempfile
import shutil

import unittest
from unittest.mock import Mock, patch, mock_open

from ansible.module_utils import basic


from ansible_collections.dettonville.utils.tests.unit.plugins.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
    MockAnsibleModule,
    exit_json,
    fail_json,
)

from ansible_collections.dettonville.utils.plugins.module_utils.export_dict_utils import (
    get_headers_and_fields,
    write_csv_string,
    write_csv_file,
    write_markdown_string,
    write_markdown_file,
)
from ansible_collections.dettonville.utils.plugins.modules.export_dicts import (
    main as module_main,
    get_file_format,
    setup_module_object,
)

MODULES_IMPORT_PATH = "ansible_collections.dettonville.utils.plugins.modules"


def make_absolute(base_path, name):
    return ".".join([base_path, name])


# Mock the export_dict_utils functions for isolated testing
def mock_write_csv_file(module, output_file, export_list, column_list):
    return {
        "changed": True,
        "message": f"The csv file has been created successfully at {output_file}",
    }


def mock_write_markdown_file(module, output_file, export_list, column_list):
    return {
        "changed": True,
        "message": f"The markdown file has been created successfully at {output_file}",
    }


# Test the utility functions directly
class TestExportDictUtils(ModuleTestCase):
    """Test cases for the export_dict_utils module functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_export_list = [
            {"key1": "value11", "key2": "value12", "key3": "value13"},
            {"key1": "value21", "key2": "value22", "key3": "value23"},
            {"key1": "value31", "key2": "value32", "key3": "value33"},
        ]

        self.sample_column_list = [
            {"name": "key1", "header": "Key #1"},
            {"name": "key2", "header": "Key #2"},
            {"name": "key3", "header": "Key #3"},
        ]

        self.get_headers_and_fields = get_headers_and_fields
        self.write_csv_string = write_csv_string
        self.write_csv_file = write_csv_file
        self.write_markdown_string = write_markdown_string
        self.write_markdown_file = write_markdown_file

    def test_get_headers_and_fields(self):
        """Test extracting headers and field names from column list."""
        headers, fieldnames = self.get_headers_and_fields(
            self.sample_column_list)

        expected_headers = ["Key #1", "Key #2", "Key #3"]
        expected_fieldnames = ["key1", "key2", "key3"]

        self.assertEqual(headers, expected_headers)
        self.assertEqual(fieldnames, expected_fieldnames)

    def test_get_headers_and_fields_no_headers(self):
        """Test fallback to fieldnames when headers are empty."""
        column_list_no_headers = [
            {"name": "key1", "header": ""},
            {"name": "key2", "header": ""},
            {"name": "key3", "header": ""},
        ]

        headers, fieldnames = self.get_headers_and_fields(
            column_list_no_headers)

        # Should fallback to fieldnames when headers are empty
        self.assertEqual(headers, fieldnames)
        self.assertEqual(fieldnames, ["key1", "key2", "key3"])

    def test_write_csv_string(self):
        """Test generating CSV string from export data."""
        csv_string = self.write_csv_string(
            self.sample_export_list, self.sample_column_list
        )

        print(f"csv_string: {csv_string}")

        # Parse the CSV string to verify structure
        csv_reader = csv.reader(io.StringIO(csv_string))
        rows = list(csv_reader)

        # Check header row
        self.assertEqual(rows[0], ["Key #1", "Key #2", "Key #3"])

        # Check data rows
        self.assertEqual(len(rows), 4)  # 1 header + 3 data rows
        self.assertEqual(rows[1], ["value11", "value12", "value13"])
        self.assertEqual(rows[2], ["value21", "value22", "value23"])
        self.assertEqual(rows[3], ["value31", "value32", "value33"])

    def test_write_csv_file_success(self):
        """Test successful CSV file creation."""
        mock_module = MockAnsibleModule()
        output_file = "/tmp/test.csv"

        with patch("builtins.open", mock_open()) as mock_file:
            result = self.write_csv_file(
                mock_module,
                output_file,
                self.sample_export_list,
                self.sample_column_list,
            )

            # Verify file was opened for writing
            mock_file.assert_called_once_with(output_file, mode="w")

            # Verify result
            self.assertTrue(result["changed"])
            self.assertIn("successfully", result["message"])
            self.assertIn(output_file, result["message"])

    def test_write_csv_file_io_error(self):
        """Test CSV file creation with IO error."""
        mock_module = MockAnsibleModule()
        output_file = "/tmp/test.csv"

        with patch("builtins.open", side_effect=IOError("Permission denied")):
            self.write_csv_file(
                mock_module,
                output_file,
                self.sample_export_list,
                self.sample_column_list,
            )

            # Should call fail_json on IO error
            mock_module.fail_json.assert_called_once()

    def test_write_markdown_string(self):
        """Test generating Markdown string from export data."""
        md_string = self.write_markdown_string(
            self.sample_export_list, self.sample_column_list
        )

        lines = md_string.strip().split("\n")

        # Check header row
        self.assertIn("Key #1", lines[0])
        self.assertIn("Key #2", lines[0])
        self.assertIn("Key #3", lines[0])

        # Check separator row
        self.assertIn("---", lines[1])

        # Check data rows
        self.assertIn("value11", lines[2])
        self.assertIn("value12", lines[2])
        self.assertIn("value13", lines[2])

    def test_write_markdown_string_missing_columns(self):
        """Test Markdown generation with missing column values."""
        incomplete_export_list = [
            {"key1": "value11", "key3": "value13"},  # Missing key2
            {"key1": "value21", "key2": "value22"},  # Missing key3
        ]

        md_string = self.write_markdown_string(
            incomplete_export_list, self.sample_column_list
        )

        lines = md_string.strip().split("\n")

        # Should handle missing columns gracefully
        self.assertIn("value11", lines[2])
        self.assertIn("value13", lines[2])
        self.assertIn("value21", lines[3])
        self.assertIn("value22", lines[3])

    def test_write_markdown_file_success(self):
        """Test successful Markdown file creation."""
        mock_module = MockAnsibleModule()
        output_file = "/tmp/test.md"

        with patch("codecs.open", mock_open()) as mock_file:
            result = self.write_markdown_file(
                mock_module,
                output_file,
                self.sample_export_list,
                self.sample_column_list,
            )

            # Verify file was opened with UTF-8 encoding
            mock_file.assert_called_once_with(
                output_file, "w", encoding="utf-8")

            # Verify result
            self.assertTrue(result["changed"])
            self.assertIn("successfully", result["message"])
            self.assertIn(output_file, result["message"])

    def test_write_markdown_file_io_error(self):
        """Test Markdown file creation with IO error."""
        mock_module = MockAnsibleModule()
        output_file = "/tmp/test.md"

        with patch("codecs.open", side_effect=IOError("Permission denied")):
            self.write_markdown_file(
                mock_module,
                output_file,
                self.sample_export_list,
                self.sample_column_list,
            )

            # Should call fail_json on IO error
            mock_module.fail_json.assert_called_once()

    def test_unicode_support_markdown(self):
        """Test Unicode character support in Markdown generation."""
        unicode_export_list = [
            {"key1": "båz", "key2": "value12", "key3": "value13"},
            {"key1": "value21", "key2": "ﬀöø", "key3": "value23"},
            {"key1": "value31", "key2": "value32", "key3": "ḃâŗ"},
        ]

        md_string = self.write_markdown_string(
            unicode_export_list, self.sample_column_list
        )

        # Unicode characters should be preserved
        self.assertIn("båz", md_string)
        self.assertIn("ﬀöø", md_string)
        self.assertIn("ḃâŗ", md_string)

    def test_unicode_support_csv(self):
        """Test Unicode character support in CSV generation."""
        unicode_export_list = [
            {"key1": "båz", "key2": "value12", "key3": "value13"},
            {"key1": "value21", "key2": "ﬀöø", "key3": "value23"},
            {"key1": "value31", "key2": "value32", "key3": "ḃâŗ"},
        ]

        csv_string = self.write_csv_string(
            unicode_export_list, self.sample_column_list)
        print(f"csv_string: {csv_string}")

        # Unicode characters should be preserved
        self.assertIn("båz", csv_string)
        self.assertIn("ﬀöø", csv_string)
        self.assertIn("ḃâŗ", csv_string)


class TestExportDictsModule(ModuleTestCase):
    """Test cases for the main export_dicts module."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_export_list = [
            {"key1": "value11", "key2": "value12", "key3": "value13"},
            {"key1": "value21", "key2": "value22", "key3": "value23"},
            {"key1": "value31", "key2": "value32", "key3": "value33"},
        ]

        self.sample_column_list = [
            {"name": "key1", "header": "Key #1"},
            {"name": "key2", "header": "Key #2"},
            {"name": "key3", "header": "Key #3"},
        ]

        self.get_file_format = get_file_format
        self.setup_module_object = setup_module_object
        self.main = module_main

        self.mock_module_helper = patch.multiple(
            basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)

    def test_get_file_format_csv(self):
        """Test file format detection for CSV files."""
        self.assertEqual(self.get_file_format("test.csv"), "csv")
        self.assertEqual(self.get_file_format("path/to/file.CSV"), "csv")

    def test_get_file_format_markdown(self):
        """Test file format detection for Markdown files."""
        self.assertEqual(self.get_file_format("test.md"), "md")
        self.assertEqual(self.get_file_format("path/to/file.MD"), "md")

    def test_get_file_format_no_extension(self):
        """Test file format detection with no extension defaults to CSV."""
        self.assertEqual(self.get_file_format("testfile"), "csv")

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    def test_setup_module_object(self, mock_ansible_module):
        """Test module object setup."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module

        self.setup_module_object()

        # Verify AnsibleModule was called with correct parameters
        mock_ansible_module.assert_called_once()
        args, kwargs = mock_ansible_module.call_args

        # Check that argument_spec is properly defined
        self.assertIn("argument_spec", kwargs)
        arg_spec = kwargs["argument_spec"]

        # Verify required parameters
        self.assertIn("file", arg_spec)
        self.assertIn("export_list", arg_spec)
        self.assertEqual(arg_spec["file"]["required"], True)
        self.assertEqual(arg_spec["export_list"]["required"], True)

        # Verify optional parameters
        self.assertIn("format", arg_spec)
        self.assertIn("column_list", arg_spec)
        self.assertIn("logging_level", arg_spec)

        # Verify choices
        self.assertEqual(arg_spec["format"]["choices"], ["md", "csv"])
        self.assertEqual(
            arg_spec["logging_level"]["choices"], [
                "NOTSET", "DEBUG", "INFO", "ERROR"]
        )

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.write_csv_file"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_csv_export(
            self, mock_exists, mock_ansible_module, mock_write_csv):
        """Test main function with CSV export."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True  # Directory exists

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": "csv",
            "export_list": self.sample_export_list,
            "column_list": self.sample_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        mock_write_csv.return_value = {
            "changed": True,
            "message": "The csv file has been created successfully at /tmp/test.csv",
        }

        self.main()

        # Verify write_csv_file was called
        mock_write_csv.assert_called_once_with(
            mock_module,
            "/tmp/test.csv",
            self.sample_export_list,
            self.sample_column_list,
        )

        # Verify exit_json was called with correct result
        mock_module.exit_json.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.write_markdown_file"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_markdown_export(
        self, mock_exists, mock_ansible_module, mock_write_markdown
    ):
        """Test main function with Markdown export."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True  # Directory exists

        mock_module.params = {
            "file": "/tmp/test.md",
            "format": "md",
            "export_list": self.sample_export_list,
            "column_list": self.sample_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        mock_write_markdown.return_value = {
            "changed": True,
            "message": "The markdown file has been created successfully at /tmp/test.md",
        }

        self.main()

        # Verify write_markdown_file was called
        mock_write_markdown.assert_called_once_with(
            mock_module,
            "/tmp/test.md",
            self.sample_export_list,
            self.sample_column_list,
        )

        # Verify exit_json was called with correct result
        mock_module.exit_json.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_directory_not_exists(self, mock_exists, mock_ansible_module):
        """Test main function when destination directory doesn't exist."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = False  # Directory doesn't exist
        mock_module.fail_json.side_effect = AnsibleFailJson(Exception)

        mock_module.params = {
            "file": "/nonexistent/test.csv",
            "format": "csv",
            "export_list": self.sample_export_list,
            "column_list": self.sample_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        with self.assertRaises(AnsibleFailJson):
            self.main()

        # Should call fail_json when directory doesn't exist
        mock_module.fail_json.assert_called_once()
        args, kwargs = mock_module.fail_json.call_args
        self.assertEqual(kwargs["rc"], 257)
        self.assertIn("does not exist", kwargs["msg"])

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_check_mode(self, mock_exists, mock_ansible_module):
        """Test main function in check mode."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_module.exit_json.side_effect = AnsibleExitJson(Exception)

        mock_exists.return_value = True

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": "csv",
            "export_list": self.sample_export_list,
            "column_list": self.sample_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = True  # Check mode enabled

        with self.assertRaises(AnsibleExitJson):
            self.main()

        # Should exit immediately in check mode
        mock_module.exit_json.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.write_csv_file"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_auto_format_detection(
        self, mock_exists, mock_ansible_module, mock_write_csv
    ):
        """Test main function with automatic format detection."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": None,  # No format specified
            "export_list": self.sample_export_list,
            "column_list": self.sample_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        mock_write_csv.return_value = {
            "changed": True,
            "message": "The csv file has been created successfully at /tmp/test.csv",
        }

        self.main()

        # Should auto-detect CSV format from file extension
        mock_write_csv.assert_called_once()

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.write_csv_file"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_auto_column_derivation(
        self, mock_exists, mock_ansible_module, mock_write_csv
    ):
        """Test main function with automatic column derivation."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": "csv",
            "export_list": self.sample_export_list,
            "column_list": [],  # Empty column list
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        mock_write_csv.return_value = {
            "changed": True,
            "message": "The csv file has been created successfully at /tmp/test.csv",
        }

        self.main()

        # Should derive columns from first row
        mock_write_csv.assert_called_once()
        call_args = mock_write_csv.call_args
        derived_columns = call_args[0][3]  # column_list parameter

        # Check that columns were derived
        self.assertGreater(len(derived_columns), 0)
        self.assertEqual(derived_columns[0]["name"], "key1")
        self.assertEqual(derived_columns[0]["header"], "key1")

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    def test_main_empty_column_name(self, mock_exists, mock_ansible_module):
        """Test main function with empty column name."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True

        invalid_column_list = [
            {"name": "", "header": "Key #1"},  # Empty name
            {"name": "key2", "header": "Key #2"},
        ]

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": "csv",
            "export_list": self.sample_export_list,
            "column_list": invalid_column_list,
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        self.main()

        # Should call fail_json for empty column name
        mock_module.fail_json.assert_called_once()
        args, kwargs = mock_module.fail_json.call_args
        self.assertIn("Column name not found", kwargs["msg"])

    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.write_csv_file"))
    @patch(make_absolute(MODULES_IMPORT_PATH, "export_dicts.AnsibleModule"))
    @patch("os.path.exists")
    @patch("sys.version_info", (3, 6))  # Mock Python 3.6
    def test_main_python36_column_sorting(
        self, mock_exists, mock_ansible_module, mock_write_csv
    ):
        """Test main function with Python 3.6 column sorting."""
        mock_module = Mock()
        mock_ansible_module.return_value = mock_module
        mock_exists.return_value = True

        # Use unordered export list to test sorting
        unordered_export_list = [
            {"key3": "value13", "key1": "value11", "key2": "value12"}
        ]

        mock_module.params = {
            "file": "/tmp/test.csv",
            "format": "csv",
            "export_list": unordered_export_list,
            "column_list": [],
            "logging_level": "INFO",
        }
        mock_module.check_mode = False

        mock_write_csv.return_value = {
            "changed": True,
            "message": "The csv file has been created successfully at /tmp/test.csv",
        }

        self.main()

        # Should sort columns for Python < 3.7
        mock_write_csv.assert_called_once()
        call_args = mock_write_csv.call_args
        derived_columns = call_args[0][3]  # column_list parameter

        # Check that columns are sorted
        column_names = [col["name"] for col in derived_columns]
        self.assertEqual(column_names, ["key1", "key2", "key3"])


class TestExportDictsIntegration(ModuleTestCase):
    """Integration tests for the complete export_dicts workflow."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.sample_data = [
            {"name": "John", "age": 30, "city": "New York"},
            {"name": "Jane", "age": 25, "city": "Los Angeles"},
            {"name": "Bob", "age": 35, "city": "Chicago"},
        ]
        self.sample_columns = [
            {"name": "name", "header": "Full Name"},
            {"name": "age", "header": "Age"},
            {"name": "city", "header": "City"},
        ]

    def tearDown(self):
        """Clean up integration test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_csv_export_integration(self):
        """Test complete CSV export workflow."""
        output_file = os.path.join(self.temp_dir, "test.csv")

        # Import utility functions
        try:

            mock_module = MockAnsibleModule()
            result = write_csv_file(
                mock_module, output_file, self.sample_data, self.sample_columns
            )

            # Verify file was created
            self.assertTrue(os.path.exists(output_file))

            # Verify content
            with open(output_file, "r") as f:
                content = f.read()
                self.assertIn("Full Name", content)
                self.assertIn("John", content)
                self.assertIn("Jane", content)
                self.assertIn("Bob", content)

            # Verify result
            self.assertTrue(result["changed"])
            self.assertIn("successfully", result["message"])

        except ImportError:
            self.skipTest(
                "export_dict_utils not available for integration test")

    def test_markdown_export_integration(self):
        """Test complete Markdown export workflow."""
        output_file = os.path.join(self.temp_dir, "test.md")

        # Import utility functions
        try:

            mock_module = MockAnsibleModule()
            result = write_markdown_file(
                mock_module, output_file, self.sample_data, self.sample_columns
            )

            # Verify file was created
            self.assertTrue(os.path.exists(output_file))

            # Verify content
            with open(output_file, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Full Name", content)
                self.assertIn("John", content)
                self.assertIn("Jane", content)
                self.assertIn("Bob", content)
                self.assertIn("|", content)  # Markdown table format
                self.assertIn("---", content)  # Markdown separator

            # Verify result
            self.assertTrue(result["changed"])
            self.assertIn("successfully", result["message"])

        except ImportError:
            self.skipTest(
                "export_dict_utils not available for integration test")

    def test_large_dataset_export(self):
        """Test exporting large datasets."""
        large_data = [
            {"id": i, "name": f"User {i}", "email": f"user{i}@example.com"}
            for i in range(1000)
        ]

        columns = [
            {"name": "id", "header": "ID"},
            {"name": "name", "header": "Name"},
            {"name": "email", "header": "Email"},
        ]

        output_file = os.path.join(self.temp_dir, "large_test.csv")

        try:

            mock_module = MockAnsibleModule()
            result = write_csv_file(
                mock_module, output_file, large_data, columns)

            # Verify file was created
            self.assertTrue(os.path.exists(output_file))

            # Verify content
            with open(output_file, "r") as f:
                lines = f.readlines()
                # 1000 data rows + 1 header row
                self.assertEqual(len(lines), 1001)

            # Verify result
            self.assertTrue(result["changed"])

        except ImportError:
            self.skipTest(
                "export_dict_utils not available for integration test")


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
