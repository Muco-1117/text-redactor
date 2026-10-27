import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from text_redactor import Redactor, run


class RedactorTest(unittest.TestCase):
    def test_consistent_placeholders_and_summary_does_not_include_values(self):
        value = "person" + "@" + "example.org"
        redactor = Redactor()
        result = redactor.text(f"Contact {value}, again {value}; 13800138000 at 192.168.1.12")
        self.assertNotIn(value, result)
        self.assertEqual(result.count("[EMAIL_001]"), 2)
        self.assertNotIn("13800138000", result)
        self.assertNotIn("192.168.1.12", result)
        self.assertNotIn(value, json.dumps(dict(redactor.counts)))

    def test_json_nested_secrets_and_escaped_strings_stay_valid(self):
        source = {"openai_api_key": "synthetic-value", "people": [{"email": "person@example.org", "note": 'quotes " and\nline break'}], "count": 42}
        result = json.loads(Redactor().document(json.dumps(source), ".json"))
        self.assertEqual(result["openai_api_key"], "[SECRET_001]")
        self.assertEqual(result["people"][0]["email"], "[EMAIL_001]")
        self.assertEqual(result["count"], 42)

    def test_csv_quoted_multiline_cells_and_secret_columns(self):
        result = Redactor().document('name,email,password,note\nAlice,person@example.org,short,"hello,\nworld"\n', ".csv")
        row = list(csv.DictReader(io.StringIO(result)))[0]
        self.assertEqual(row["password"], "[SECRET_001]")
        self.assertEqual(row["note"], "hello,\nworld")
        self.assertEqual(row["email"], "[EMAIL_001]")

    def test_batch_failure_publishes_nothing_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "a.txt").write_text("person@example.org")
            (source / "b.json").write_text("invalid json")
            output = root / "sanitized"
            with self.assertRaises(ValueError):
                run(source, output)
            self.assertFalse(output.exists())
            self.assertEqual((source / "a.txt").read_text(), "person@example.org")
            output.mkdir()
            with self.assertRaises(ValueError):
                run(source, output)

    def test_check_is_read_only_and_custom_terms_are_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "notes.txt"
            source.write_text("Internal.Project[1] and person@example.org")
            before = source.read_bytes()
            result = run(source, terms=["Internal.Project[1]"])
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(result["total_replacements"], 2)

    def test_output_cannot_be_nested_inside_input(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run(directory, Path(directory) / "output")

    def test_private_keys_and_assigned_secrets_are_fully_removed(self):
        header = "-----BEGIN " + "PRIVATE KEY-----"
        footer = "-----END " + "PRIVATE KEY-----"
        private = header + "\nsynthetic-pem-body\n" + footer
        api = "sk-" + "7u9A3m2B5x8C6p4D1r0E7y3F9q2G8s4H"
        value = private + "\nOPENAI_API_KEY=" + api + "\npassword='short-value'"
        result = Redactor().text(value)
        self.assertNotIn("synthetic-pem-body", result)
        self.assertNotIn(api, result)
        self.assertNotIn("short-value", result)
        self.assertIn("PRIVATE_KEY", result)

    def test_cli_check_and_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            output = root / "sanitized.json"
            source.write_text('{"email":"person@example.org"}', encoding="utf-8")
            script = str(Path(__file__).resolve().parents[1] / "text_redactor.py")
            checked = subprocess.run([sys.executable, script, str(source), "--check"], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 1, checked.stdout)
            self.assertNotIn("person@example.org", checked.stdout)
            written = subprocess.run([sys.executable, script, str(source), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(written.returncode, 0, written.stdout)
            self.assertEqual(json.loads(output.read_text())["email"], "[EMAIL_001]")


if __name__ == "__main__":
    unittest.main()
