"""Offline redaction for text, JSON and CSV without replacing original files."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path

EXTENSIONS = {".txt", ".md", ".log", ".json", ".csv", ".yaml", ".yml", ".ini", ".conf", ".env"}
SKIP = {".git", "node_modules", ".venv", "__pycache__"}
MAX_BYTES = 10_000_000
SECRET_KEY = re.compile(r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?key|secret|password|passwd|token|authorization|credential)(?:$|[_-])")
ASSIGNMENT = re.compile(r'''(?im)\b(?:[A-Z][A-Z0-9]*[_-])*(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s#,'";]+))''')
RULES = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]+?-----END \1-----")),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16})\b")),
    ("BEARER", re.compile(r"(?i)(?<=Bearer )[A-Za-z0-9._~+/-]+=*")),
    ("EMAIL", re.compile(r"(?i)(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,}(?![\w.-])")),
    ("CN_ID", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{9}[\dXx](?!\d)")),
    ("PHONE", re.compile(r"(?<![\d\w])(?:\+?86[ -]?)?1[3-9]\d{9}(?!\d)")),
    ("IPV4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
)


class Redactor:
    def __init__(self, terms: list[str] | None = None):
        self.terms = sorted(set(term for term in terms or [] if term), key=len, reverse=True)
        self.values: dict[str, dict[str, str]] = {}
        self.counts = Counter()

    def mask(self, category: str, value: str) -> str:
        mapping = self.values.setdefault(category, {})
        if value not in mapping:
            mapping[value] = f"[{category}_{len(mapping) + 1:03d}]"
        self.counts[category] += 1
        return mapping[value]

    def text(self, text: str) -> str:
        spans = []
        for term in self.terms:
            spans.extend((match.start(), match.end(), "CUSTOM") for match in re.finditer(re.escape(term), text))
        for category, pattern in RULES:
            for match in pattern.finditer(text):
                if category == "IPV4":
                    try:
                        ipaddress.IPv4Address(match.group())
                    except ipaddress.AddressValueError:
                        continue
                spans.append((match.start(), match.end(), category))
        for match in ASSIGNMENT.finditer(text):
            group = next(index for index in (1, 2, 3) if match.group(index) is not None)
            spans.append((*match.span(group), "SECRET"))
        # Prefer the widest match so nested emails/phones inside a credential do not survive.
        accepted = []
        for start, end, category in sorted(spans, key=lambda item: (-(item[1] - item[0]), item[0])):
            if not any(start < other_end and end > other_start for other_start, other_end, _ in accepted):
                accepted.append((start, end, category))
        result = []
        cursor = 0
        for start, end, category in sorted(accepted):
            result.extend([text[cursor:start], self.mask(category, text[start:end])])
            cursor = end
        result.append(text[cursor:])
        return "".join(result)

    def json_value(self, value, key: str = ""):
        if SECRET_KEY.search(key) and value is not None and value != "":
            return self.mask("SECRET", json.dumps(value, ensure_ascii=False, sort_keys=True))
        if isinstance(value, dict):
            result = {}
            for child_key, child in value.items():
                sanitized_key = self.text(child_key)
                if sanitized_key in result:
                    raise ValueError("redaction would create duplicate JSON keys")
                result[sanitized_key] = self.json_value(child, child_key)
            return result
        if isinstance(value, list):
            return [self.json_value(child) for child in value]
        if isinstance(value, str):
            return self.text(value)
        # Numeric identifiers cannot be pattern-matched safely without changing arbitrary numbers.
        return value

    def document(self, content: str, suffix: str) -> str:
        if suffix.lower() == ".json":
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON keys are not supported")
                    result[key] = value
                return result
            return json.dumps(self.json_value(json.loads(content, object_pairs_hook=unique_pairs)), ensure_ascii=False, indent=2) + "\n"
        if suffix.lower() == ".csv":
            rows = list(csv.reader(io.StringIO(content), strict=True))
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\n")
            headers = rows[0] if rows else []
            for number, row in enumerate(rows):
                writer.writerow([self.mask("SECRET", cell) if number and index < len(headers) and SECRET_KEY.search(headers[index]) and cell else self.text(cell) for index, cell in enumerate(row)])
            return output.getvalue()
        return self.text(content)


def input_files(source: Path) -> list[Path]:
    if source.is_symlink():
        raise ValueError("symbolic links are not supported")
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise ValueError("input does not exist")
    files = []
    for directory, dirs, names in os.walk(source, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in SKIP and not (Path(directory) / name).is_symlink())
        files.extend(Path(directory) / name for name in sorted(names) if not (Path(directory) / name).is_symlink() and ((Path(name).suffix.lower() in EXTENSIONS) or name.startswith(".env")))
    return files


def run(source: str | Path, output: str | Path | None = None, terms: list[str] | None = None) -> dict:
    original = Path(source)
    if original.is_symlink():
        raise ValueError("symbolic links are not supported")
    source = original.resolve()
    target = Path(output).resolve() if output is not None else None
    if target and (target.exists() or target == source or (source.is_dir() and target.is_relative_to(source))):
        raise ValueError("output must be new and outside the input directory")
    files = input_files(source)
    redactor = Redactor(terms)
    parent = target.parent if target else None
    if parent and not parent.is_dir():
        raise ValueError("output parent directory does not exist")
    with tempfile.TemporaryDirectory(prefix="redactor-", dir=parent) as temp:
        staged = Path(temp) / "result"
        if source.is_dir():
            staged.mkdir()
        for path in files:
            if path.stat().st_size > MAX_BYTES:
                raise ValueError(f"file exceeds 10 MB: {path.name}")
            content = path.read_text(encoding="utf-8-sig")
            sanitized = redactor.document(content, path.suffix)
            if target:
                destination = staged / path.relative_to(source) if source.is_dir() else staged
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(sanitized, encoding="utf-8")
        if target:
            if target.exists():
                raise ValueError("output already exists")
            staged.rename(target)
    return {"files_processed": len(files), "replacements": dict(sorted(redactor.counts.items())), "total_replacements": sum(redactor.counts.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="report counts without writing documents; exit 1 if matches found")
    parser.add_argument("--terms-file", type=Path, help="UTF-8 exact-match terms, one per line")
    args = parser.parse_args()
    if bool(args.output) == args.check:
        parser.error("choose exactly one of --output or --check")
    try:
        terms = args.terms_file.read_text(encoding="utf-8-sig").splitlines() if args.terms_file else None
        result = run(args.source, args.output, terms)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if args.check and result["total_replacements"] else 0
    except (OSError, ValueError, csv.Error) as exc:
        # Do not include a parser's potentially sensitive source text in logs.
        print(f"Unable to process input ({type(exc).__name__}). Check encoding, format and output path.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
