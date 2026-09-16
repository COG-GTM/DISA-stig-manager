"""Consistency tests for the D-DIL assessment deliverables.

Run with either of:

    python3 -m pytest docs/assessments/test_ddil_assessment.py -q
    python3 docs/assessments/test_ddil_assessment.py

The tests assert that
  * every stable identifier (DEP-, FM-, REC-, LAB-, GOV-) present in the JSON
    appears in the markdown and vice versa (bidirectional set equality);
  * cross-references inside the JSON resolve (failure mode -> dependency,
    recommendation -> failure mode, lab test -> recommendation,
    decision -> recommendation);
  * every dependency has a failure mode for every D-DIL condition and every
    recommendation has exactly one lab test;
  * every `file:line` or `file:start-end` evidence reference in the JSON and the
    markdown points to an existing file and a line range inside that file;
  * the generated regions of the markdown are current with respect to the JSON.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
JSON_PATH = HERE / "ddil-findings.json"
MD_PATH = HERE / "ddil-assessment.md"

sys.path.insert(0, str(HERE))
import build_ddil_summary  # noqa: E402

ID_RE = re.compile(r"\b(DEP|FM|REC|LAB|GOV)-\d{2}\b")
# A repository-relative path followed by :line or :start-end. Paths are limited
# to the directories that hold evidence so that prose such as "10:00" or URLs
# with ports are not mistaken for references.
EVIDENCE_RE = re.compile(
    r"(?<![\w/])((?:api|client|docs|test)/[A-Za-z0-9_./-]+|Dockerfile):(\d+)(?:-(\d+))?(?![\w:])"
)

ID_SECTIONS = {
    "DEP": "dependencies",
    "FM": "failure_modes",
    "REC": "recommendations",
    "LAB": "lab_tests",
    "GOV": "government_decisions",
}


def load() -> tuple[dict, str]:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    markdown = MD_PATH.read_text(encoding="utf-8")
    return data, markdown


def json_ids(data: dict, prefix: str) -> set[str]:
    return {item["id"] for item in data[ID_SECTIONS[prefix]]}


def markdown_ids(markdown: str, prefix: str) -> set[str]:
    return {m.group(0) for m in ID_RE.finditer(markdown) if m.group(1) == prefix}


def json_evidence(data: dict) -> set[str]:
    refs: set[str] = set()
    for section in ("dependencies", "failure_modes", "recommendations"):
        for item in data[section]:
            refs.update(item["evidence"])
    return refs


def parse_ref(ref: str) -> tuple[str, int, int]:
    match = EVIDENCE_RE.fullmatch(ref)
    if not match:
        raise ValueError(f"malformed evidence reference: {ref!r}")
    path, start, end = match.group(1), int(match.group(2)), match.group(3)
    return path, start, int(end) if end else start


def line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


class TestIdConsistency(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.markdown = load()

    def test_ids_match_bidirectionally(self) -> None:
        for prefix in ID_SECTIONS:
            with self.subTest(prefix=prefix):
                in_json = json_ids(self.data, prefix)
                in_md = markdown_ids(self.markdown, prefix)
                self.assertTrue(in_json, f"no {prefix} identifiers in JSON")
                self.assertEqual(
                    in_json,
                    in_md,
                    f"{prefix}: only in JSON {sorted(in_json - in_md)}; only in markdown {sorted(in_md - in_json)}",
                )

    def test_ids_are_unique_and_well_formed(self) -> None:
        for prefix, section in ID_SECTIONS.items():
            ids = [item["id"] for item in self.data[section]]
            self.assertEqual(len(ids), len(set(ids)), f"duplicate {prefix} ids")
            for item_id in ids:
                self.assertRegex(item_id, rf"^{prefix}-\d{{2}}$")

    def test_internal_cross_references_resolve(self) -> None:
        deps = json_ids(self.data, "DEP")
        fms = json_ids(self.data, "FM")
        recs = json_ids(self.data, "REC")
        for fm in self.data["failure_modes"]:
            self.assertIn(fm["dependency_id"], deps, fm["id"])
        for rec in self.data["recommendations"]:
            for fm_id in rec["addresses"]:
                self.assertIn(fm_id, fms, f"{rec['id']} addresses unknown {fm_id}")
        for lab in self.data["lab_tests"]:
            self.assertIn(lab["recommendation_id"], recs, lab["id"])
        for gov in self.data["government_decisions"]:
            for rec_id in gov["related"]:
                self.assertIn(rec_id, recs, f"{gov['id']} relates to unknown {rec_id}")

    def test_every_dependency_has_every_condition(self) -> None:
        conditions = set(self.data["assessment"]["conditions"])
        seen: dict[str, set[str]] = {}
        for fm in self.data["failure_modes"]:
            self.assertIn(fm["condition"], conditions, fm["id"])
            seen.setdefault(fm["dependency_id"], set()).add(fm["condition"])
        for dep in self.data["dependencies"]:
            self.assertEqual(
                seen.get(dep["id"], set()),
                conditions,
                f"{dep['id']} missing conditions",
            )
        self.assertEqual(
            len(self.data["failure_modes"]),
            len(self.data["dependencies"]) * len(conditions),
        )

    def test_recommendations_are_ranked_and_tested(self) -> None:
        ranks = sorted(rec["rank"] for rec in self.data["recommendations"])
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))
        lab_targets = [lab["recommendation_id"] for lab in self.data["lab_tests"]]
        self.assertEqual(sorted(lab_targets), sorted(json_ids(self.data, "REC")))
        for rec in self.data["recommendations"]:
            self.assertIn(rec["effort"], {"S", "M", "L"}, rec["id"])
            self.assertTrue(rec["nist_controls"], f"{rec['id']} has no controls")
            for ctrl in rec["nist_controls"]:
                self.assertRegex(ctrl, r"^[A-Z]{2}-\d+$", f"{rec['id']}: {ctrl}")
            self.assertTrue(
                set(rec["conditions"]) <= set(self.data["assessment"]["conditions"]),
                rec["id"],
            )


class TestEvidenceReferences(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.markdown = load()

    def _assert_ref_exists(self, ref: str, origin: str) -> None:
        path, start, end = parse_ref(ref)
        target = REPO_ROOT / path
        self.assertTrue(target.is_file(), f"{origin}: {ref} -> {path} does not exist")
        total = line_count(target)
        self.assertGreaterEqual(start, 1, f"{origin}: {ref} has a non-positive line")
        self.assertLessEqual(end, total, f"{origin}: {ref} exceeds {total} lines")
        self.assertLessEqual(start, end, f"{origin}: {ref} has an inverted range")

    def test_json_evidence_exists(self) -> None:
        refs = json_evidence(self.data)
        self.assertTrue(refs)
        for ref in sorted(refs):
            with self.subTest(ref=ref):
                self._assert_ref_exists(ref, "json")

    def test_every_finding_has_evidence(self) -> None:
        for section in ("dependencies", "failure_modes", "recommendations"):
            for item in self.data[section]:
                self.assertTrue(item["evidence"], f"{item['id']} has no evidence")

    def test_markdown_evidence_exists(self) -> None:
        refs = {m.group(0) for m in EVIDENCE_RE.finditer(self.markdown)}
        self.assertTrue(refs)
        for ref in sorted(refs):
            with self.subTest(ref=ref):
                self._assert_ref_exists(ref, "markdown")

    def test_json_evidence_appears_in_markdown(self) -> None:
        md_refs = {m.group(0) for m in EVIDENCE_RE.finditer(self.markdown)}
        missing = json_evidence(self.data) - md_refs
        self.assertEqual(
            missing, set(), f"JSON evidence absent from markdown: {sorted(missing)}"
        )


class TestGeneratedContent(unittest.TestCase):
    def test_markdown_is_current(self) -> None:
        data, markdown = load()
        self.assertEqual(
            build_ddil_summary.regenerate(markdown, data),
            markdown,
            "ddil-assessment.md is stale; run build_ddil_summary.py",
        )

    def test_assessed_sha_present(self) -> None:
        data, markdown = load()
        sha = data["assessment"]["assessed_sha"]
        self.assertRegex(sha, r"^[0-9a-f]{40}$")
        self.assertIn(sha, markdown)


if __name__ == "__main__":
    unittest.main(verbosity=2)
