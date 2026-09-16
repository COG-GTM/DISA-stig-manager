#!/usr/bin/env python3
"""Regenerate the generated sections of ddil-assessment.md from ddil-findings.json.

Every table and every count that appears in the assessment markdown is
rendered from the JSON so that no number or identifier is hand-typed.
Generated regions are delimited by marker comments of the form

    <!-- BEGIN GENERATED: <name> -->
    ...
    <!-- END GENERATED: <name> -->

Usage:
    python3 docs/assessments/build_ddil_summary.py          # rewrite the markdown in place
    python3 docs/assessments/build_ddil_summary.py --check  # exit 1 if the markdown is stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
JSON_PATH = HERE / "ddil-findings.json"
MD_PATH = HERE / "ddil-assessment.md"

BEGIN_RE = re.compile(r"<!-- BEGIN GENERATED: ([a-z0-9-]+) -->")
END_TEMPLATE = "<!-- END GENERATED: {name} -->"


def load_findings(path: Path = JSON_PATH) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def md_cell(value) -> str:
    """Escape a value for use inside a markdown table cell."""
    if isinstance(value, list):
        value = "; ".join(str(v) for v in value)
    return str(value).replace("|", "\\|").replace("\n", " ")


def code_list(items: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in items)


def table(headers: list[str], rows: list[list[str]]) -> str:
    out = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(" --- " for _ in headers) + "|",
    ]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def render_summary(data: dict) -> str:
    deps = data["dependencies"]
    fms = data["failure_modes"]
    recs = data["recommendations"]
    labs = data["lab_tests"]
    govs = data["government_decisions"]
    conditions = data["assessment"]["conditions"]

    by_condition = Counter(fm["condition"] for fm in fms)
    by_confidence = Counter(
        "inferred" if "inferred" in fm["confidence"] else "confirmed" for fm in fms
    )
    by_effort = Counter(rec["effort"] for rec in recs)
    by_owner = Counter(
        "Government decision involved"
        if "Government" in rec["owner"]
        else "Engineering"
        for rec in recs
    )
    controls = Counter(ctrl for rec in recs for ctrl in rec["nist_controls"])
    evidence_refs = set()
    for section in ("dependencies", "failure_modes", "recommendations"):
        for item in data[section]:
            evidence_refs.update(item.get("evidence", []))

    lines = [
        f"- Assessed commit: `{data['assessment']['assessed_sha']}` "
        f"(`{data['assessment']['repository']}`, branch `{data['assessment']['assessed_branch']}`, "
        f"API package version {data['assessment']['api_package_version']}).",
        f"- External dependencies enumerated: **{len(deps)}** ({', '.join(d['id'] for d in deps)}).",
        f"- Failure modes analyzed: **{len(fms)}** = {len(deps)} dependencies x {len(conditions)} conditions "
        + "("
        + ", ".join(f"{c}: {by_condition.get(c, 0)}" for c in conditions)
        + ").",
        f"- Failure modes by confidence: confirmed in code **{by_confidence.get('confirmed', 0)}**, "
        f"containing inferred elements **{by_confidence.get('inferred', 0)}**.",
        f"- Ranked engineering recommendations: **{len(recs)}** "
        + "(effort S: {S}, M: {M}, L: {L}; ".format(
            **{k: by_effort.get(k, 0) for k in ("S", "M", "L")}
        )
        + f"Engineering-owned: {by_owner.get('Engineering', 0)}, requiring a Government decision: "
        f"{by_owner.get('Government decision involved', 0)}).",
        f"- Distinct NIST SP 800-53 Rev. 5 controls referenced: **{len(controls)}** "
        f"({', '.join(sorted(controls))}).",
        f"- Lab test cases defined: **{len(labs)}** (one per recommendation).",
        f"- Items requiring a Government decision: **{len(govs)}**.",
        f"- Distinct `file:line` evidence references: **{len(evidence_refs)}**.",
    ]
    return "\n".join(lines)


def render_dependency_matrix(data: dict) -> str:
    headers = [
        "ID",
        "Dependency",
        "Direction",
        "Protocol/port",
        "Required at startup?",
        "Required per request?",
        "Evidence (file:line)",
    ]
    rows = []
    for dep in data["dependencies"]:
        rows.append(
            [
                dep["id"],
                md_cell(dep["name"]),
                md_cell(dep["direction"]),
                md_cell(dep["protocol_port"]),
                md_cell(dep["required_at_startup"]),
                md_cell(dep["required_per_request"]),
                code_list(dep["evidence"]),
            ]
        )
    return table(headers, rows)


def render_failure_modes(data: dict) -> str:
    dep_names = {d["id"]: d["name"] for d in data["dependencies"]}
    headers = [
        "ID",
        "Dependency",
        "Condition",
        "Observed/expected behavior",
        "Confidence",
        "Security consequence",
        "Evidence (file:line)",
    ]
    rows = []
    for fm in data["failure_modes"]:
        rows.append(
            [
                fm["id"],
                f"{fm['dependency_id']} {md_cell(dep_names[fm['dependency_id']])}",
                fm["condition"],
                md_cell(fm["behavior"]),
                md_cell(fm["confidence"]),
                md_cell(fm["security_consequence"]),
                code_list(fm["evidence"]),
            ]
        )
    return table(headers, rows)


def render_recommendations(data: dict) -> str:
    headers = [
        "Rank",
        "ID",
        "Recommendation",
        "D-DIL condition addressed",
        "NIST SP 800-53 Rev. 5 controls",
        "Effort",
        "Owner",
        "Addresses",
        "Evidence (file:line)",
    ]
    rows = []
    for rec in sorted(data["recommendations"], key=lambda r: r["rank"]):
        rows.append(
            [
                str(rec["rank"]),
                rec["id"],
                f"**{md_cell(rec['title'])}.** {md_cell(rec['recommendation'])}",
                md_cell(rec["conditions"]),
                md_cell(rec["nist_controls"]),
                rec["effort"],
                md_cell(rec["owner"]),
                md_cell(rec["addresses"]),
                code_list(rec["evidence"]),
            ]
        )
    return table(headers, rows)


def render_top_recommendations(data: dict, count: int = 5) -> str:
    recs = sorted(data["recommendations"], key=lambda r: r["rank"])[:count]
    lines = []
    for rec in recs:
        lines.append(
            f"{rec['rank']}. **{rec['id']} - {rec['title']}** "
            f"({', '.join(rec['conditions'])}; {', '.join(rec['nist_controls'])}; effort {rec['effort']}; owner: {rec['owner']})"
        )
    return "\n".join(lines)


def render_lab_plan(data: dict) -> str:
    rec_titles = {r["id"]: r["title"] for r in data["recommendations"]}
    blocks = []
    for lab in data["lab_tests"]:
        steps = "\n".join(
            f"   {i}. {step}" for i, step in enumerate(lab["steps"], start=1)
        )
        blocks.append(
            "\n".join(
                [
                    f"#### {lab['id']} - verifies {lab['recommendation_id']} ({rec_titles[lab['recommendation_id']]})",
                    "",
                    f"- **Tooling:** {lab['tooling']}",
                    f"- **Setup:** {lab['setup']}",
                    "- **Steps:**",
                    steps,
                    f"- **Pass:** {lab['pass']}",
                    f"- **Fail:** {lab['fail']}",
                ]
            )
        )
    return "\n\n".join(blocks)


def render_government_decisions(data: dict) -> str:
    headers = ["ID", "Topic", "Decision required", "Related recommendations"]
    rows = [
        [
            gov["id"],
            md_cell(gov["topic"]),
            md_cell(gov["decision_required"]),
            md_cell(gov["related"]),
        ]
        for gov in data["government_decisions"]
    ]
    return table(headers, rows)


RENDERERS = {
    "summary": render_summary,
    "dependency-matrix": render_dependency_matrix,
    "failure-modes": render_failure_modes,
    "recommendations": render_recommendations,
    "top-recommendations": render_top_recommendations,
    "lab-plan": render_lab_plan,
    "government-decisions": render_government_decisions,
}


def regenerate(markdown: str, data: dict) -> str:
    """Return `markdown` with every generated region re-rendered from `data`."""
    out = []
    pos = 0
    seen = set()
    for match in BEGIN_RE.finditer(markdown):
        name = match.group(1)
        if name not in RENDERERS:
            raise SystemExit(f"unknown generated region '{name}'")
        end_marker = END_TEMPLATE.format(name=name)
        end = markdown.find(end_marker, match.end())
        if end == -1:
            raise SystemExit(f"missing end marker for generated region '{name}'")
        seen.add(name)
        out.append(markdown[pos : match.end()])
        out.append("\n" + RENDERERS[name](data) + "\n")
        pos = end
    out.append(markdown[pos:])
    missing = set(RENDERERS) - seen
    if missing:
        raise SystemExit(f"markdown is missing generated regions: {sorted(missing)}")
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the markdown is stale",
    )
    args = parser.parse_args(argv)

    data = load_findings()
    current = MD_PATH.read_text(encoding="utf-8")
    rendered = regenerate(current, data)
    if args.check:
        if rendered != current:
            print(
                f"{MD_PATH.name} is stale; run {Path(__file__).name} to regenerate",
                file=sys.stderr,
            )
            return 1
        print(f"{MD_PATH.name} is up to date")
        return 0
    if rendered != current:
        MD_PATH.write_text(rendered, encoding="utf-8")
        print(f"updated {MD_PATH.relative_to(HERE.parent.parent)}")
    else:
        print(f"{MD_PATH.name} already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
