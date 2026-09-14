# ICAM and Zero Trust assessment artifacts

Source-based assessment of STIG Manager against DoD ICAM and Zero Trust requirements (CDRL A006 — DAF ICAM Assessment and Integration Roadmap). All findings cite `path:line` in this repository at the baseline commit recorded in `scripts/icam_gap_data.py` (`BASELINE_COMMIT`).

## Artifacts

| Path | Description |
|---|---|
| `ICAM-ZT-Gap-Assessment.md` | Narrative assessment: executive summary, as-is architecture and authentication flow, requirement sources, assessment by Zero Trust pillar and by NIST SP 800-53 control, identity lifecycle and authorization observations, auditability, legacy patterns, target-state architecture, integration roadmap, test plan, risks, and Government decisions. Embeds the three PNG diagrams. |
| `ICAM-ZT-Gap-Register.xlsx` | Generated workbook. Sheets: `Gaps` (one row per gap, twelve fixed columns), `Control-Crosswalk` (NIST control → status → evidence → related gaps), `ZT-Pillar-Summary` (as-is, target, derived gap counts per pillar), `Roadmap` (phase, activities, dependencies, decision needed, gaps addressed), `Method`, `Sources`. Header row frozen, autofilter on every sheet, conditional fill by risk level and by crosswalk status. |
| `diagrams/as-is-architecture.mmd` / `.png` | Component diagram of the deployed system as implemented. |
| `diagrams/target-state-architecture.mmd` / `.png` | Component diagram of the target state (enterprise IdP federation, PKI/CAC, policy decision and enforcement points, attribute sources, SIEM). |
| `diagrams/auth-sequence.mmd` / `.png` | Sequence diagram of the actual login → token → API authorization flow, annotated with the code locations that implement each step. |
| `scripts/icam_gap_data.py` | Maintained source data: gaps, crosswalk, pillar summaries, roadmap, method, verified sources. Edit this file, never the workbook. |
| `scripts/icam_gap_register.py` | Generates the workbook from the data file and validates the data and the Markdown cross-references. |

## Regenerating the workbook

Requires Python 3 and `openpyxl` (`pip install openpyxl`).

```sh
python3 docs/security/icam-zero-trust/scripts/icam_gap_register.py
```

The script validates the data (unique gap IDs, allowed pillar/risk/effort/phase values, `file:line` evidence or an explicit "Needs Government input" source, crosswalk references resolve to gap IDs), writes `ICAM-ZT-Gap-Register.xlsx`, reloads it, and prints each sheet's row count and the gap totals by risk level.

## Keeping the Markdown and the register synchronised

```sh
python3 docs/security/icam-zero-trust/scripts/icam_gap_register.py --check
```

`--check` regenerates the workbook and then fails (exit 1) if `ICAM-ZT-Gap-Assessment.md` drifts from the data in any of these ways: it references a gap ID that is not in the data or omits one that is; it does not contain the derived total string `N gaps (H High, M Medium, L Low)`; a row of the NIST crosswalk table (section 5) is missing, duplicated, has a different status, or lists different gap IDs than `CROSSWALK`; a pillar row header in section 4 is missing, duplicated, or lists different gap IDs than the gaps assigned to that pillar; or a roadmap phase bullet in section 10 is missing, duplicated, or lists different gap IDs than the gaps sequenced into that phase. Every control, pillar and phase must appear exactly once so that two contradictory rows cannot both pass. Run it after editing either file. Gap counts in the Markdown executive summary must match the data; do not type counts that the data does not produce.

## Regenerating the diagrams

Requires the Mermaid CLI (`npx @mermaid-js/mermaid-cli`).

```sh
cd docs/security/icam-zero-trust/diagrams
for f in as-is-architecture target-state-architecture auth-sequence; do
  npx -y @mermaid-js/mermaid-cli -i "$f.mmd" -o "$f.png" -b white -s 4
done
```

If the Chromium download used by the Mermaid CLI is not permitted in your environment, pass `-p puppeteer.json` with `{"executablePath": "<path to chromium>"}`.

## Rendering the assessment to PDF

The delivered PDF is produced from `ICAM-ZT-Gap-Assessment.md` with the contractor's Word template pipeline (Markdown to DOCX, DOCX to PDF via LibreOffice); that tooling is not part of this repository. The PNG diagrams are embedded by relative path, so any Markdown converter run from this directory produces an unbranded equivalent:

```sh
cd docs/security/icam-zero-trust
pandoc ICAM-ZT-Gap-Assessment.md -o ICAM-ZT-Gap-Assessment.pdf --resource-path=. -V geometry:margin=2cm
```

The narrative body is designed to render at 8–12 pages; re-check the page count after editing the Markdown.

## Conventions

- Evidence is `path:line` at the baseline commit. Line numbers drift; re-verify before quoting externally.
- Rows whose requirement source is "Needs Government input" record an assumption to be replaced by Government-furnished DAF ICAM direction (see assessment Section 4.3 and gap G-26).
- Only requirement sources whose URL was opened and matched from the assessment environment carry a URL in the `Sources` sheet; the others are cited by title.
