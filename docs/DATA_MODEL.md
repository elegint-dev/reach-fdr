# Data model

## Goal

A field-provenance and join-graph explorer for SOC hunters working FDR data
**in Splunk**. Renders live connections between fields, shows where each field
came from, encodes FDR-specific join semantics (process lineage), and does the
conversion math for the analyst.

Constraint that drives everything: **the hunter is in Splunk**, so the tool must
show the field names and values they will actually see in a Splunk search — not
the raw FDR wire format alone.

---

## The three provenance layers

Every field a hunter sees in Splunk is at one of three layers. The tool should
label every field with its layer — that *is* the provenance feature.

| Layer | Origin | Example | Source of truth |
|---|---|---|---|
| **1. Raw FDR** | emitted by the sensor | `TargetProcessId`, `CommandLine` | `data/public/fields_catalogue.csv`, FDR schema API |
| **2. TA-derived** | computed by the Splunk TA | `AsepFlags_meaning`, `aid_computer_name` | `data/cim/fdr_to_cim_fields.csv` (LOOKUP rows) |
| **3. CIM** | normalized model field | `action`, `process_id`, `dest` | `data/cim/cim_field_to_events.csv` (EVAL rows) |

A hunter typing `process_id` is at layer 3; the tool should be able to walk them
back to `TargetProcessId` at layer 1 and show the `EVAL` that did it. That
round-trip is the core interaction.

Already built and usable as the provenance backbone:

- `data/cim/fdr_to_cim_fields.csv` — 352 mappings, raw → CIM, with the responsible
  `EVAL`/`LOOKUP`/`FIELDALIAS`
- `data/cim/cim_field_to_events.csv` — 100 CIM fields → which events populate each
- `data/cim/cim_coverage_gaps.csv` — 219 events with **no** CIM representation; in
  the UI these are the "you can only reach this by raw `event_simpleName`" set
- `data/public/event_fields_observed.csv` — 275 events → their fields

---

## The join graph (the hard part)

FDR process identifiers are **not** OS PIDs and do not join naively. The tool's
value is encoding these correctly.

Relationships to model (**each must be validated against a real corpus before
being shipped as a join — see below**):

| Edge | Meaning |
|---|---|
| child `ParentProcessId` → parent `TargetProcessId` | process tree lineage |
| event `ContextProcessId` → process `TargetProcessId` | "which process caused this event" — the join that makes DNS/file/registry events attributable |
| `RawProcessId` | the OS-visible PID; **not** unique over time, unsafe as a join key alone |
| `TreeId` | groups a whole detection/activity tree |
| `aid` | host identity; joins to `aidmaster` for hostname/OS |
| `SHA256HashData` | joins to `appinfo` for file metadata |
| `UserSid` | joins to `userinfo` for account context |

The last three are confirmed directly from the TA — they are exactly the lookup
keys `Splunk_TA_CrowdStrike_FDR` 3.2.0 uses for enrichment.

### Conversion math to offer

- `*_decimal` legacy twins vs. current values
- FDR timestamp fields (ms epoch) ↔ human time; `ContextTimeStamp` vs
  `timestamp` vs `_time` differ in meaning and are a classic hunter trap
- bitmask fields → decoded meaning (the TA already ships
  `crowdstrike_ta_bitmask_lookup_*` tables for ~dozens of these; reuse rather
  than reimplement)

---

## What the TA already gives you (most of the semantic layer)

The corpus dependency is small. `Splunk_TA_CrowdStrike_FDR` 3.2.0 ships the semantics
directly, and `tools/analyze_splunk_ta.py` now extracts all of it.

### 1. Field semantics — how CIM names map to FDR fields

From `EVAL` bodies, per event type. E.g.:

```
process_id        = TargetProcessId   (ProcessRollup2, SyntheticProcessRollup2,
                                       InjectedThread, WmiCreateProcess, ...)
parent_process_id = ParentProcessId   (ProcessRollup2, EndOfProcess, ...)
process_exec      = ImageFileName     (split per platform)
process           = CommandLine       (trimmed, quotes stripped)
process_path      = platform-dependent parse of CommandLine vs ImageFileName
```

This is the provenance backbone, and it is **event-conditional** — the same CIM
field draws from different FDR fields depending on `event_simpleName`. The UI
must model that, not assume a flat 1:1 mapping. `data/cim/fdr_to_cim_fields.csv` and
`data/cim/cim_field_to_events.csv` carry it.

### 2. The conversion math — 169 decode tables, 1,370 value mappings

`data/cim/decode_tables.{json,csv}`. These are the enum decodes the "do the math for
me" feature needs, straight from the vendor:

```
ConnectionDirection  0 -> DIRECTION_OUTBOUND, 1 -> DIRECTION_INBOUND, ...
AsepClass            7 -> SERVICE, 8 -> AUTHENTICATION, ...
RequestType          1 -> A, 2 -> NS, 5 -> CNAME, 28 -> AAAA, ...
```

87 of the 169 decoded fields also appear in the field catalogue; the other 82
are fields the Elastic fixtures never exercised — more evidence the public
corpus is thin, and a reason to treat the TA as the better schema source here.

Edge cases handled during extraction: one table (`RequestType`) ships its
columns **reversed** (`<X>_meaning,<X>`), and the host-resolution lookup is
18 columns wide and is not a decode table — both are detected rather than
silently mis-parsed.

### 3. The enrichment joins — confirmed, not inferred

The TA's `LOOKUP` statements name the exact keys it joins on:

| Key | Joins to | Yields |
|---|---|---|
| `aid` | `aidmaster` | hostname, domain, OU, site, OS, geo, gateway, MAC |
| `SHA256HashData` | `appinfo` | company, file description/name/version, product |
| `UserSid` | `userinfo` | account type, user, username |

---

## What still genuinely needs a real corpus

Only **statistics and validation** — not semantics:

- fill rate / cardinality per field (drives UI ranking: show populated fields first)
- confirming the process-lineage edges actually resolve
  (`ParentProcessId` → `TargetProcessId`, `ContextProcessId` → `TargetProcessId`)
  and measuring how often they do
- real value formats and ranges
- which of the 219 CIM-gap events actually appear in this tenant's data

### Why the public corpus can't do it

The Elastic pipeline fixtures are **sanitized**. Over the 401 real telemetry
docs in that corpus:

- `ContextProcessId` samples as `000000000000`; `ParentProcessId` as `0`
- `ContextThreadId` / `SourceThreadId` zeroed
- `TargetProcessId` ↔ `ContextProcessId` value overlap only **16%**, where a
  real corpus would be near-total

Fine for structure, useless for joins and statistics.

### Recommended corpus source: Splunk, not FDR

Pull from the Splunk instance the hunters already use:

- the TA's transforms are **already applied**, so raw + TA-derived + CIM fields
  arrive together — provenance is directly observable rather than reconstructed
- it is, by construction, what the hunter sees
- no AWS credentials needed
- real cardinality, real joins, real value formats

Stratify the sample by `event_simpleName` so rare events are represented; a flat
head-N would be almost entirely `ProcessRollup2`.


---

## The build (`tools/build_knowledge_base.py`)

The corpus worth reasoning over is the **schema itself**, not a sample of
events. The build fuses every extracted artifact into one record per field
and emits the bundle the app renders (`app/data/`, contract in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §2).

```bash
python3 tools/build_knowledge_base.py --readme README.md
```

Inputs, all under `data/`:

| Path | Contents |
|---|---|
| `public/` | field catalogue and observed event→field mapping (`tools/harvest_public_schema.py`) |
| `cim/` | raw→CIM mappings, CIM coverage, decode tables (`tools/analyze_splunk_ta.py`) |
| `enrichment/` | AI-synthesized field semantics, 16 batches — an input, never regenerated |
| `curated/` | hand-authored join edges (each with a citable `basis_ref`) and the PID translation model; validated by the build |

### What a record carries

Type; semantic role and how it was decided (`role_basis`: decode table >
`_meaning` sibling > dotted prefix > name convention > enrichment); provenance
layer (`raw_fdr` / `ta_derived` / `cim`); the events it appears on; its CIM
targets or raw sources with the responsible `EVAL`/`LOOKUP` statement, per
event; its decode table; its join edges; enrichment suggestions kept separate
from edges; and a process route per `(field, event)` with a summary that is
`mixed` when events disagree.

Counts are in `app/data/manifest.json` and in the README's generated stats
block; they are not repeated here.

### Join edges: what is known vs. asserted

- **`confirmed_ta`** — the TA performs the join. `aid` → `aidmaster`,
  `SHA256HashData` → `appinfo`, `UserSid` → `userinfo`. These are search-time
  `LOOKUP-` stanzas: their outputs are already on the record wherever the
  stanza fires (`automatic_on` on the edge).
- **`asserted`** — CrowdStrike data-model semantics, not corpus-validated:
  `ParentProcessId` → `TargetProcessId` (process tree),
  `ContextProcessId` → `TargetProcessId` (causal attribution), `TreeId`
  grouping, and the detection-event renames `SHA256String` →
  `SHA256HashData`, `AgentIdString` → `aid`.

Not an edge: `ProcessId` on detection summary events. Nothing on disk says
which PID space it occupies.

`RawProcessId` is `cardinality: unsafe` — it is the OS PID, recycled, and the
generated SPL requires `aid` and a time window before it will use it.
