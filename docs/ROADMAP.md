# Roadmap

Known gaps in v1, in the order they should be closed. The first unblocks the
rest.

## 1. A corpus

Everything below "asserted" in the trust vocabulary exists because the only
public FDR data is sanitized pipeline fixtures. The fix is a stratified sample
from the Splunk instance the hunters already use (`queries/discovery/` is the
starting point), ingested by the build as `data/curated/observed.json`:

- fill rate per `(field, event)` and a cardinality class per field
- measured resolution rates for the three asserted process edges
- which of the 284 never-observed fields appear in the tenant

With that, `asserted` edges become `validated` (with a rate) or `refuted`, the
empty "populated first" ordering fills in, and `RawProcessId` recycling gets a
measured rate. The trust vocabulary and `basis_ref` are already shaped to take
it.

## 2. Settle the detection `ProcessId` PID space

One query against tenant data: join `Event_DetectionSummaryEvent.ProcessId` to
`ProcessRollup2.TargetProcessId` on the same agent id, and separately to
`RawProcessId` in a window. Whichever resolves replaces the gate in the
detection workflow with a cited edge.

## 3. `process_events` columns

"Everything this process did" returns `_time event_simpleName ContextProcessId
TargetProcessId`. The useful observable columns (`DomainName`,
`RemoteAddressIP4`, `TargetFileName`, `RegObjectName`, `CommandLine`) should be
chosen against a corpus, not fixtures — hence after §1.

## 4. Display-layer tests

The data layer and the SPL generator are pinned by tests. The display layer is
not: chip text equals edge basis, meaning renders confidence and evidence,
suggested joins never share a table with edges, `audit` never reaches the DOM.
DOM-shimmed render tests per band.

## 5. Smaller

- `same_role_fields` for `user_id` lumps `UID`/`GID` with SIDs (reference list
  only, never a join). The name rule is too broad.
- The 17 `unclassified` CIM names (`answer`, `app`, `date`, `description`, …)
  could carry curated meanings.
- Accessibility was verified structurally (real tables, roles, focus, contrast),
  not with a screen reader.
- Default event scope on a field page is alphabetical; with no fill rates there
  is no better default.
