# FDR query library

Splunk Cloud. Every query uses only Cloud-available commands — no `join`,
no `map`, no custom commands.

```
queries/
  macros/      reusable macros — install once, call from anywhere
  process/     process-centric hunting (the current focus)
  discovery/   learn your own data before you hunt in it
```

## Start here

1. **Install the macros** — `macros/SPLUNK_CLOUD_MACROS.md`. Do `cs_index`
   first; everything depends on it.
2. **Run `discovery/01`** — find out which event types you actually receive.
   The catalogue lists 275; your licensing, platform mix and sensor versions
   decide which you really get.
3. **Then hunt** — `process/`.

## What a macro actually buys you

A macro is a saved, named SPL fragment with arguments. You install it once, then
call it with backticks from any search bar. The alternative is pasting 20 lines
and editing the value in two places each time.

Without:
```spl
index=cs sourcetype=crowdstrike:events:sensor earliest=-24h
  ( SHA256HashData="abc123" OR event_simpleName=ProcessRollup2 OR ... )
| eval _pid = coalesce(ContextProcessId, TargetProcessId)
| where isnotnull(_pid)
... 15 more lines, and "abc123" appears twice ...
```

With:
```spl
`cs_trace_process("SHA256HashData", "abc123", "-24h")`
```

Same result. The backticks are what make it a macro call — without them Splunk
treats it as literal text.

## Worked example — you have a suspicious hash

```spl
| `cs_trace_process("SHA256HashData", "e3b0c44298fc1c14...", "-24h")`
```
→ every process that touched that file, on every host, with image, command line,
OS PID and parent.

Pick the interesting row; it gives you `aid` and `TargetProcessId`.

```spl
| `cs_process_events("<aid>", "<TargetProcessId>", "-24h")`
```
→ everything that process did: network, files, registry, DNS.

```spl
| `cs_process_table("<aid>", "-24h")`
```
→ the host's whole process table, so you can walk lineage up and down.

Three macro calls from an unattributed hash to full process context.

## Going the other way — a ticket gave you an OS PID

```spl
| `cs_pid_lookup("<aid>", "4820", "-1h")`
```

**Expect multiple rows.** The OS recycles PIDs; a busy host reuses the same one
several times a day. That is why `earliest` is required rather than optional.

Disambiguate on `ImageFileName`, then confirm `ProcessStartTime` precedes the
activity you are investigating — a process cannot cause an event that predates
its own start. Carry `TargetProcessId` forward.

There is **no arithmetic** that converts an OS PID to a CrowdStrike one. Tested
against 28 paired documents: low-32-bit mask, low-16-bit mask, right-shift 32
and modulo all failed in every case. It is a lookup, never a calculation.

## Macros

| Macro | Args | Purpose |
|---|---|---|
| `cs_index` | — | your FDR index; set first |
| `cs_trace_process` | field, value, earliest | observable → process |
| `cs_process_table` | aid, earliest | every process on a host (tree source) |
| `cs_pid_lookup` | aid, ospid, earliest | OS PID → TargetProcessId |
| `cs_process_events` | aid, tpid, earliest | process → everything it did |

## Caveat

These are written from the schema, not validated against a live Splunk.
Run each once against data you already understand before trusting it on an
investigation.
