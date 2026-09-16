# Reach macros — Splunk Cloud install

Splunk Cloud gives you no filesystem, so there is no `local/macros.conf` to drop
a file into. Install these through the web UI instead:

**Settings → Advanced search → Search macros → New Search Macro**

For each macro below: paste the **Name** exactly (the `(n)` arity suffix
matters), the comma-separated **Arguments**, and the **Definition** body.
Leave "Validation Expression" empty. Set permissions to your app/role as needed.

> Paste the definition as plain multi-line SPL. Do **not** add backslash
> continuations — those are only for `.conf` files, and will break the macro
> in the web form.

Every macro below uses only commands available on Splunk Cloud
(`eval`, `stats`, `eventstats`, `where`, `table`, `sort`, `convert`, `rename`).
No `join`, no `map`, no custom commands.

Set `cs_index` first — the others depend on it.

---

## 1. `cs_index`

**Name:** `cs_index`
**Arguments:** *(leave empty)*
**Definition:**
```
your_fdr_index
```

---

## 2. `cs_trace_process(3)` — any observable → the process that did it

**Name:** `cs_trace_process(3)`
**Arguments:** `field, value, earliest`
**Definition:**
```
search index=`cs_index` sourcetype=crowdstrike:events:sensor earliest=$earliest$
  ( $field$="$value$"
    OR event_simpleName=ProcessRollup2
    OR event_simpleName=SyntheticProcessRollup2 )
| eval _pid = coalesce(ContextProcessId, TargetProcessId)
| where isnotnull(_pid)
| eval _hit = if($field$="$value$", 1, 0),
       _anchor = if(event_simpleName IN ("ProcessRollup2","SyntheticProcessRollup2"), 1, 0)
| stats max(_hit) as matched, max(_anchor) as has_anchor,
        min(_time) as first_seen, max(_time) as last_seen,
        values(eval(if(_hit=1, event_simpleName, null()))) as observed_on,
        values(eval(if(_anchor=1, ImageFileName, null()))) as image,
        values(eval(if(_anchor=1, CommandLine, null()))) as command_line,
        values(eval(if(_anchor=1, RawProcessId, null()))) as os_pid,
        values(eval(if(_anchor=1, ParentProcessId, null()))) as parent_pid
        by aid, _pid
| where matched=1
| rename _pid as TargetProcessId
| eval resolved = if(has_anchor=1, "yes", "no - creation event outside time range")
| table aid TargetProcessId os_pid image command_line parent_pid observed_on first_seen last_seen resolved
| convert ctime(first_seen) ctime(last_seen)
| sort - last_seen
```

**Use:**
```spl
`cs_trace_process("SHA256HashData", "abc123...", "-24h")`
`cs_trace_process("DomainName", "evil.example.com", "-7d")`
`cs_trace_process("RemoteAddressIP4", "10.1.2.3", "-1h")`
```

`resolved=no` means the observable was attributed to a process, but that
process's creation event is outside your window or aged out. Widen `earliest`.

---

## 3. `cs_process_table(2)` — every process on a host

**Name:** `cs_process_table(2)`
**Arguments:** `aid, earliest`
**Definition:**
```
search index=`cs_index` sourcetype=crowdstrike:events:sensor earliest=$earliest$
  aid="$aid$"
  (event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2)
| stats min(_time) as start_seen, values(RawProcessId) as os_pid,
        values(ImageFileName) as image, values(CommandLine) as command_line,
        values(ParentProcessId) as parent_tpid,
        values(ProcessStartTime) as process_start_time,
        values(UserSid) as user_sid, values(SHA256HashData) as sha256
        by aid, TargetProcessId
| convert ctime(start_seen)
| sort start_seen
```

This is the **tree source**. SPL has no recursion, so rather than forcing an
N-level ancestry walk into a search, pull the host's process table once and let
the client walk it. It is one scan and the whole lineage is in the result.

**Use:**
```spl
`cs_process_table("abc123def456...", "-24h")`
```

---

## 4. `cs_pid_lookup(3)` — OS PID → CrowdStrike TargetProcessId

**Name:** `cs_pid_lookup(3)`
**Arguments:** `aid, ospid, earliest`
**Definition:**
```
search index=`cs_index` sourcetype=crowdstrike:events:sensor earliest=$earliest$
  aid="$aid$" RawProcessId="$ospid$"
  (event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2)
| table _time aid TargetProcessId RawProcessId ImageFileName CommandLine ProcessStartTime ParentProcessId
| sort _time
```

**Expect more than one row.** The OS recycles PIDs, so a narrow `earliest` is
required, not optional. Disambiguate on `ImageFileName`, then confirm
`ProcessStartTime` precedes the activity you are investigating. Carry
`TargetProcessId` forward.

---

## 5. `cs_process_events(3)` — everything a process did

**Name:** `cs_process_events(3)`
**Arguments:** `aid, tpid, earliest`
**Definition:**
```
search index=`cs_index` sourcetype=crowdstrike:events:sensor earliest=$earliest$
  aid="$aid$"
  (ContextProcessId="$tpid$" OR TargetProcessId="$tpid$")
| table _time event_simpleName ContextProcessId TargetProcessId
| sort _time
```

The reverse of `cs_trace_process`: given a process, every event it generated.
`ContextProcessId` is the attribution key on non-process events — 176 of 275
event types carry it.

---

## Notes for Splunk Cloud

- **Index name.** Cloud indexes are often named per-tenant. If `cs_index` is
  wrong you get zero results with no error. Confirm with
  `| eventcount summarize=false index=*` first.
- **Sourcetype.** These assume the TA's `crowdstrike:events:sensor`. If your
  ingest is via HEC or a different route, check with
  `index=<yours> | stats count by sourcetype`.
- **No `join` anywhere.** Splunk's `join` truncates at 50k rows / 60s
  *silently* — on a busy FDR index it drops results without telling you. These
  use the `stats` self-join pattern, which has no such limit.
- **Cost.** `cs_trace_process` scans the observable plus all process-creation
  events in the window. If you know the host, add `aid="..."` to the search
  line — orders of magnitude faster.
