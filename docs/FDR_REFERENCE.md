# CrowdStrike Falcon Data Replicator — what it emits

## The short answer

**There is no single fixed list of FDR fields**, and any list you find published
on the open web is a partial, dated snapshot. The real schema is:

- **hundreds of event types** (`event_simpleName` values) and **thousands of
  distinct fields** — the dump script prints the exact counts for your tenant;
- **versioned** — events and fields are added/deprecated with sensor releases;
- **tenant-scoped** — you only receive event types your CID is licensed and
  configured for (Insight/EDR vs. Identity Protection vs. Cloud, etc.);
- **platform-conditional** — the same event carries different fields on
  Windows vs. Mac vs. Linux vs. Android.

CrowdStrike does not publish the dictionary publicly. It is exposed two ways,
both gated behind your own tenant:

1. **FDR schema API** (machine-readable — use this) — see below.
2. **Events Data Dictionary** in the Falcon console
   (*Documentation → Events Data Dictionary*), the human-readable enumeration.

`tools/dump_fdr_schema.py` in this directory pulls #1 and produces the complete,
authoritative, tenant-accurate list as JSON + CSV + Markdown.

---

## 0. Credentials — two different kinds

Both are issued from **Support and resources → API clients and keys**, and they
are *not* interchangeable. Creating either requires the **Falcon Administrator**
role.

### a. OAuth2 API client  ← what `tools/dump_fdr_schema.py` needs
Section: *OAuth2 API clients* → **Create API client**.
Yields a **Client ID** + **Client Secret** (secret is shown **once** — capture it).

| | |
|---|---|
| Scope required | **Falcon Data Replicator: READ** (that one scope, nothing else) |
| Used for | the `/fdr/...` schema endpoints — the event/field dictionary |
| Auth | OAuth2 client-credentials → bearer token, **valid 30 minutes** |
| Cloud | base URL must match your tenant's region (see table in §1) |

This is a *metadata* credential. It gets you the schema. It does **not** give you
any telemetry.

### b. FDR AWS S3 + SQS credentials  ← what you need to read actual data
Section: *FDR AWS S3 credentials and SQS queue*. Only present if FDR is
provisioned for your CID (it is a paid add-on — CrowdStrike enables it).

Yields an **AWS access key ID**, **AWS secret access key**, an **SQS queue URL**
(e.g. `https://sqs.<region>.amazonaws.com/<acct>/fdr-queue-<name>`) and the
S3 bucket/prefix. Confusingly, the console sometimes labels these "Client ID" /
"Client Secret" too — they are AWS IAM keys, not OAuth2 credentials.

You consume the feed by long-polling SQS for notifications, then fetching the
gzipped NDJSON objects listed in each message from S3.

> Each FDR instance gets its own unique key pair; keys are not reusable across
> FDR deployments, and rotating them re-issues the pair.

**For answering "what fields exist?" you only need (a).**

---

## 1. Getting the authoritative list (recommended)

Create an API client with the **`Falcon Data Replicator: READ`** scope
(*Support and resources → API clients and keys*), then:

```bash
export FALCON_CLIENT_ID=...
export FALCON_CLIENT_SECRET=...
export FALCON_CLOUD=us-1        # us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2

python3 tools/dump_fdr_schema.py --outdir ./out
```

Outputs into `./out`:

| File | Contents |
|---|---|
| `events.json` | every event schema entity, raw |
| `fields.json` | every field schema entity, raw |
| `fields.csv` | flat catalogue of all distinct fields |
| `event_fields.csv` | **event → field mapping** (the useful one for a UI) |
| `FDR_FIELDS.md` | same mapping, human-readable |
| `combined_schema.json` | combined schema-members response |

### Underlying endpoints

| Operation | Method | Path |
|---|---|---|
| `fdrschema.combined.event.get` | GET | `/fdr/combined/schema-members/v1` |
| `fdrschema.queries.event.get` | GET | `/fdr/queries/schema-events/v1` |
| `fdrschema.entities.event.get` | GET | `/fdr/entities/schema-events/v1` |
| `fdrschema.queries.field.get` | GET | `/fdr/queries/schema-fields/v1` |
| `fdrschema.entities.field.get` | GET | `/fdr/entities/schema-fields/v1` |

Queries endpoints return IDs (paginate with `limit`/`offset`, FQL `filter`);
entities endpoints take `ids` and return the definitions.

Equivalent via the official SDK:

```python
from falconpy import FDR
fdr = FDR(client_id=..., client_secret=...)

event_ids = fdr.query_event_entities(limit=500)["body"]["resources"]
events    = fdr.get_event_entities(ids=event_ids[:100])["body"]["resources"]

field_ids = fdr.query_field_entities(limit=500)["body"]["resources"]
fields    = fdr.get_field_entities(ids=field_ids[:100])["body"]["resources"]

combined  = fdr.get_event_combined()["body"]["resources"]   # takes no parameters
```

SDK method → operation ID:
`get_event_combined` → `fdrschema_combined_event_get` ·
`query_event_entities` → `fdrschema_queries_event_get` ·
`get_event_entities` → `fdrschema_entities_event_get` ·
`query_field_entities` → `fdrschema_queries_field_get` ·
`get_field_entities` → `fdrschema_entities_field_get`

---

## 2. What the feed physically looks like

FDR writes to a CrowdStrike-managed S3 bucket; you're notified via SQS.
Each notification lists gzipped **newline-delimited JSON** files under a
`pathPrefix`. Two broad classes of file arrive:

### a. Primary sensor telemetry
One JSON object per line, one line per event. The event type is in
`event_simpleName`. This is where the bulk of the fields live.

### b. Ancillary / context tables
Periodic snapshot tables rather than a telemetry stream, delivered as separate
files alongside the telemetry. These *are* small enough to enumerate and are
stable — listed below. Exact object-key prefixes vary by tenant and FDR
version; read them from the `pathPrefix`/`files[]` in the SQS notification
rather than hardcoding.

---

## 3. The common envelope (present on essentially every telemetry event)

| Field | Meaning |
|---|---|
| `event_simpleName` | event type name — the discriminator |
| `name` | fully-qualified event name (e.g. `ProcessRollup2V19`) |
| `aid` | agent/sensor ID (unique per host install) |
| `cid` | customer ID (your tenant) |
| `aip` | external/apparent IP the sensor connected from |
| `id` | event UUID |
| `timestamp` | sensor-side event time (ms epoch) |
| `ContextTimeStamp` | context event time (ms epoch) |
| `_time` | ingest/normalized time |
| `event_platform` | `Win` / `Mac` / `Lin` / `Android` |
| `ConfigBuild`, `ConfigStateHash` | sensor config version |
| `Entitlements` | licensing bitmask |
| `ContextProcessId`, `ContextThreadId` | originating process/thread |
| `TreeId` | process-tree correlation ID |
| `fdr_event_type` | FDR-level event class |

Deprecated `*_decimal` twins (`TreeId_decimal`, `ContextTimeStamp_decimal`,
`ContextProcessId_decimal`, …) still appear in older data — treat as legacy.

---

## 4. Ancillary tables (stable, fully enumerable)

**`aidmaster`** — host inventory, one row per sensor
`Time, AgentLoadFlags, AgentLocalTime, AgentTimeOffset, AgentVersion, aid, cid,
aip, BiosManufacturer, BiosVersion, ChassisType, City, Country, Continent,
ComputerName, ConfigIDBuild, event_platform, FirstSeen, MachineDomain, OU,
PointerSize, ProductType, ServicePackMajor, SiteName, SystemManufacturer,
SystemProductName, Timezone, Version, HostHiddenStatus`

**`appinfo`** — observed applications
`_time, cid, CompanyName, detectioncount, FileName, SHA256HashData,
FileDescription, FileVersion, ProductName, ProductVersion`

**`userinfo`** — user accounts
`_time, cid, AccountType, DomainUser, UserName, UserSid_readable,
LastLoggedOnHost, LocalAdminAccess, LoggedOnHostCount`

**`managedassets`** — network config of managed hosts
`_time, aid, cid, GatewayIP, GatewayMAC, MacPrefix, MAC, LocalAddressIP4,
InterfaceAlias, InterfaceDescription`

**`notmanaged`** — discovered unmanaged assets
`_time, aip, aipcount, localipCount, cid, CurrentLocalIP, Subnet, MAC,
MacPrefix, DiscovererCount, discoverer_aid, discoverer_devicetype,
FirstDiscoveredDate, LastDiscoveredBy, LocalAddressIP4, ComputerName,
NeighborName`

---

## 5. Per-event field lists

See **`data/public/event_fields_observed.csv`** — 275 event types with their observed
field sets, generated by `tools/harvest_public_schema.py` (§6) from real FDR
documents. Query it directly:

```bash
# fields on a given event
awk -F, '$1=="ProcessRollup2"{print $2}' data/public/event_fields_observed.csv

# which events carry a given field
awk -F, '$2=="CommandLine"{print $1}' data/public/event_fields_observed.csv

# event types, ranked by field count
tail -n +2 data/public/event_fields_observed.csv | cut -d, -f1 | uniq -c | sort -rn
```

> An earlier revision of this document hand-listed fields for a dozen events,
> sourced from Panther's open-source Go parsers. That repository is now deleted
> (404) and the lists were both stale and materially incomplete — it showed ~20
> fields for `ProcessRollup2` where the fixtures show 58. It has been removed in
> favour of the reproducible CSV.

---

## 6. What you can get with NO credentials at all

`tools/harvest_public_schema.py` assembles a catalogue from two open-source inputs,
no CrowdStrike account of any kind:

```bash
pip install pyyaml
python3 tools/harvest_public_schema.py
```

**Sources**

1. `elastic/integrations` → `packages/crowdstrike/data_stream/fdr/fields/fields.yml`
   — a curated list of FDR field names with Elasticsearch types.
2. The same package's pipeline **test fixtures** (`_dev/test/pipeline/*.log`) —
   these are *real FDR event documents*. Unioning their JSON keys per
   `event_simpleName` yields an observed event→field mapping.

**What that yields** (checked in under `data/public/`):

| | Count |
|---|---|
| Event types (`event_simpleName`) | **275** |
| Distinct field names (union of both sources) | **1,525** |
| Fields with a declared type | 1,255 |
| Ancillary tables | 7 |

The two sources are complementary, which is why the script unions them:
1,050 fields appear in both, 205 only in the curated list, 137 only in the
fixtures (mostly nested paths like `AnodeIndicators.*`).

**Outputs**

| File | Contents |
|---|---|
| `event_fields_observed.csv` | event → field mapping (275 types) |
| `event_types.txt` | just the event names |
| `fields_catalogue.csv` | 1,255 fields with types |
| `ancillary_tables.csv` | the non-telemetry snapshot tables |
| `all_field_names.txt` | flat union, 1,525 names |
| `fdr_public_schema.json` | everything, structured |

Event types confirmed present include the full `*FileWritten` family (Pe, MachO,
ELF, Zip, Pdf, Ooxml, Jar, Dmg, …), `Reg*`, `Firewall*`, `ScheduledTask*`,
`DcUsb*`, `OpenDirectory*`, `Smb*Etw`, injection events (`InjectedThread`,
`DllInjection`, `BrowserInjectedThread`), cloud asset events (`AwsEc2Instance`,
`AzureVirtualMachine`, `GcpComputeInstance`) and newer additions such as
`AgenticSessionStart` and `WSLDistributionStarted`.

---

## 7. Splunk CIM mapping (`tools/analyze_splunk_ta.py`)

If you ingest FDR via the **Splunk Add-on for CrowdStrike FDR** (Splunkbase
app 5579), the FDR→CIM mapping is already on disk in the TA's conf files.
`tools/analyze_splunk_ta.py` extracts it and joins it to the §6 catalogue.

```bash
python3 tools/analyze_splunk_ta.py \
    --ta ./splunk-add-on-for-crowdstrike-fdr_XXX.spl \
    --events data/public/event_fields_observed.csv \
    --outdir data/cim
```

`--ta` accepts the downloaded **`.spl`** (Splunkbase's native format), a
`.tgz`/`.tar.gz`, an extracted directory, or a live install
(`$SPLUNK_HOME/etc/apps/Splunk_TA_crowdstrike_fdr`).

A `.spl` is normally a gzipped tar; a minority are zip. **Both are handled** —
detection is by file content, not extension, so the extension never matters.

The TA is ~70 MB but **only the conf files are read** — the script extracts just
the `default/` and `local/` `.conf` members (a few hundred KB) and ignores
everything else. Verified to produce identical output from a `.spl` (tar),
a `.spl` (zip), a `.tgz`, and a plain directory.

### Measured results — Splunk_TA_CrowdStrike_FDR **3.2.0**

| | |
|---|---|
| FDR→CIM field mappings | **352** |
| CIM fields populated | **100** |
| Eventtypes → data models | **64** |
| Event types the TA normalizes | **67** |
| Of the 275 catalogued events: mapped | **56** |
| Of the 275 catalogued events: **NOT mapped** | **219** |

**How this TA actually maps to CIM** — worth knowing, because it is not what
you would guess:

- **`EVAL-` (100)** is the primary mechanism. The EVAL name *is* the CIM field,
  and the body is a `case(event_simpleName IN (...), ...)` naming exactly which
  events feed it. `cim_field_to_events.csv` inverts this.
- **`LOOKUP-` (226)** does enrichment (appinfo/host/userinfo resolution keyed on
  `SHA256HashData`, `aid`, `UserSid`) and bitmask decoding (`X` → `X_meaning`).
- **`FIELDALIAS-` — exactly one.** Do not expect to find the mapping by
  grepping for field aliases.

### CIM data model coverage

| Data model | Eventtypes |
|---|---|
| Endpoint.Filesystem | 16 |
| Endpoint.Processes | 13 |
| Endpoint.Ports | 8 |
| Endpoint.Services | 5 |
| Change.Endpoint_Changes | 3 |
| Alerts.Alerts | 3 |
| Malware.Malware_Attacks | 2 |
| Endpoint.Registry | 2 |
| Compute_Inventory.OS | 2 |
| Compute_Inventory.Network | 2 |
| Change.Account_Changes | 2 |
| Network_Resolution.DNS | 1 |
| Compute_Inventory.User | 1 |
| Compute_Inventory.CPU | 1 |
| Compute_Inventory.All_Inventory | 1 |
| Change.All_Changes | 1 |
| Authentication.Authentication | 1 |

**The most actionable finding: FDR network telemetry never reaches
`Network_Traffic`.** `NetworkConnectIP4`/`IP6` *are* normalized — but
`tags.conf` tags them `listening` + `port`, which puts them in
**`Endpoint.Ports`**, not `network` + `communicate` → `Network_Traffic`.
So a CIM network search (`| tstats ... from datamodel=Network_Traffic`) will
not see FDR connection events at all. Verified directly in 3.2.0's
`tags.conf`. Also absent entirely: `Web` and `Intrusion_Detection`.

> **No field-level "unreachable fields" count is reported**, deliberately.
> `LOOKUP` rows name the lookup's *input key* (`aid`, `UserSid`,
> `SHA256HashData`), and `EVAL` source fields are scraped heuristically from
> expression bodies — so any such number measures the scraper, not CIM
> reachability. Event-level coverage is derived from explicit TA statements and
> is the trustworthy signal.

Gap accuracy spot-checked: `AsepFileChange`, `AccessoryConnected` and
`AwsEc2Instance` appear **zero** times across `props.conf`, `eventtypes.conf`
and `transforms.conf` — genuine gaps, not matching failures. Conversely
`AsepValueUpdate`, `DriverLoad`, `InjectedThread` and `ScreenshotTakenEtw` all
correctly resolve as mapped.

### Sourcetypes

`crowdstrike:events:sensor` (the bulk), `:events:external`, `:events:ztha`,
`:events:sensor:ithr`, plus the inventory feeds `:inventory:aidmaster`,
`:managedassets`, `:notmanaged`, `:appinfo`, `:userinfo` — matching §4.

### Outputs

| File | Contents |
|---|---|
| `fdr_to_cim_fields.csv` | raw FDR field → CIM field, per sourcetype, with the `EVAL`/`LOOKUP`/`FIELDALIAS` responsible |
| `cim_field_to_events.csv` | **CIM field → which FDR events populate it** |
| `eventtype_to_datamodel.csv` | eventtype → CIM data model, from `tags.conf` |
| `cim_coverage_gaps.csv` | per event: normalized or not, and into which models |

`cim_coverage_gaps.csv` is the useful one: CIM models only a subset of FDR, so
anything untagged is invisible to CIM-based searches and to Enterprise Security.
Those events are still in your index — you just have to reach them by raw
`event_simpleName`.

Coverage comes from **explicit TA statements** — event names in
`eventtypes.conf` searches and in `EVAL case()` bodies — not from guessing. The
script also carries a canary that warns if `ProcessRollup2`, `DnsRequest` and
`NetworkConnectIP4` *all* read as unmapped, which would mean the matching broke
rather than a real gap. It does **not** fire on 3.2.0.

### Conf semantics handled

- backslash line-continuations (used heavily in the big `EVAL case()` bodies)
- `local/` overriding `default/` (Splunk layering)
- quoted field names, and `AS`/`as`/`ASNEW` aliasing
- `LOOKUP-` parsed into table + input fields + `OUTPUT`/`OUTPUTNEW` fields
- `EVAL-` parsed into CIM field + the `event_simpleName` list driving it
- `tags.conf` tag-sets → data models, matched **most-specific-first** (so
  `{change, endpoint}` resolves to `Change.Endpoint_Changes`, not
  `Change.All_Changes`); an unrecognized combination is reported verbatim as
  `(tagged, unmapped combo: ...)` rather than silently dropped

### Slimming the TA by hand

Not required — the script reads the big archive directly — but if you want a
small file to move between machines:

```bash
# see which confs are in there
tar tzf splunk-add-on-for-crowdstrike-fdr_*.tgz \
  | grep -E '/(default|local)/[^/]+\.conf$'

# extract just those, then repack (~100s of KB)
mkdir -p slim && tar tzf splunk-add-on-for-crowdstrike-fdr_*.tgz \
  | grep -E '/(default|local)/[^/]+\.conf$' \
  | xargs tar xzf splunk-add-on-for-crowdstrike-fdr_*.tgz -C slim
tar czf ta_confs.tgz -C slim .
```

The slim tarball produces byte-identical analysis output.

> The `TAG_MODELS` table in the script maps Splunk CIM tag-sets to data model
> names. It covers the common models; if your TA tags something it doesn't
> recognize, the combo is surfaced in the output so you can extend the table.

---

## Caveats

**On the keyless catalogue (§6)** — this is a good approximation, not the
authority:

- Per-event field sets are **what the fixtures happen to contain**. That is a
  **floor, not a ceiling** — optional and platform-specific fields that no
  fixture exercises are missing. An event showing 25 fields here may carry 60
  in practice.
- Elastic curates toward what its integration maps. Event types and fields it
  does not handle are absent.
- 275 event types is a solid fraction of the real surface but **not all of it**.
- No official field *descriptions* — the curated list carries types but
  descriptions for only a handful.

**On object prefixes** — `ancillary_tables.csv` labels one table
`fdrv2/notmanaged`. That prefix is *inferred from an Elastic fixture filename*
(`test-fdrv2-notmanaged.log`), not observed in a production bucket. Per §2,
read real prefixes from the SQS notification rather than trusting this label.

**Only §1 (the schema API) is complete, current, and tenant-accurate.** It is
also the only source with authoritative field descriptions and the only one
that reflects what *your* CID actually receives.
