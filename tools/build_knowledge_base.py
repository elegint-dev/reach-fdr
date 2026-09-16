#!/usr/bin/env python3
"""
Build the data bundle: one record per field, cross-referenced, plus events,
edges, translations and decode tables.

Inputs (all previously extracted, no network, no credentials):
  data/public/fields_catalogue.csv      1,255 fields + Elasticsearch types
  data/public/event_fields_observed.csv 275 events -> their fields (+ fixture counts)
  data/public/ancillary_tables.csv      ancillary table -> field (fixture-derived)
  data/cim/fdr_to_cim_fields.csv        352 raw->CIM/TA mappings w/ responsible stmt
  data/cim/cim_field_to_events.csv      100 CIM fields -> populating events
  data/cim/decode_tables.json           169 enum decodes, 1,370 value mappings
  data/cim/cim_coverage_gaps.csv        per-event CIM reachability
  data/enrichment/batch_*.json          AI enrichment -- a build INPUT, never regenerated
  data/curated/edges.json               hand-authored join edges with basis_ref
  data/curated/translations.json        hand-authored PID translation knowledge

Emits (--out, default app/data/ -- docs/ARCHITECTURE.md section 2):
  manifest.json fields.json events.json edges.json translations.json decodes.json

The build FAILS (non-zero exit) on: a name collision across layers that is not
in KNOWN_COLLISIONS; an edge whose src/dst is not a field (or, when dotted, not
a known ancillary table); an edge basis outside {confirmed_ta, asserted}; an
empty basis_ref; a ProcessId -> TargetProcessId edge; translations
naming unknown events/fields; enrichment naming unknown fields or roles.

Stdlib only.
"""

import argparse
import collections
import csv
import datetime
import glob
import hashlib
import json
import os
import re
import sys

SCHEMA_VERSION = 1
TA_VERSION = "3.2.0"

SENSOR_ST = "crowdstrike:events:sensor"
EXTERNAL_ST = "crowdstrike:events:external"
ANCHOR_EVENTS = ("ProcessRollup2", "SyntheticProcessRollup2")
PROCESS_HANDLES = ("ContextProcessId", "TargetProcessId", "ParentProcessId")

# The role vocabulary (ARCHITECTURE section 2.2); enrichment roles are validated against it.
ROLES = {
    "process_id", "thread_id", "tree_id", "agent_id", "customer_id", "event_id",
    "hash", "user_id", "timestamp", "file_path", "command", "domain", "ip",
    "port", "mac", "enum", "enum_label", "version", "count", "register",
    "size", "bool", "flag", "platform", "event_name", "identifier",
    "container", "other", "unclassified",
}
# Roles enrichment used that are outside the vocabulary, and what they map to.
ENRICHMENT_ROLE_MAP = {"network": "other"}

ROLE_BASIS_ORDER = ("decode_table", "meaning_sibling", "dotted_prefix",
                    "name_convention", "enrichment", "none")

EDGE_KINDS = {"process_lineage", "causal_attribution", "tree_grouping", "os_pid",
              "host_enrichment", "file_enrichment", "user_enrichment",
              "detection_handle"}
EDGE_BASES = {"confirmed_ta", "asserted"}
# `search_time_lookup`: a TA LOOKUP- stanza applied automatically at search time,
# so its outputs are already on the record for the sourcetypes it covers.
# `query`: a search the user runs.
EDGE_MECHANISMS = {"query", "search_time_lookup"}
EDGE_CARDINALITIES = {"n:1", "1:1", "n:n", "unsafe"}
EDGE_SCOPES = {"aid", "time"}

# Raw names that also appear as CIM EVAL outputs. The raw record wins the name,
# the CIM EVAL is recorded under `collision`; any other collision fails the build.
KNOWN_COLLISIONS = {"service", "severity", "status"}

# `fdr_field` tokens in cim/fdr_to_cim_fields.csv that are parser artifacts of
# the EVAL bodies (operators, string literals, registry hive names), not fields.
JUNK_SOURCE_TOKENS = {
    "AND", "NOT", "CONFIG", "DEFAULT", "CrowdStrike", "FDR", "HKEY_LOCAL_MACHINE",
    "IPv4", "IPv6", "MACHINE", "Periodic", "REGISTRY", "SAM", "SECURITY",
    "SOFTWARE", "SYSTEM", "Win",
}

# Ancillary tables the TA joins to (FDR_REFERENCE.md section 4).
ANCILLARY_TABLES_REFERENCE = {
    "aidmaster": "FDR_REFERENCE.md section 4 (aidmaster: host inventory)",
    "appinfo": "FDR_REFERENCE.md section 4 (appinfo: observed applications)",
    "userinfo": "FDR_REFERENCE.md section 4 (userinfo: user accounts)",
    "managedassets": "FDR_REFERENCE.md section 4 (managedassets)",
    "notmanaged": "FDR_REFERENCE.md section 4 (notmanaged)",
}

# FDR_REFERENCE.md section 3: the common envelope. Used as `meaning` with
# source "reference" for fields nothing else explains.
REFERENCE_MEANINGS = {
    "event_simpleName": "event type name -- the discriminator",
    "name": "fully-qualified event name (e.g. ProcessRollup2V19)",
    "aid": "agent/sensor ID (unique per host install)",
    "cid": "customer ID (your tenant)",
    "aip": "external/apparent IP the sensor connected from",
    "id": "event UUID",
    "timestamp": "sensor-side event time (ms epoch)",
    "ContextTimeStamp": "context event time (ms epoch)",
    "_time": "ingest/normalized time",
    "event_platform": "Win / Mac / Lin / Android",
    "ConfigBuild": "sensor config version",
    "ConfigStateHash": "sensor config version",
    "Entitlements": "licensing bitmask",
    "ContextProcessId": "originating process",
    "ContextThreadId": "originating thread",
    "TreeId": "process-tree correlation ID",
    "fdr_event_type": "FDR-level event class",
}

# ---------------------------------------------------------------------------
# Semantic role by name convention. Order matters: specific before generic, `identifier` last.
# ---------------------------------------------------------------------------
ROLE_RULES = [
    # --- raw FDR CamelCase conventions -----------------------------------
    # Role only; edges come solely from curated/edges.json.
    ("process_id",  r"ProcessId$|Pid$"),
    ("thread_id",   r"ThreadId$"),
    ("tree_id",     r"^TreeId$"),
    ("agent_id",    r"^aid$|^AgentIdString$|^AgentId$"),
    ("customer_id", r"^cid$"),
    ("event_id",    r"^id$|^ContextEventId$"),
    ("hash",        r"^(SHA256|SHA1|MD5|Authenticode)HashData$|Hash$"),
    ("user_id",     r"Sid$|^UserPrincipal$|^AuthenticationId$|^UID$|^GID$"),
    ("timestamp",   r"TimeStamp$|^timestamp$|^_time$|Time$|^ProcessStartTime$|^ProcessEndTime$"),
    ("file_path",   r"FileName$|FilePath$|^ImageFileName$|Path$|Directory$"),
    ("command",     r"^CommandLine$|^ScriptContent$"),
    ("domain",      r"^DomainName$|Domain$"),
    ("ip",          r"AddressIP4$|AddressIP6$|^aip$|IpAddress$|IP$"),
    ("port",        r"Port$"),
    ("mac",         r"^MAC$|MacPrefix$|MAC$"),
    ("enum",        r"Type$|Status$|Class$|Flags$|Reason$|Result$|Disposition$"
                    r"|State$|Level$|Mode$|Direction$|Method$|Code$|Severity$"),
    ("version",     r"Version$|^ConfigIDBuild$"),
    ("count",       r"Count$|^(In|Out)[A-Z]\w*(Octets|Pkts|Errors|Discards|Packets)$"),
    ("register",    r"^(MmioData|PciConfigData|SpibarData)\w*$"),
    ("size",        r"Size$|Length$"),
    ("bool",        r"^Is[A-Z]|^Has[A-Z]|^Dual"),
    ("platform",    r"^event_platform$|^ConfigBuild$|^ConfigStateHash$"),
    ("event_name",  r"^event_simpleName$|^name$|^fdr_event_type$|^ExternalApiType$"),
    # --- snake_case CIM / TA-derived conventions (ARCHITECTURE 2.2) --------
    # Anchored so they never match CamelCase raw names.
    ("process_id",  r"^(parent_)?process_id$"),
    ("agent_id",    r"_aid$"),
    ("user_id",     r"^user_id$|_user_id$|^user$|_user$|^user_name$|_user_name$"),
    ("hash",        r"_hash$"),
    ("timestamp",   r"_time$"),
    ("count",       r"_count$|^cpu_(cores|count)$"),
    ("size",        r"_size$"),
    ("port",        r"_port$"),
    ("mac",         r"^mac$|_mac$"),
    ("ip",          r"^ip$|_ip$|_ip4$|_ip6$"),
    ("domain",      r"_domain$|^query$"),
    ("file_path",   r"^(?!registry_).*_path$|^(file|original_file|appinfo_file)_name$|_exec$"),
    ("command",     r"^command$|^process$"),
    ("version",     r"^version$|_version$"),
    ("enum",        r"_type$|_category$|_level$|^state$|_state$|_method$|_hive$"
                    r"|^transport$|^aid_(country|continent)$"),
    ("other",       r"^aid_(city|ou)$"),
    # Generic identifier LAST so the specific *_id roles above win.
    ("identifier",  r"Id$|Guid$|Uuid$|UUID$|^Entitlements$|_benchmark_ids$"
                    r"|^(dest|src|dvc|dest_host)$|^(?!registry_).*_name$|_guid$|_id$"),
]

# Same-role buckets: raw fields whose `_id` role came from name convention. Informational.
SAME_ROLE_BASES = {"name_convention"}

CONVERSIONS = {
    "timestamp": dict(
        op="epoch_ms_to_time",
        note="FDR timestamps are milliseconds since epoch. Note that "
             "`timestamp`, `ContextTimeStamp` and `_time` differ in meaning: "
             "sensor event time, context event time, and Splunk index time. "
             "Mixing them is a classic hunting error.",
        spl="eval t=strftime(FIELD/1000, \"%F %T.%3N\")"),
    "legacy_decimal": dict(
        op="decimal_twin",
        note="Deprecated `*_decimal` twin of a base field, present in older "
             "data. Prefer the base field.",
        spl="coalesce(FIELD, FIELD_decimal)"),
}

ROUTE_EXPLAIN = {
    "direct_anchor": "This field appears on a process-creation event, so the "
                     "process context is already present on the same record. "
                     "No pivot needed.",
    "one_hop": "This field appears on events carrying a process handle (usually "
               "ContextProcessId). One pivot to ProcessRollup2 recovers the "
               "full process context.",
    "host_only": "The events carrying this field have NO process handle. You "
                 "can attribute this to a HOST (aid) and a time, but not to a "
                 "specific process. Do not fabricate a process link.",
    "external_only": "This field rides only on detection summary events "
                     "(crowdstrike:events:external). Their ProcessId / "
                     "ParentProcessId are renames whose PID space is not "
                     "established, so no process join is offered from "
                     "here. The detection workflow leads with the hash and host "
                     "pivots instead.",
    "unobserved": "Never observed on any event in the public corpus, so no route "
                  "can be computed; run queries/discovery/01 against your tenant "
                  "to find which events carry it.",
}
ROUTE_RANK = {"direct_anchor": 3, "one_hop": 2, "host_only": 1}


class BuildError(Exception):
    pass


def load_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as fh:
        return json.load(fh)


def dump_json(obj, path, sort_keys=True):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=sort_keys)
        fh.write("\n")


def classify(name, has_decode=False, container_children=0):
    """Semantic role, strongest evidence first: decode table, `_meaning`
    suffix, container parent, name convention. Enrichment is folded in by the
    caller after these. Returns (role, basis)."""
    if has_decode:
        return "enum", "decode_table"
    if name.endswith("_meaning"):
        # Produced by a TA lookup that decodes <base> into <base>_meaning.
        return "enum_label", "meaning_sibling"
    if container_children >= 2:
        return "container", "dotted_prefix"
    if name.endswith("_decimal"):
        # A `*_decimal` twin carries the role of its base field.
        base_role, base_basis = classify(name[:-8], has_decode=has_decode,
                                         container_children=0)
        if base_role != "unclassified":
            return base_role, "name_convention"
    leaf = name.rsplit(".", 1)[-1]
    for role, pat in ROLE_RULES:
        if re.search(pat, name) or re.search(pat, leaf):
            return role, "name_convention"
    return "unclassified", "none"


def scope_label(scope):
    if not scope:
        return "global"
    if scope == ["aid"]:
        return "same aid"
    if scope == ["aid", "time"]:
        return "same aid + time window"
    return " + ".join(scope)


def route_for(event, ev_fields, event_sourcetype=None):
    """Route per (field, event) (ARCHITECTURE 2.2). On the external sourcetype
    the `*ProcessId` names are not process handles: their PID space is not
    established."""
    fields = ev_fields.get(event, set())
    external = bool(event_sourcetype) and event_sourcetype.get(event) == EXTERNAL_ST
    handles = [] if external else [h for h in PROCESS_HANDLES if h in fields]
    is_anchor = event in ANCHOR_EVENTS
    if is_anchor:
        route = "direct_anchor"
    elif handles:
        route = "one_hop"
    else:
        route = "host_only"
    return route, handles, is_anchor, external


# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data", help="dir holding public/, cim/, enrichment/, curated/")
    ap.add_argument("--out", default="app/data", help="where to emit the bundle")
    ap.add_argument("--readme", default=None,
                    help="regenerate the <!-- reach:stats --> block in this file")
    args = ap.parse_args(argv)
    try:
        return build(args)
    except BuildError as e:
        print(f"\nBUILD FAILED\n{e}", file=sys.stderr)
        return 1


def build(args):
    b = lambda *p: os.path.join(args.data, *p)
    errors = []
    warnings = []

    catalogue = load_csv(b("public", "fields_catalogue.csv"))
    ev_rows = load_csv(b("public", "event_fields_observed.csv"))
    ancillary_rows = load_csv(b("public", "ancillary_tables.csv"))
    cim_rows = load_csv(b("cim", "fdr_to_cim_fields.csv"))
    cim_ev = load_csv(b("cim", "cim_field_to_events.csv"))
    gaps = load_csv(b("cim", "cim_coverage_gaps.csv"))
    decodes = load_json(b("cim", "decode_tables.json"), {})
    curated_edges = load_json(b("curated", "edges.json"))
    translations = load_json(b("curated", "translations.json"))
    if curated_edges is None:
        errors.append("curated/edges.json is missing")
    if translations is None:
        errors.append("curated/translations.json is missing")

    enrichment, batch_count = load_enrichment(b("enrichment"), errors)

    # ---- indexes ----------------------------------------------------------
    types = {r["field"]: r.get("type", "") for r in catalogue}
    ev_fields = collections.defaultdict(set)
    field_events = collections.defaultdict(set)
    samples = collections.defaultdict(dict)          # field -> {event: n}
    for r in ev_rows:
        ev, f = r["event_simpleName"], r["field"]
        ev_fields[ev].add(f)
        field_events[f].add(ev)
        try:
            samples[f][ev] = int(r.get("sample_events_seen") or 0)
        except ValueError:
            samples[f][ev] = 0
    known_events = set(ev_fields)
    event_sourcetype = {ev: (EXTERNAL_ST if "ExternalApiType" in fs else SENSOR_ST)
                        for ev, fs in ev_fields.items()}

    raw_names = set(types) | set(field_events) | set(decodes)

    # TA/CIM mapping rows, with the `fdr_field` list cleaned of parser junk.
    cim_for_raw = collections.defaultdict(list)     # raw -> [target rows]
    rows_for_out = collections.defaultdict(list)    # TA/CIM output -> [rows]
    unmodelled_sources = collections.Counter()
    for r in cim_rows:
        out = r["cim_field"]
        toks = [t.strip() for t in (r.get("fdr_field") or "").split(",") if t.strip()]
        if not toks:
            # Constant-valued EVAL (e.g. action="created"): no raw source, not a field record.
            continue
        srcs = [t for t in toks if t not in JUNK_SOURCE_TOKENS]
        for t in srcs:
            if t not in raw_names:
                unmodelled_sources[t] += 1
        row = {
            "via": r["kind"], "sourcetype": r["sourcetype"],
            "events": [e for e in (r.get("events") or "").split(";") if e],
            "statement": r.get("detail") or "",
        }
        rows_for_out[out].append(dict(row, raw_fields=srcs))
        for t in srcs:
            if t in raw_names:
                cim_for_raw[t].append(dict(row, cim_field=out))

    cim_field_events = {r["cim_field"]: [e for e in r["event_simpleNames"].split(";") if e]
                        for r in cim_ev}
    event_cim_status = {r["event_simpleName"]: r for r in gaps}
    cim_names = set(cim_field_events)           # the CIM field vocabulary on disk

    # ---- collisions across layers ----------------------------------------
    collisions = raw_names & set(rows_for_out)
    for c in sorted(collisions - KNOWN_COLLISIONS):
        errors.append(f"name collision across layers: {c!r} is a raw FDR field "
                      f"AND a TA/CIM output; add it to KNOWN_COLLISIONS only "
                      f"after deciding which layer owns the name")
    for c in sorted(collisions & KNOWN_COLLISIONS):
        warnings.append(f"known collision {c!r}: raw record wins the name; the "
                        f"CIM EVAL is recorded under `collision`")

    # A field that is the dotted prefix of >=2 other fields is a nested
    # container, not a leaf value.
    container_children = collections.Counter()
    for f in raw_names | set(rows_for_out):
        if "." in f:
            container_children[f.rsplit(".", 1)[0]] += 1

    # ---- layers -----------------------------------------------------------
    def layer_of(out):
        kinds = {r["via"] for r in rows_for_out[out]}
        if "EVAL" in kinds:
            return "cim"                  # CIM membership wins
        if kinds == {"FIELDALIAS"}:
            return "cim" if out in cim_names else "ta_derived"
        return "ta_derived"               # LOOKUP outputs

    # ---- build records ----------------------------------------------------
    recs = {}
    for f in sorted(raw_names):
        role, basis = classify(f, has_decode=f in decodes,
                               container_children=container_children.get(f, 0))
        evs = sorted(field_events.get(f, ()))
        rec = new_record(f, "raw_fdr")
        rec.update({
            "legacy": f.endswith("_decimal"),
            "type": types.get(f, ""),
            "in_catalogue": f in types,
            "observed": f in field_events,
            "role": role, "role_basis": basis,
            "events": evs, "event_count": len(evs),
            "cim_targets": sorted(cim_for_raw.get(f, []),
                                  key=lambda x: (x["cim_field"], x["sourcetype"], x["via"])),
            "audit": {"sample_events_seen": dict(sorted(samples.get(f, {}).items()))},
        })
        if f in KNOWN_COLLISIONS and f in rows_for_out:
            rec["collision"] = {
                "with_layer": layer_of(f),
                "note": "The TA also emits a CIM field of this name; that EVAL "
                        "reads other raw fields and is NOT this field.",
                "sources": [{"raw_field": t, "via": r["via"], "sourcetype": r["sourcetype"],
                             "events": r["events"], "statement": r["statement"]}
                            for r in rows_for_out[f] for t in (r["raw_fields"] or [None])],
            }
        recs[f] = rec

    for out in sorted(rows_for_out):
        if out in recs:
            continue                      # collision: raw owns the name
        layer = layer_of(out)
        role, basis = classify(out, container_children=container_children.get(out, 0))
        rows = rows_for_out[out]
        sources = []
        for r in rows:
            for t in (r["raw_fields"] or []):
                sources.append({"raw_field": t, "via": r["via"], "sourcetype": r["sourcetype"],
                                "events": r["events"], "statement": r["statement"]})
        sources.sort(key=lambda x: (x["raw_field"], x["sourcetype"], x["via"]))
        # Events: those the EVAL names; for a LOOKUP, every event carrying its input.
        explicit = set(cim_field_events.get(out, ()))
        for r in rows:
            explicit |= set(r["events"])
        if explicit:
            evs = sorted(explicit & known_events)
        else:
            evs = set()
            for s in sources:
                for ev in field_events.get(s["raw_field"], ()):
                    if event_sourcetype.get(ev) == s["sourcetype"]:
                        evs.add(ev)
            evs = sorted(evs)
        rec = new_record(out, layer)
        rec.update({
            "role": role, "role_basis": basis,
            "events": evs, "event_count": len(evs),
            "sources": sources,
        })
        recs[out] = rec

    # ---- decode tables, conversions ---------------------------------------
    for f, d in decodes.items():
        rec = recs[f]
        rec["decode"] = {"lookup": d["lookup"], "meaning_field": d["meaning_field"],
                         "values": dict(d["values"])}
        rec["conversions"].append({
            "op": "enum_decode",
            "note": f"{len(d['values'])} known values; TA ships {d['lookup']} "
                    f"to decode into {d['meaning_field']}.",
            "spl": f"lookup {d['lookup'].replace('.csv', '')} {f} OUTPUT {d['meaning_field']}",
        })
    for f, rec in recs.items():
        if rec["role"] == "timestamp" and rec["layer"] == "raw_fdr":
            c = dict(CONVERSIONS["timestamp"])
            c["spl"] = c["spl"].replace("FIELD", f)
            rec["conversions"].append(c)
        if rec["legacy"]:
            c = dict(CONVERSIONS["legacy_decimal"])
            c["spl"] = c["spl"].replace("FIELD", f[:-8])
            rec["conversions"].append(c)

    # ---- fold enrichment (role precedence: ... > name_convention > enrichment)
    for f, e in sorted(enrichment.items()):
        if f not in recs:
            errors.append(f"enrichment names unknown field {f!r}")
            continue
        rec = recs[f]
        e_role = ENRICHMENT_ROLE_MAP.get(e["semantic_role"], e["semantic_role"])
        if e_role not in ROLES:
            errors.append(f"enrichment role {e['semantic_role']!r} on {f!r} is outside "
                          f"the role vocabulary")
            continue
        rec["meaning"] = {
            "description": e["description"], "hunting_notes": e["hunting_notes"],
            "data_format": e["data_format"], "source": "enrichment",
            "confidence": e["confidence"], "evidence": e["evidence"],
        }
        rec["suggested_joins"] = [
            {"to": c["to"], "why": c["why"], "confidence": c["confidence"]}
            for c in e.get("join_candidates", [])]
        if rec["role"] == "unclassified":
            rec["role"], rec["role_basis"] = e_role, "enrichment"
        elif rec["role"] != e_role:
            rec["role_disagreement"] = {"enrichment": e_role}

    # ---- meaning for fields enrichment did not cover -----------------------
    # Curated field notes outrank the generic fallbacks below.
    curated_fields = ((translations or {}).get("pid_translation") or {}).get("fields") or {}
    for f, note in curated_fields.items():
        if f in recs and recs[f]["meaning"] is None:
            m = meaning_block(note.get("meaning", ""), "curated")
            m["hunting_notes"] = note.get("note")
            m["safe_to_join"] = bool(note.get("safe_to_join"))
            recs[f]["meaning"] = m
    for f, rec in recs.items():
        if rec["meaning"] is not None:
            continue
        if rec["decode"] is not None:
            d = rec["decode"]
            rec["meaning"] = meaning_block(
                f"Enumerated code; the TA ships {d['lookup']} decoding "
                f"{len(d['values'])} values into {d['meaning_field']}.", "decode_table")
        elif f.endswith("_meaning") and f[:-8] in recs:
            rec["meaning"] = meaning_block(
                f"TA lookup output: the decoded label for {f[:-8]}.", "ta")
        elif rec["layer"] in ("ta_derived", "cim") and rec["sources"]:
            srcs = sorted({s["raw_field"] for s in rec["sources"]})
            via = sorted({s["via"] for s in rec["sources"]})
            rec["meaning"] = meaning_block(
                f"Produced by the TA ({'/'.join(via)}) from {', '.join(srcs)}.", "ta")
        elif f in REFERENCE_MEANINGS:
            rec["meaning"] = meaning_block(REFERENCE_MEANINGS[f], "reference")

    # ---- edges (curated, validated) ---------------------------------------
    edges = validate_edges(curated_edges or [], recs, ancillary_rows, errors)
    # Search-time lookups: which sourcetypes the stanza fires on, and what it yields.
    lookup_rows = collections.defaultdict(lambda: collections.defaultdict(set))
    for r in cim_rows:
        if r.get("kind") != "LOOKUP":
            continue
        for key in filter(None, (r.get("fdr_field") or "").split(",")):
            lookup_rows[key.strip()][r["sourcetype"]].add(r["cim_field"])
    for e in edges:
        if e.get("mechanism") != "search_time_lookup":
            e["automatic_on"], e["yields"] = [], []
            continue
        per_st = collections.defaultdict(set)
        for key in e.get("lookup_keys") or [e["src"]]:
            for st, outs in lookup_rows.get(key, {}).items():
                per_st[st] |= {o for o in outs if o in recs}
        if not per_st:
            errors.append(f"{e['id']}: mechanism search_time_lookup but no LOOKUP row is keyed on "
                          f"{e.get('lookup_keys') or [e['src']]}")
        e["automatic_on"] = sorted(per_st)
        e["yields"] = sorted(set().union(*per_st.values())) if per_st else []
    for e in edges:
        for endpoint in (e["src"], e["dst"]):
            if endpoint in recs and e["id"] not in recs[endpoint]["edges"]:
                recs[endpoint]["edges"].append(e["id"])

    # A suggestion promoted to a curated edge is recorded on the edge, not repeated.
    for e in edges:
        promoted = []
        for s in list(recs.get(e["src"], {}).get("suggested_joins", [])):
            if s["to"] == e["dst"]:
                recs[e["src"]]["suggested_joins"].remove(s)
                promoted.append(s)
        if promoted:
            e["enrichment_concurs"] = {
                "confidence": promoted[0]["confidence"], "why": promoted[0]["why"]}

    # ---- same-role buckets (informational) -------------------------
    by_role = collections.defaultdict(list)
    for f, r in recs.items():
        if (r["layer"] == "raw_fdr" and r["role"].endswith("_id")
                and r["role_basis"] in SAME_ROLE_BASES):
            by_role[r["role"]].append(f)
    same_role_buckets = {role: sorted(fs) for role, fs in by_role.items() if len(fs) > 1}
    for role, fs in same_role_buckets.items():
        for f in fs:
            recs[f]["same_role_fields"] = [x for x in fs if x != f]

    # ---- routes per (field, event) and summary ----------------------------
    for f, rec in recs.items():
        by_event = {}
        for ev in rec["events"]:
            route, handles, is_anchor, external = route_for(ev, ev_fields, event_sourcetype)
            by_event[ev] = {"route": route, "handles": handles, "is_anchor": is_anchor}
            if external:
                by_event[ev]["external"] = True
        if rec["layer"] in ("ta_derived", "cim"):
            summary = "derived"
            derived_from = sorted({s["raw_field"] for s in rec["sources"] if s["raw_field"] in recs})
            named = sorted({s["raw_field"] for s in rec["sources"]})
            if derived_from:
                explain = (f"This field is computed by the TA from "
                           f"{', '.join(derived_from)}, so see "
                           f"{derived_from[0]}'s route; a process route belongs to "
                           f"the raw source, not to the derived field.")
            elif named:
                explain = (f"This field is computed by the TA from "
                           f"{', '.join(named)} (TA intermediates or fields not in any "
                           f"catalogue), so no raw source's route can be shown.")
            else:
                explain = ("This field is a constant the TA sets by EVAL, so there is "
                           "no raw source and no process route.")
        elif not rec["events"]:
            summary, derived_from = "unobserved", []
            explain = ROUTE_EXPLAIN["unobserved"]
        else:
            derived_from = []
            kinds = collections.Counter(v["route"] for v in by_event.values())
            if len(kinds) == 1:
                summary = next(iter(kinds))
                explain = ROUTE_EXPLAIN[summary]
                if summary == "host_only" and all(v.get("external") for v in by_event.values()):
                    explain = ROUTE_EXPLAIN["external_only"]
            else:
                summary = "mixed"
                parts = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items(), key=lambda kv: -ROUTE_RANK[kv[0]]))
                explain = (f"The route depends on which event you are looking at "
                           f"({parts}); check by_event for the event in hand.")
        rec["route"] = {"summary": summary, "explain": explain,
                        "by_event": by_event, "derived_from": derived_from}

    # ---- events -----------------------------------------------------------
    events = {}
    for ev in sorted(ev_fields):
        st = event_cim_status.get(ev, {})
        fields = sorted(ev_fields[ev])
        fbr = collections.defaultdict(list)
        for f in fields:
            fbr[recs[f]["role"]].append(f)
        cim_fields = sorted(cf for cf, evs in cim_field_events.items()
                            if ev in evs and cf in recs)
        normalized = (st.get("normalized_by_ta") or "").lower() == "yes"
        events[ev] = {
            "name": ev,
            "field_count": len(fields),
            "fields": fields,
            "fields_by_role": {r: sorted(fs) for r, fs in fbr.items()},
            "handles": ([] if event_sourcetype[ev] == EXTERNAL_ST
                        else [h for h in PROCESS_HANDLES if h in ev_fields[ev]]),
            "is_anchor": ev in ANCHOR_EVENTS,
            "sourcetype": event_sourcetype[ev],
            # `*ProcessId` names present on an external event but not treated as handles.
            "pid_fields_unestablished": (sorted(f for f in ev_fields[ev] if f.endswith("ProcessId"))
                                         if event_sourcetype[ev] == EXTERNAL_ST else []),
            "cim": {
                "normalized": normalized,
                "data_models": [m for m in (st.get("cim_data_models") or "").split(" | ") if m] if normalized else [],
                "fields": cim_fields,
            },
            "pid_spaces": {"TargetProcessId": "TargetProcessId" in ev_fields[ev],
                           "RawProcessId": "RawProcessId" in ev_fields[ev]},
        }

    # ---- translations (validated, copied verbatim) -----------------------
    if translations is not None:
        validate_translations(translations, recs, events, errors)

    # ---- forbidden-edge guard ------------------------------------------------------
    for e in edges:
        if e["src"] == "ProcessId" and e["dst"] == "TargetProcessId":
            errors.append("edge ProcessId -> TargetProcessId is forbidden")

    if errors:
        raise BuildError("\n".join(f"  - {x}" for x in errors))

    # ---- write the bundle -------------------------------------------------
    manifest = write_app(args.out, recs, edges, events, translations, decodes, batch_count)
    if args.readme:
        update_readme(args.readme, manifest)

    # ---- summary ----------------------------------------------------------
    for w in warnings:
        print(f"[!] {w}")
    if unmodelled_sources:
        print(f"[!] TA statement inputs that are not field records (kept in `sources`, "
              f"excluded from `derived_from`): "
              f"{', '.join(sorted(unmodelled_sources))}")
    c = manifest["counts"]
    print(f"[+] {args.out}/  fields={c['fields']} events={c['events']} "
          f"edges={c['edges_confirmed'] + c['edges_asserted']} "
          f"decodes={c['decode_tables']} hash={manifest['content_hash'][:12]}")
    print(f"    layers: raw_fdr={c['raw_fdr']} ta_derived={c['ta_derived']} cim={c['cim']} "
          f"| unclassified={c['unclassified']} | routes={c['routes']}")
    return 0


# ---------------------------------------------------------------------------


def new_record(name, layer):
    return {
        "name": name, "layer": layer, "legacy": False, "type": "",
        "in_catalogue": False, "observed": False,
        "role": "unclassified", "role_basis": "none", "role_disagreement": None,
        "meaning": None, "events": [], "event_count": 0,
        "cim_targets": [], "sources": [], "decode": None, "conversions": [],
        "edges": [], "suggested_joins": [], "same_role_fields": [],
        "route": None, "audit": {"sample_events_seen": {}},
    }


def meaning_block(description, source):
    return {"description": description, "hunting_notes": None, "data_format": None,
            "source": source, "confidence": None, "evidence": None}


def load_enrichment(dirname, errors):
    out = {}
    paths = sorted(glob.glob(os.path.join(dirname, "batch_*.json")))
    for p in paths:
        for r in load_json(p, []):
            f = r.get("field")
            if not f:
                errors.append(f"{p}: enrichment record without a field name")
                continue
            if f in out:
                errors.append(f"{p}: duplicate enrichment record for {f!r}")
            out[f] = r
    return out, len(paths)


def validate_edges(curated, recs, ancillary_rows, errors):
    # table registry: public/ancillary_tables.csv labels + FDR_REFERENCE section 4
    tables = {}
    for r in ancillary_rows:
        label = r["table"]
        key = label.split(" ", 1)[0].split("/")[-1].lower()
        tables.setdefault(key, {"label": label, "source": "public/ancillary_tables.csv",
                                "columns": set()})
        tables[key]["columns"].add(r["field"])
    for key, src in ANCILLARY_TABLES_REFERENCE.items():
        tables.setdefault(key, {"label": key, "source": src, "columns": set()})
    edges = []
    seen_ids = set()
    for i, e in enumerate(curated):
        eid = e.get("id") or f"<edge #{i}>"
        if not e.get("id"):
            errors.append(f"{eid}: missing id")
        if eid in seen_ids:
            errors.append(f"{eid}: duplicate id")
        seen_ids.add(eid)
        for k in ("src", "kind", "basis", "basis_ref", "cardinality", "scope",
                  "src_sourcetype", "dst_sourcetype", "target_label", "note"):
            if k not in e:
                errors.append(f"{eid}: missing {k!r}")
        if e.get("basis") not in EDGE_BASES:
            errors.append(f"{eid}: basis {e.get('basis')!r} not in {sorted(EDGE_BASES)}")
        if not (e.get("basis_ref") or "").strip():
            errors.append(f"{eid}: empty basis_ref (asserted-with-no-citation is not an edge)")
        if e.get("kind") not in EDGE_KINDS:
            errors.append(f"{eid}: kind {e.get('kind')!r} not in {sorted(EDGE_KINDS)}")
        if e.get("cardinality") not in EDGE_CARDINALITIES:
            errors.append(f"{eid}: cardinality {e.get('cardinality')!r} invalid")
        if not isinstance(e.get("scope"), list) or not set(e.get("scope") or []) <= EDGE_SCOPES:
            errors.append(f"{eid}: scope must be a list drawn from {sorted(EDGE_SCOPES)}")
        if not (e.get("target_label") or "").strip():
            errors.append(f"{eid}: empty target_label")
        hz = e.get("hazard")
        if hz is not None and not (isinstance(hz, dict) and hz.get("level") and hz.get("text")):
            errors.append(f"{eid}: hazard must be null or {{level, text}}")
        if e.get("src") not in recs:
            errors.append(f"{eid}: src {e.get('src')!r} is not a field")
        if e.get("mechanism") not in EDGE_MECHANISMS:
            errors.append(f"{eid}: mechanism {e.get('mechanism')!r} not in {sorted(EDGE_MECHANISMS)}")
        out = dict(e)
        out["dst_table"] = None
        dst = e.get("dst")
        if dst is None:
            if e.get("kind") != "os_pid":
                errors.append(f"{eid}: dst is null (only allowed for kind os_pid)")
        elif "." in dst and dst not in recs:
            table, col = dst.split(".", 1)
            t = tables.get(table.lower())
            if t is None:
                errors.append(f"{eid}: dst {dst!r} names unknown ancillary table {table!r}")
            else:
                out["dst_table"] = {"table": table, "label": t["label"], "column": col,
                                    "resolved_from": t["source"],
                                    "column_listed": col in t["columns"]}
        elif dst not in recs:
            errors.append(f"{eid}: dst {dst!r} is not a field")
        edges.append(out)
    return edges


def validate_translations(tr, recs, events, errors):
    prov = tr.get("_provenance")
    if not isinstance(prov, dict) or not all(prov.get(k) for k in ("source", "date", "validated_by")):
        errors.append("translations: missing _provenance {source, date, validated_by}")
    pt = tr.get("pid_translation", {})
    for section in ("anchor_events", "needs_join", "raw_only"):
        for ev in pt.get(section, {}).get("events", []):
            if ev not in events:
                errors.append(f"translations: {section} names unknown event {ev!r}")
    primary = pt.get("anchor_events", {}).get("primary")
    if primary and primary not in events:
        errors.append(f"translations: anchor primary {primary!r} is not an event")
    for f in pt.get("fields", {}):
        if f not in recs:
            errors.append(f"translations: fields names unknown field {f!r}")
    for d in pt.get("directions", []):
        if re.search(r"\|\s*join\b", d.get("spl", "")):
            errors.append(f"translations: direction {d.get('id')!r} uses `join` "
                          f"(not Splunk-Cloud-safe; queries/README.md)")


# ---------------------------------------------------------------------------


def write_app(app_out, recs, edges, events, translations, decodes, batch_count):
    os.makedirs(app_out, exist_ok=True)
    p = lambda n: os.path.join(app_out, n)
    app_fields = {}
    for f, r in recs.items():
        rec = dict(r)
        if "collision" not in rec:
            rec.pop("collision", None)
        app_fields[f] = rec
    decodes_out = {f: {"lookup": d["lookup"], "meaning_field": d["meaning_field"],
                       "values": dict(d["values"])} for f, d in decodes.items()}
    dump_json(app_fields, p("fields.json"))
    dump_json(events, p("events.json"))
    dump_json(edges, p("edges.json"))
    dump_json(translations, p("translations.json"))
    dump_json(decodes_out, p("decodes.json"))

    counts = compute_counts(recs, edges, events, decodes, batch_count)
    h = hashlib.sha256()
    for n in sorted(("decodes.json", "edges.json", "events.json", "fields.json",
                     "translations.json")):
        with open(p(n), "rb") as fh:
            h.update(fh.read())
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "content_hash": h.hexdigest(),
        "ta_version": TA_VERSION,
        "counts": counts,
    }
    dump_json(manifest, p("manifest.json"))
    return manifest


def compute_counts(recs, edges, events, decodes, batch_count):
    vals = list(recs.values())
    layers = collections.Counter(r["layer"] for r in vals)
    return {
        "fields": len(recs),
        "raw_fdr": layers.get("raw_fdr", 0),
        "ta_derived": layers.get("ta_derived", 0),
        "cim": layers.get("cim", 0),
        "legacy": sum(1 for r in vals if r["legacy"]),
        "events": len(events),
        "events_cim_normalized": sum(1 for e in events.values() if e["cim"]["normalized"]),
        "events_cim_gap": sum(1 for e in events.values() if not e["cim"]["normalized"]),
        "enriched": sum(1 for r in vals if r["meaning"] and r["meaning"]["source"] == "enrichment"),
        "enrichment_batches": batch_count,
        "decode_tables": len(decodes),
        "decode_values": sum(len(d["values"]) for d in decodes.values()),
        "edges_confirmed": sum(1 for e in edges if e["basis"] == "confirmed_ta"),
        "edges_asserted": sum(1 for e in edges if e["basis"] == "asserted"),
        "suggested_joins": sum(len(r["suggested_joins"]) for r in vals),
        "roles": dict(sorted(collections.Counter(r["role"] for r in vals).items())),
        "role_basis": dict(sorted(collections.Counter(r["role_basis"] for r in vals).items())),
        "routes": {k: sum(1 for r in vals if r["route"]["summary"] == k)
                   for k in ("direct_anchor", "one_hop", "host_only", "mixed",
                             "unobserved", "derived")},
        "unclassified": sum(1 for r in vals if r["role"] == "unclassified"),
    }


def update_readme(path, manifest):
    if not os.path.exists(path):
        print(f"[-] {path} does not exist; stats block not written (not creating it)")
        return
    text = open(path).read()
    start, end = "<!-- reach:stats -->", "<!-- /reach:stats -->"
    if start not in text or end not in text:
        print(f"[-] {path} has no {start} ... {end} block; nothing replaced")
        return
    c = manifest["counts"]
    rows = [
        ("Fields", c["fields"]),
        ("raw FDR / TA-derived / CIM", f"{c['raw_fdr']} / {c['ta_derived']} / {c['cim']}"),
        ("Events", c["events"]),
        ("Events CIM-normalized / gap", f"{c['events_cim_normalized']} / {c['events_cim_gap']}"),
        ("Enriched fields (batches)", f"{c['enriched']} ({c['enrichment_batches']})"),
        ("Decode tables (values)", f"{c['decode_tables']} ({c['decode_values']})"),
        ("Edges confirmed / asserted", f"{c['edges_confirmed']} / {c['edges_asserted']}"),
        ("Suggested joins", c["suggested_joins"]),
        ("Unclassified", c["unclassified"]),
    ]
    block = [start, "| Stat | Value |", "|---|---|"]
    block += [f"| {k} | {v} |" for k, v in rows]
    block += [f"", f"Generated by build_knowledge_base.py at {manifest['built_at']} "
                   f"(TA {manifest['ta_version']}, bundle {manifest['content_hash'][:12]}).", end]
    pre, rest = text.split(start, 1)
    _, post = rest.split(end, 1)
    open(path, "w").write(pre + "\n".join(block) + post)
    print(f"[+] {path} stats block regenerated")


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    sys.exit(main())
