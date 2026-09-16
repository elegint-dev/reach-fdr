#!/usr/bin/env python3
"""
Extract the FDR -> Splunk CIM mapping from the Splunk Add-on for CrowdStrike FDR,
and cross-reference it against the FDR event/field catalogue.

Answers the questions the TA docs don't:
  * which raw FDR field becomes which CIM field, per sourcetype
  * which CIM data models each FDR eventtype feeds (via tags.conf)
  * which FDR event types the TA does NOT normalize  <- the CIM blind spots
  * which fields on mapped events are never aliased to CIM

Usage:
    # point at the .spl/.tgz you downloaded, or an already-extracted dir,
    # or your live install ($SPLUNK_HOME/etc/apps/Splunk_TA_crowdstrike_fdr)
    python3 analyze_splunk_ta.py --ta ./splunk-add-on-for-crowdstrike-fdr_20.tgz \
        --events data/public/event_fields_observed.csv --outdir data/cim

Stdlib only.
"""

import argparse
import collections
import csv
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile

CONFS = ("props.conf", "transforms.conf", "eventtypes.conf", "tags.conf",
         "fields.conf", "macros.conf")

# tags.conf tag combinations -> CIM data model. Splunk keys data models off
# tag sets, so a stanza's tags identify which model(s) it feeds.
TAG_MODELS = [
    # Tag-set -> CIM data model. Derived from the tag vocabulary actually used
    # by Splunk_TA_CrowdStrike_FDR. Matched MOST-SPECIFIC-FIRST, since e.g.
    # {change} is a subset of {change, endpoint}.
    ({"endpoint", "filesystem"},          "Endpoint.Filesystem"),
    ({"endpoint", "registry"},            "Endpoint.Registry"),
    ({"process", "report"},               "Endpoint.Processes"),
    ({"report", "service"},               "Endpoint.Services"),
    ({"listening", "port"},               "Endpoint.Ports"),
    ({"change", "endpoint"},              "Change.Endpoint_Changes"),
    ({"account", "change"},               "Change.Account_Changes"),
    ({"change", "audit"},                 "Change.Auditing_Changes"),
    ({"change"},                          "Change.All_Changes"),
    ({"attack", "data", "malware"},       "Malware.Malware_Attacks"),
    ({"attack", "malware"},               "Malware.Malware_Attacks"),
    ({"malware", "operations"},           "Malware.Malware_Operations"),
    ({"dns", "network", "resolution"},    "Network_Resolution.DNS"),
    ({"network", "communicate"},          "Network_Traffic.All_Traffic"),
    ({"inventory", "system", "version"},  "Compute_Inventory.OS"),
    ({"inventory", "network"},            "Compute_Inventory.Network"),
    ({"inventory", "user"},               "Compute_Inventory.User"),
    ({"cpu", "inventory"},                "Compute_Inventory.CPU"),
    ({"inventory", "memory"},             "Compute_Inventory.Memory"),
    ({"inventory", "storage"},            "Compute_Inventory.Storage"),
    ({"inventory"},                       "Compute_Inventory.All_Inventory"),
    ({"authentication"},                  "Authentication.Authentication"),
    ({"alert"},                           "Alerts.Alerts"),
    ({"ids", "attack"},                   "Intrusion_Detection.IDS_Attacks"),
    ({"web"},                             "Web.Web"),
    ({"certificate"},                     "Certificates.All_Certificates"),
    ({"vulnerability"},                   "Vulnerabilities.Vulnerabilities"),
    ({"email"},                           "Email.All_Email"),
    ({"session"},                         "Network_Sessions.All_Sessions"),
]


def parse_conf(text):
    """Parse a Splunk .conf into {stanza: {key: value}}, honouring continuations."""
    stanzas, cur = collections.OrderedDict(), None
    # Join backslash line-continuations first.
    text = re.sub(r"\\\s*\n\s*", " ", text)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            stanzas.setdefault(cur, collections.OrderedDict())
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1)
            stanzas[cur][k.strip()] = v.strip()
    return stanzas


def _is_conf_member(name):
    """True for default/<x>.conf or local/<x>.conf inside an archive."""
    parts = name.split("/")
    return (len(parts) >= 2 and parts[-2] in ("default", "local")
            and parts[-1] in CONFS)


def _is_lookup_member(name):
    """True for lookups/<x>.csv -- the TA's enum/bitmask decode tables."""
    parts = name.split("/")
    return (len(parts) >= 2 and parts[-2] == "lookups"
            and parts[-1].lower().endswith(".csv"))


def _wanted(name):
    return _is_conf_member(name) or _is_lookup_member(name)


def _unsafe(name):
    return name.startswith("/") or ".." in name.split("/")


def load_ta(path):
    """Return {conf_name: merged stanzas} from a dir, .spl, .tgz or .tar.gz.

    A .spl is normally a gzipped tar; a minority are zip archives. Both are
    handled -- detection is by content, not by file extension.
    """
    tmp = None
    if os.path.isfile(path):
        tmp = tempfile.mkdtemp(prefix="fdrta-")
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                # The TA is ~70MB, but the conf files are a few hundred KB.
                # Extract ONLY those.
                safe, total = [], 0
                for m in tf.getmembers():
                    if _unsafe(m.name) or not m.isfile():
                        continue
                    if _wanted(m.name):
                        safe.append(m)
                        total += m.size
                if not safe:
                    sys.exit(f"[!] {path} (tar) contains no default/ or local/ "
                             ".conf files. Is it really the Splunk TA?")
                print(f"[*] tar archive: extracting {len(safe)} conf files "
                      f"({total/1024:.0f} KB)", file=sys.stderr)
                try:
                    tf.extractall(tmp, members=safe, filter="data")
                except TypeError:            # Python < 3.12
                    tf.extractall(tmp, members=safe)
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                safe = [n for n in zf.namelist()
                        if not _unsafe(n) and _wanted(n)]
                if not safe:
                    sys.exit(f"[!] {path} (zip) contains no default/ or local/ "
                             ".conf files. Is it really the Splunk TA?")
                total = sum(zf.getinfo(n).file_size for n in safe)
                print(f"[*] zip archive: extracting {len(safe)} conf files "
                      f"({total/1024:.0f} KB)", file=sys.stderr)
                for n in safe:
                    zf.extract(n, tmp)
        else:
            sys.exit(f"[!] {path} is neither a tar nor a zip archive.\n"
                     "    A .spl should be one of the two. Check the download "
                     "completed, or unpack it yourself and pass the directory.")
        root = tmp
    elif os.path.isdir(path):
        root = path
    else:
        sys.exit(f"[!] no such path: {path}")

    found = collections.defaultdict(dict)
    hits = 0
    for dirpath, _, files in os.walk(root):
        # local/ overrides default/ in Splunk; walk default first, local second.
        for fn in files:
            if fn not in CONFS:
                continue
            layer = os.path.basename(dirpath)
            if layer not in ("default", "local"):
                continue
            full = os.path.join(dirpath, fn)
            with open(full, errors="replace") as fh:
                parsed = parse_conf(fh.read())
            hits += 1
            for stanza, kv in parsed.items():
                tgt = found[fn].setdefault(stanza, {})
                # local wins
                if layer == "local":
                    tgt.update(kv)
                else:
                    for k, v in kv.items():
                        tgt.setdefault(k, v)
    if not hits:
        sys.exit(f"[!] found no Splunk .conf files under {path}")
    print(f"[*] parsed {hits} conf files", file=sys.stderr)
    return found, root


ALIAS_RE = re.compile(r'("?[\w.{}\[\]:*-]+"?)\s+(?:AS|as|ASNEW|asnew)\s+("?[\w.{}\[\]:*-]+"?)')
# event_simpleName IN ("A","B")  /  event_simpleName="A"
EV_IN_RE = re.compile(r'event_simpleName\s+IN\s*\(([^)]*)\)', re.I)
# Splunk accepts both event_simpleName="X" and event_simpleName=X
EV_EQ_RE = re.compile(r'event_simpleName\s*=\s*(?:"([^"]+)"|([A-Za-z0-9_]+))', re.I)
OUTPUT_SPLIT_RE = re.compile(r'\s+OUTPUTNEW\s+|\s+OUTPUT\s+', re.I)


def events_in(expr):
    """Every event_simpleName literal referenced by a Splunk expression."""
    found = {q or bare for q, bare in EV_EQ_RE.findall(expr)}
    found.discard("")
    for grp in EV_IN_RE.findall(expr):
        found |= set(re.findall(r'"([^"]+)"', grp))
    return found


def parse_lookup(val):
    """`<table> <in...> OUTPUT|OUTPUTNEW <out...>` -> (table, inputs, outputs).

    Field specs may be `Name` or `Name AS alias`; for inputs the alias is the
    event field, for outputs the alias is the CIM field.
    """
    parts = OUTPUT_SPLIT_RE.split(val, maxsplit=1)
    left = parts[0].split()
    table = left[0] if left else ""
    def pairs(tokens):
        out, i = [], 0
        while i < len(tokens):
            if i + 2 < len(tokens) and tokens[i + 1].lower() in ("as", "asnew"):
                out.append((tokens[i], tokens[i + 2])); i += 3
            else:
                out.append((tokens[i], tokens[i])); i += 1
        return out
    inputs = pairs(left[1:])
    outputs = pairs(parts[1].split()) if len(parts) > 1 else []
    return table, inputs, outputs


def extract_mappings(props):
    """Rows of raw-FDR-field -> CIM-field, plus CIM-field -> source events."""
    rows, eval_events = [], collections.defaultdict(set)
    for stanza, kv in props.items():
        for key, val in kv.items():
            if key.startswith("FIELDALIAS-"):
                for src, dst in ALIAS_RE.findall(val):
                    rows.append({"sourcetype": stanza, "kind": "FIELDALIAS",
                                 "cim_field": dst.strip('"'),
                                 "fdr_field": src.strip('"'),
                                 "events": "", "detail": key})
            elif key.startswith("EVAL-"):
                cim = key[len("EVAL-"):].strip()
                evs = events_in(val)
                eval_events[cim] |= evs
                # Candidate source fields: CamelCase tokens that are not
                # event names, Splunk functions or string literals.
                lits = set(re.findall(r'"([^"]*)"', val))
                cands = sorted({
                    t for t in re.findall(r"\b([A-Z][A-Za-z0-9_]{2,})\b", val)
                    if t not in evs and t not in lits and t != "IN"
                })
                rows.append({"sourcetype": stanza, "kind": "EVAL",
                             "cim_field": cim,
                             "fdr_field": ",".join(cands[:10]),
                             "events": ";".join(sorted(evs)),
                             "detail": val[:250].replace("\n", " ")})
            elif key.startswith("LOOKUP-"):
                table, inputs, outputs = parse_lookup(val)
                for out_src, out_dst in outputs:
                    rows.append({
                        "sourcetype": stanza, "kind": "LOOKUP",
                        "cim_field": out_dst,
                        "fdr_field": ",".join(sorted({a for _, a in inputs})),
                        "events": "",
                        "detail": f"{key} via {table} ({out_src})",
                    })
    return rows, eval_events


def models_for_tags(tags):
    """Best match = the most specific tag-set that is a subset of `tags`."""
    if not tags:
        return set()
    matches = [(len(req), m) for req, m in TAG_MODELS if req <= tags]
    if not matches:
        return {"(tagged, unmapped combo: " + ",".join(sorted(tags)) + ")"}
    best = max(n for n, _ in matches)
    return {m for n, m in matches if n == best}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ta", required=True, help=".spl/.tgz, extracted dir, or live app dir")
    ap.add_argument("--events", help="event_fields_observed.csv from harvest_public_schema.py")
    ap.add_argument("--outdir", default="data/cim")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    o = lambda n: os.path.join(args.outdir, n)

    confs, root = load_ta(args.ta)
    props = confs.get("props.conf", {})
    eventtypes = confs.get("eventtypes.conf", {})
    tags = confs.get("tags.conf", {})

    print(f"[*] props stanzas={len(props)} eventtypes={len(eventtypes)} tags={len(tags)}",
          file=sys.stderr)

    # ---- 1. field mapping -------------------------------------------------
    rows, eval_events = extract_mappings(props)
    with open(o("fdr_to_cim_fields.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["sourcetype", "kind", "cim_field",
                                           "fdr_field", "events", "detail"])
        w.writeheader()
        for r in sorted(rows, key=lambda x: (x["sourcetype"], x["cim_field"])):
            w.writerow(r)
    print(f"[+] fdr_to_cim_fields.csv ({len(rows)} mappings)")

    with open(o("cim_field_to_events.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cim_field", "event_count", "event_simpleNames"])
        for cim in sorted(eval_events):
            evs = sorted(eval_events[cim])
            w.writerow([cim, len(evs), ";".join(evs)])
    print(f"[+] cim_field_to_events.csv ({len(eval_events)} CIM fields)")

    # ---- enum / bitmask decode tables ------------------------------------
    decodes, ntables = {}, 0
    for dirpath, _, files in os.walk(root):
        if os.path.basename(dirpath) != "lookups":
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".csv"):
                continue
            with open(os.path.join(dirpath, fn), errors="replace") as fh:
                rdr = csv.reader(fh)
                try:
                    header = next(rdr)
                except StopIteration:
                    continue
                header = [h.strip() for h in header]
                # Decode tables are 2-4 columns of <field>,<field>_meaning.
                # Anything wider (e.g. the host-resolution lookup) is not one.
                if not (2 <= len(header) <= 4):
                    continue
                vcol, mcol = 0, 1
                # One table ships its columns reversed: <X>_meaning,<X>
                if header[0].endswith("_meaning") and not header[1].endswith("_meaning"):
                    vcol, mcol = 1, 0
                elif not header[1].endswith("_meaning"):
                    continue          # not a decode table
                field = header[vcol]
                pairs = {r[vcol].strip(): r[mcol].strip()
                         for r in rdr
                         if len(r) > max(vcol, mcol) and r[vcol].strip() != ""}
            if pairs:
                decodes[field] = {"lookup": fn, "meaning_field": header[mcol],
                                  "reversed_columns": vcol == 1,
                                  "values": pairs}
                ntables += 1
    if decodes:
        json.dump(decodes, open(o("decode_tables.json"), "w"), indent=1, sort_keys=True)
        with open(o("decode_tables.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["field", "value", "meaning", "lookup_file"])
            for field in sorted(decodes):
                d = decodes[field]
                for v, meaning in sorted(d["values"].items(),
                                         key=lambda kv: (len(kv[0]), kv[0])):
                    w.writerow([field, v, meaning, d["lookup"]])
        total = sum(len(d["values"]) for d in decodes.values())
        print(f"[+] decode_tables.json/.csv ({ntables} tables, {total} value mappings)")

    # ---- 2. eventtype -> data model --------------------------------------
    et_tags = collections.defaultdict(set)
    for stanza, kv in tags.items():
        m = re.match(r"eventtype\s*=\s*(.+)", stanza)
        if not m:
            continue
        name = m.group(1).strip()
        for k, v in kv.items():
            if v.strip().lower() == "enabled":
                et_tags[name].add(k.strip())

    with open(o("eventtype_to_datamodel.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["eventtype", "cim_data_models", "tags", "search"])
        for et in sorted(set(eventtypes) | set(et_tags)):
            t = et_tags.get(et, set())
            w.writerow([et, " | ".join(sorted(models_for_tags(t))),
                        " ".join(sorted(t)),
                        eventtypes.get(et, {}).get("search", "")[:300]])
    print(f"[+] eventtype_to_datamodel.csv ({len(set(eventtypes)|set(et_tags))} eventtypes)")

    # ---- 3. coverage gaps -------------------------------------------------
    if not args.events:
        print("[i] pass --events to get the CIM coverage-gap report")
        return

    ev_fields = collections.defaultdict(set)
    with open(args.events) as fh:
        for r in csv.DictReader(fh):
            ev_fields[r["event_simpleName"]].add(r["field"])

    # Authoritative coverage: an event is CIM-normalized if the TA names it
    # literally in an eventtype search, or drives a CIM field from it in an
    # EVAL case(). Both are explicit statements by the TA -- no guessing.
    et_events = {}
    for et, kv in eventtypes.items():
        et_events[et] = events_in(kv.get("search", ""))
    from_eventtypes = set().union(*et_events.values()) if et_events else set()
    from_evals = set().union(*eval_events.values()) if eval_events else set()
    referenced = from_eventtypes | from_evals
    missing = sorted(set(ev_fields) - referenced)

    # Which data models each event reaches, via its eventtype's tags.
    ev_models = collections.defaultdict(set)
    for et, evs in et_events.items():
        models = models_for_tags(et_tags.get(et, set()))
        for e in evs:
            ev_models[e] |= models

    print(f"[*] events named in eventtypes={len(from_eventtypes)} "
          f"in EVALs={len(from_evals)} union={len(referenced)}", file=sys.stderr)

    with open(o("cim_coverage_gaps.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["event_simpleName", "normalized_by_ta", "cim_data_models",
                    "in_eventtype", "in_eval", "field_count"])
        for e in sorted(set(ev_fields) | referenced):
            w.writerow([e,
                        "yes" if e in referenced else "NO",
                        " | ".join(sorted(ev_models.get(e, set()))),
                        "yes" if e in from_eventtypes else "",
                        "yes" if e in from_evals else "",
                        len(ev_fields.get(e, set()))])
    print(f"[+] cim_coverage_gaps.csv")

    # Sanity canary: the TA definitely normalizes these. If they read as
    # unreferenced, the gap number is measuring our name-matching, not the TA.
    CANARIES = [e for e in ("ProcessRollup2", "DnsRequest", "NetworkConnectIP4")
                if e in ev_fields]
    missed = [e for e in CANARIES if e not in referenced]
    if missed and CANARIES:
        print(
            "\n[!] SUSPECT COVERAGE REPORT: these are events the TA is known to\n"
            f"    normalize, yet none matched: {', '.join(missed)}\n"
            "    The TA most likely keys on sourcetype/macros rather than naming\n"
            "    events literally, so 'NO' in cim_coverage_gaps.csv reflects this\n"
            "    script's name matching, NOT a real CIM gap. Treat the gap count as\n"
            "    unreliable and inspect eventtypes.conf/macros.conf by hand.",
            file=sys.stderr,
        )

    # NOTE: a field-level "never reaches CIM" metric was deliberately removed.
    # LOOKUP rows name the lookup's INPUT key (aid, UserSid, SHA256HashData),
    # and EVAL source fields are scraped heuristically from expression bodies,
    # so any such count measures the scraper, not CIM reachability. Event-level
    # coverage in cim_coverage_gaps.csv is derived from explicit TA statements
    # and is the trustworthy signal.

    print(f"\n[✓] CIM analysis")
    print(f"    FDR->CIM field mappings : {len(rows)}")
    print(f"    eventtypes / data models: {len(set(eventtypes)|set(et_tags))}")
    overlap = referenced & set(ev_fields)
    print(f"    event types the TA maps : {len(referenced)}")
    print(f"      of the {len(ev_fields)} catalogued: {len(overlap)} mapped, "
          f"{len(missing)} NOT mapped")
    extra = sorted(referenced - set(ev_fields))
    if extra:
        print(f"      TA maps {len(extra)} events absent from the catalogue: "
              f"{', '.join(extra[:6])}{'...' if len(extra) > 6 else ''}")
    if missing:
        print(f"\n    sample gaps: {', '.join(missing[:12])}")


if __name__ == "__main__":
    main()
