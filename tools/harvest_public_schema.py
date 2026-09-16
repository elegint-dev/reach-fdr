#!/usr/bin/env python3
"""
Assemble an FDR field/event catalogue from PUBLIC sources only -- no
CrowdStrike credentials of any kind.

Sources (both open-source, no auth):
  1. elastic/integrations -> packages/crowdstrike/data_stream/fdr/fields/fields.yml
     A curated list of FDR field names + Elasticsearch types.
  2. the same package's pipeline test fixtures (_dev/test/pipeline/*.log),
     which are REAL FDR event documents. Unioning their keys per
     `event_simpleName` yields an observed event -> field mapping.

This is a good approximation, not the authority. See dump_fdr_schema.py for the
tenant-accurate version. Coverage caveats are printed at the end and written
into the generated README.

Usage:  python3 harvest_public_schema.py --outdir data/public
Requires: pyyaml  (pip install pyyaml)
"""

import argparse
import collections
import csv
import json
import os
import sys
import urllib.request

RAW = ("https://raw.githubusercontent.com/elastic/integrations/main/"
       "packages/crowdstrike/data_stream/fdr")
API = ("https://api.github.com/repos/elastic/integrations/contents/"
       "packages/crowdstrike/data_stream/fdr/_dev/test/pipeline")

# Ancillary snapshot tables ship as their own files, not as event_simpleName
# telemetry. Map the fixture filename to the table it represents.
ANCILLARY = {
    "test-fdr.log": "aidmaster (host inventory)",
    # NB: the "fdrv2/" prefix here is inferred from the fixture FILENAME,
    # not observed in a production bucket. Read real prefixes from SQS.
    "test-fdrv2-notmanaged.log": "fdrv2/notmanaged (unmanaged asset discovery)",
    "test-user-map.log": "userinfo / user map",
    "test-data.log": "ZTA assessment scores",
    "test-fdr-lengthy-field-delete.log": "ZTA assessment scores",
    "test-fdr-lengthy-field-index.log": "ZTA assessment scores",
    "test-fdr-cspm-iom.log": "CSPM IOM (cloud misconfiguration)",
    "test-fdr-cspm-ioa.log": "CSPM IOA (cloud attack indicator)",
    "test-tags-formats.log": "tags-only fixture",
}


def fetch(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": "fdr-schema-harvester"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def flatten(obj, prefix=""):
    """Collect dotted key paths from a JSON document."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}{k}"
            out.add(full)
            if isinstance(v, (dict, list)):
                out |= flatten(v, full + ".")
    elif isinstance(obj, list):
        for item in obj[:3]:          # sample; lists are homogeneous here
            if isinstance(item, (dict, list)):
                out |= flatten(item, prefix)
    return out


def harvest_fields():
    """Source 1: curated field list with types."""
    try:
        import yaml
    except ImportError:
        sys.exit("[!] pip install pyyaml")
    tree = yaml.safe_load(fetch(f"{RAW}/fields/fields.yml"))

    rows = []

    def walk(nodes, prefix=""):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            full = f"{prefix}{n.get('name','')}"
            if n.get("type") == "group" and "fields" in n:
                walk(n["fields"], f"{full}." if full else "")
            else:
                rows.append((full, n.get("type", ""),
                             (n.get("description") or "").strip().replace("\n", " ")))

    walk(tree)
    out = []
    for name, typ, desc in rows:
        if not name.startswith("crowdstrike."):
            continue
        name = name[len("crowdstrike."):]
        if name.startswith("__mv_"):     # Elastic multi-value helper, not FDR
            continue
        out.append({"field": name, "type": typ, "description": desc})
    return out


def harvest_events():
    """Source 2: real FDR documents from the package's test fixtures."""
    listing = json.loads(fetch(API))
    logs = [f["name"] for f in listing if f["name"].endswith(".log")]

    ev_fields = collections.defaultdict(set)
    ev_count = collections.Counter()
    anc_fields = collections.defaultdict(set)
    all_fields = set()

    for fname in logs:
        try:
            body = fetch(f"{RAW}/_dev/test/pipeline/{fname.replace(' ', '%20')}")
        except Exception as e:
            print(f"    [!] skip {fname}: {e}", file=sys.stderr)
            continue
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if not isinstance(doc, dict):
                continue
            keys = flatten(doc)
            all_fields |= keys
            name = doc.get("event_simpleName") or doc.get("ExternalApiType")
            if name:
                ev_fields[name] |= keys
                ev_count[name] += 1
            else:
                anc_fields[ANCILLARY.get(fname, fname)] |= keys
        print(f"    parsed {fname}", file=sys.stderr)

    return ev_fields, ev_count, anc_fields, all_fields, len(logs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="data/public")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    o = lambda n: os.path.join(args.outdir, n)

    print("[*] Fetching curated field list ...", file=sys.stderr)
    fields = harvest_fields()
    with open(o("fields_catalogue.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["field", "type", "description"])
        w.writeheader()
        for r in sorted(fields, key=lambda x: x["field"].lower()):
            w.writerow(r)
    print(f"[+] fields_catalogue.csv  ({len(fields)} fields)")

    print("[*] Fetching real FDR sample events ...", file=sys.stderr)
    ev_fields, ev_count, anc, all_fields, nlogs = harvest_events()

    with open(o("event_fields_observed.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["event_simpleName", "field", "sample_events_seen"])
        for name in sorted(ev_fields):
            for f in sorted(ev_fields[name]):
                w.writerow([name, f, ev_count[name]])
    print(f"[+] event_fields_observed.csv  ({len(ev_fields)} event types)")

    with open(o("event_types.txt"), "w") as fh:
        for name in sorted(ev_fields):
            fh.write(f"{name}\n")
    print(f"[+] event_types.txt  ({len(ev_fields)} names)")

    with open(o("ancillary_tables.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["table", "field"])
        for t in sorted(anc):
            for f in sorted(anc[t]):
                w.writerow([t, f])
    print(f"[+] ancillary_tables.csv  ({len(anc)} tables)")

    json.dump(
        {
            "event_fields": {k: sorted(v) for k, v in sorted(ev_fields.items())},
            "ancillary_tables": {k: sorted(v) for k, v in sorted(anc.items())},
            "field_catalogue": sorted(f["field"] for f in fields),
        },
        open(o("fdr_public_schema.json"), "w"),
        indent=1,
    )
    print(f"[+] fdr_public_schema.json")

    union = sorted({f["field"] for f in fields} | all_fields)
    with open(o("all_field_names.txt"), "w") as fh:
        fh.write("\n".join(union) + "\n")
    print(f"[+] all_field_names.txt  ({len(union)} distinct names, both sources)")

    print(
        f"\n[✓] From public sources only: {len(ev_fields)} event types, "
        f"{len(union)} distinct field names, {len(anc)} ancillary tables.\n"
        f"    Derived from {nlogs} fixture files.\n"
        "    CAVEAT: per-event field sets are what the FIXTURES contain, which is a\n"
        "    floor, not the full set. Optional/platform-specific fields are missing.\n"
        "    Run dump_fdr_schema.py for the authoritative, tenant-accurate schema."
    )


if __name__ == "__main__":
    main()
