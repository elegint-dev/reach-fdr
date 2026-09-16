#!/usr/bin/env python3
"""
Dump the COMPLETE CrowdStrike FDR schema (every event type and every field)
from your own tenant via the FDR schema API.

This is the authoritative source. Public docs and third-party connectors only
ever mirror a subset, and they lag the live schema.

Required API scope on the client: "Falcon Data Replicator: READ"
(Falcon console -> Support and resources -> API clients and keys)

Usage:
    export FALCON_CLIENT_ID=...
    export FALCON_CLIENT_SECRET=...
    export FALCON_CLOUD=us-1          # us-1 | us-2 | eu-1 | us-gov-1
    python3 dump_fdr_schema.py --outdir ./out

Dependency-free (stdlib only).
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

# Entity endpoints take a bounded number of ids per call.
ID_BATCH = 100
PAGE_LIMIT = 500


class Falcon:
    def __init__(self, base, client_id, client_secret):
        self.base = base.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_exp = 0

    # -- auth ---------------------------------------------------------------
    def _authenticate(self):
        body = urllib.parse.urlencode(
            {"client_id": self.client_id, "client_secret": self.client_secret}
        ).encode()
        req = urllib.request.Request(
            f"{self.base}/oauth2/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            raise SystemExit(
                f"[!] Auth failed ({e.code}). Check credentials and cloud region.\n{detail}"
            )
        self.token = payload["access_token"]
        # Refresh a minute early rather than racing the expiry.
        self.token_exp = time.time() + int(payload.get("expires_in", 1800)) - 60

    def _ensure_token(self):
        if self.token is None or time.time() >= self.token_exp:
            self._authenticate()

    # -- request ------------------------------------------------------------
    def get(self, path, params=None, attempt=0):
        self._ensure_token()
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 6:
                wait = int(e.headers.get("X-RateLimit-RetryAfter", 0)) - int(time.time())
                wait = max(wait, 2 ** attempt)
                print(f"    rate limited, sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                return self.get(path, params, attempt + 1)
            if e.code == 401 and attempt < 2:
                self.token = None
                return self.get(path, params, attempt + 1)
            detail = e.read().decode(errors="replace")[:500]
            raise SystemExit(f"[!] GET {path} failed ({e.code}):\n{detail}")

    # -- helpers ------------------------------------------------------------
    def all_ids(self, path):
        """Page through a queries/* endpoint and collect every id."""
        ids, offset = [], 0
        while True:
            body = self.get(path, {"limit": PAGE_LIMIT, "offset": offset})
            batch = body.get("resources") or []
            ids.extend(batch)
            pagination = (body.get("meta") or {}).get("pagination") or {}
            total = pagination.get("total", len(ids))
            offset += len(batch)
            print(f"    {len(ids)}/{total} ids", file=sys.stderr)
            if not batch or len(ids) >= total:
                break
        return ids

    def entities(self, path, ids):
        """Fetch entity bodies for ids, batched."""
        out = []
        for i in range(0, len(ids), ID_BATCH):
            chunk = ids[i : i + ID_BATCH]
            body = self.get(path, {"ids": chunk})
            out.extend(body.get("resources") or [])
            print(f"    {len(out)}/{len(ids)} entities", file=sys.stderr)
        return out


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    print(f"[+] {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="./out")
    ap.add_argument("--cloud", default=os.environ.get("FALCON_CLOUD", "us-1"))
    ap.add_argument(
        "--client-id", default=os.environ.get("FALCON_CLIENT_ID")
    )
    ap.add_argument(
        "--client-secret", default=os.environ.get("FALCON_CLIENT_SECRET")
    )
    args = ap.parse_args()

    if not args.client_id or not args.client_secret:
        raise SystemExit(
            "[!] Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET "
            "(or pass --client-id/--client-secret)."
        )
    if args.cloud not in CLOUDS:
        raise SystemExit(f"[!] --cloud must be one of: {', '.join(CLOUDS)}")

    os.makedirs(args.outdir, exist_ok=True)
    api = Falcon(CLOUDS[args.cloud], args.client_id, args.client_secret)

    print("[*] Combined schema members ...", file=sys.stderr)
    # This endpoint takes no parameters.
    combined = api.get("/fdr/combined/schema-members/v1")
    write_json(os.path.join(args.outdir, "combined_schema.json"), combined)

    print("[*] Event ids ...", file=sys.stderr)
    event_ids = api.all_ids("/fdr/queries/schema-events/v1")
    print("[*] Event schemas ...", file=sys.stderr)
    events = api.entities("/fdr/entities/schema-events/v1", event_ids)
    write_json(os.path.join(args.outdir, "events.json"), events)

    print("[*] Field ids ...", file=sys.stderr)
    field_ids = api.all_ids("/fdr/queries/schema-fields/v1")
    print("[*] Field schemas ...", file=sys.stderr)
    fields = api.entities("/fdr/entities/schema-fields/v1", field_ids)
    write_json(os.path.join(args.outdir, "fields.json"), fields)

    field_index = _build_field_index(fields)

    # ---- flat field catalogue (CSV) --------------------------------------
    fields_csv = os.path.join(args.outdir, "fields.csv")
    keys = sorted({k for f in fields for k in f.keys()})
    with open(fields_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for f in sorted(fields, key=lambda x: str(x.get("name", ""))):
            w.writerow({k: _flat(f.get(k)) for k in keys})
    print(f"[+] {fields_csv}  ({len(fields)} fields)")

    # ---- event -> fields mapping (CSV + Markdown) ------------------------
    map_csv = os.path.join(args.outdir, "event_fields.csv")
    rows = 0
    with open(map_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["event_name", "event_id", "field_name", "field_type", "description"])
        for ev in sorted(events, key=lambda x: str(x.get("name", ""))):
            for fl in _event_fields(ev, field_index):
                w.writerow(
                    [
                        ev.get("name", ""),
                        ev.get("id", ""),
                        fl.get("name", ""),
                        _flat(fl.get("type", "")),
                        _flat(fl.get("description", "")),
                    ]
                )
                rows += 1
    print(f"[+] {map_csv}  ({len(events)} events, {rows} event-field pairs)")

    if rows == 0 and events:
        sample = sorted(events[0].keys())
        print(
            "\n[!] Could not locate field references on event entities, so the\n"
            "    event->field mapping is EMPTY. The entity shape differs from\n"
            "    what this script expects.\n"
            f"    Keys on events[0]: {sample}\n"
            f"    Inspect {os.path.join(args.outdir, 'events.json')} and extend\n"
            "    FIELD_LIST_KEYS / _event_fields() accordingly.\n"
            "    (fields.csv is still complete -- only the mapping failed.)",
            file=sys.stderr,
        )
        sys.exit(2)

    md = os.path.join(args.outdir, "FDR_FIELDS.md")
    with open(md, "w") as fh:
        fh.write("# CrowdStrike FDR — event/field schema\n\n")
        fh.write(f"Tenant cloud: `{args.cloud}`  \n")
        fh.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}  \n")
        fh.write(f"Events: **{len(events)}** · Distinct fields: **{len(fields)}**\n\n")
        for ev in sorted(events, key=lambda x: str(x.get("name", ""))):
            fh.write(f"## {ev.get('name', ev.get('id', '?'))}\n\n")
            if ev.get("description"):
                fh.write(f"{ev['description']}\n\n")
            evf = _event_fields(ev, field_index)
            if not evf:
                fh.write("_No field list returned for this event._\n\n")
                continue
            fh.write("| Field | Type | Description |\n|---|---|---|\n")
            for fl in evf:
                d = str(_flat(fl.get("description", ""))).replace("|", "\\|")
                fh.write(
                    f"| `{fl.get('name','')}` | {_flat(fl.get('type',''))} | {d} |\n"
                )
            fh.write("\n")
    print(f"[+] {md}")

    print("\n[✓] Done. Authoritative, tenant-scoped FDR schema written to", args.outdir)


FIELD_LIST_KEYS = ("fields", "members", "schema_fields", "event_fields", "field_ids")


def _event_fields(ev, field_index):
    """Resolve an event entity's field list.

    Event entities may embed field dicts, or (more commonly) reference fields
    by id/name -- in which case we resolve against the field catalogue.
    """
    for key in FIELD_LIST_KEYS:
        val = ev.get(key)
        if not isinstance(val, list):
            continue
        out = []
        for item in val:
            if isinstance(item, dict):
                # Embedded, but may still be a bare {"id": ...} reference.
                ref = item.get("id") or item.get("field_id") or item.get("name")
                resolved = field_index.get(str(ref), {})
                merged = dict(resolved)
                merged.update({k: v for k, v in item.items() if v not in (None, "")})
                out.append(merged)
            else:
                ref = str(item)
                out.append(field_index.get(ref, {"name": ref}))
        return out
    return []


def _build_field_index(fields):
    """Index field entities by every plausible reference key."""
    idx = {}
    for f in fields:
        for key in ("id", "name", "field_id", "uuid"):
            val = f.get(key)
            if val not in (None, ""):
                idx.setdefault(str(val), f)
    return idx


def _flat(v):
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"))
    return "" if v is None else v


if __name__ == "__main__":
    main()
