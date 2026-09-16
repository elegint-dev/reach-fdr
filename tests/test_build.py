"""Build invariants for the data bundle (docs/ARCHITECTURE.md §2).

    python3 -m unittest tests.test_build -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(d, name):
    with open(os.path.join(d, name)) as fh:
        return json.load(fh)


class BundleTest(unittest.TestCase):
    """One build into a temp dir; every test reads its output."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app = os.path.join(cls.tmp.name, "data")
        proc = subprocess.run(
            [sys.executable, os.path.join("tools", "build_knowledge_base.py"),
             "--data", os.path.join(ROOT, "data"), "--out", cls.app],
            cwd=ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            raise AssertionError(f"build failed:\n{proc.stdout}\n{proc.stderr}")
        cls.stdout = proc.stdout
        cls.fields = _load(cls.app, "fields.json")
        cls.events = _load(cls.app, "events.json")
        cls.edges = _load(cls.app, "edges.json")
        cls.manifest = _load(cls.app, "manifest.json")
        cls.translations = _load(cls.app, "translations.json")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # -- the enrichment fold ----------------------------------------------

    def test_no_raw_field_is_left_unclassified(self):
        """Every raw field is classified after the enrichment fold."""
        stuck = [n for n, r in self.fields.items()
                 if r["layer"] == "raw_fdr" and r["role"] == "unclassified"]
        self.assertEqual(stuck, [], f"{len(stuck)} raw fields still unclassified")

    def test_every_enriched_field_carries_its_meaning_with_confidence_and_evidence(self):
        """Both confidence and evidence must survive the fold."""
        enriched = [r for r in self.fields.values()
                    if r.get("meaning") and r["meaning"].get("source") == "enrichment"]
        self.assertEqual(len(enriched), self.manifest["counts"]["enriched"])
        for r in enriched:
            self.assertIn(r["meaning"]["confidence"], ("high", "medium", "low"), r["name"])
            self.assertTrue(r["meaning"]["evidence"], r["name"])

    # -- joins: what is known vs asserted vs suggested -------------------

    def test_no_edge_without_a_citable_basis(self):
        for e in self.edges:
            self.assertIn(e["basis"], ("confirmed_ta", "asserted"), e["id"])
            self.assertTrue(e.get("basis_ref"), f"{e['id']} has no basis_ref")

    def test_inferred_same_role_buckets_are_not_edges(self):
        """They are reference lists, never pivots."""
        for e in self.edges:
            self.assertNotEqual(e["basis"], "inferred", e["id"])
            self.assertNotEqual(e.get("kind"), "same_role_candidates", e["id"])

    def test_detection_process_id_has_no_join_edge(self):
        """nothing on disk says which PID space it occupies."""
        self.assertFalse([e for e in self.edges if e["src"] == "ProcessId"])

    def test_suggested_joins_never_leak_into_edges(self):
        """Enrichment join_candidates render distinctly, never merged."""
        edge_pairs = {(e["src"], e["dst"]) for e in self.edges}
        for r in self.fields.values():
            for s in r.get("suggested_joins", []):
                self.assertNotIn((r["name"], s["to"]), edge_pairs, r["name"])
                self.assertIn(s["confidence"], ("high", "medium", "low"))

    def test_raw_process_id_edge_is_marked_unsafe_and_scoped(self):
        """Never offered without aid AND a time window."""
        e = next(x for x in self.edges if x["src"] == "RawProcessId")
        self.assertEqual(e["cardinality"], "unsafe")
        self.assertEqual(sorted(e["scope"]), ["aid", "time"])
        self.assertTrue(e.get("hazard"), "the OS-PID edge must carry a hazard")

    # -- three provenance layers --------------------------------

    def test_ta_derived_is_its_own_layer(self):
        self.assertEqual(self.fields["aid_computer_name"]["layer"], "ta_derived")
        self.assertEqual(self.fields["TargetProcessId_meaning"]["layer"]
                         if "TargetProcessId_meaning" in self.fields else "ta_derived",
                         "ta_derived")
        self.assertEqual(self.fields["process_id"]["layer"], "cim")
        counts = self.manifest["counts"]
        self.assertEqual(counts["ta_derived"] + counts["cim"], 321,
                         "the 321 TA/CIM records must split, not vanish")

    def test_layers_partition_the_namespace(self):
        c = self.manifest["counts"]
        self.assertEqual(c["raw_fdr"] + c["ta_derived"] + c["cim"], len(self.fields))

    # -- routes are per-event, not a collapsed verdict ----------

    def test_route_is_event_conditional_where_events_disagree(self):
        self.assertEqual(self.fields["RawProcessId"]["route"]["summary"], "mixed")
        by_event = self.fields["RawProcessId"]["route"]["by_event"]
        self.assertIn("AgenticSessionStart", by_event)
        self.assertNotEqual(by_event["AgenticSessionStart"]["route"],
                            by_event["ProcessRollup2"]["route"])

    def test_unobserved_and_derived_are_distinct_truths(self):
        routes = self.manifest["counts"]["routes"]
        self.assertGreater(routes["unobserved"], 0)
        self.assertGreater(routes["derived"], 0)
        for r in self.fields.values():
            self.assertTrue(r["route"]["explain"], r["name"])
            if r["route"]["summary"] == "derived" and not r["route"]["derived_from"]:
                # Legitimate: the TA computes it from an input that is not
                # itself a catalogued field (bitmask lookup intermediates).
                # It may not promise a route it cannot show.
                self.assertIn("no raw source", r["route"]["explain"], r["name"])

    # -- ResponsiblePid ------------------------------------------------

    def test_responsible_pid_is_ready_for_scenario_a(self):
        r = self.fields["ResponsiblePid"]
        # role comes from the name convention (`Pid$`), which outranks
        # enrichment's "identifier". The convention is checkable.
        self.assertEqual(r["role"], "process_id")
        self.assertEqual(r["role_basis"], "name_convention")
        self.assertEqual(r["meaning"]["confidence"], "high")
        self.assertEqual(r["route"]["summary"], "one_hop")
        self.assertEqual(r["events"],
                         ["ConfigurationProfileModified", "LoginItemAdded"])
        # A *Pid role must not manufacture a join edge.
        self.assertEqual(r["edges"], [])
        self.assertTrue(r["suggested_joins"])

    # -- no invented statistics ------------------------------------------

    def test_fixture_provenance_is_quarantined_in_audit(self):
        """sample_events_seen is fixture provenance, not a fill rate."""
        r = self.fields["ResponsiblePid"]
        self.assertIn("sample_events_seen", r["audit"])
        for key in ("fill_rate", "cardinality", "frequency", "populated"):
            self.assertNotIn(key, r, f"{key} is not knowable from a sanitized corpus")

    # -- the drift guard ----------------------------------------

    def test_manifest_counts_match_the_data_they_describe(self):
        c = self.manifest["counts"]
        self.assertEqual(c["fields"], len(self.fields))
        self.assertEqual(c["events"], len(self.events))
        self.assertEqual(c["edges_confirmed"] + c["edges_asserted"], len(self.edges))
        self.assertEqual(c["edges_confirmed"],
                         sum(1 for e in self.edges if e["basis"] == "confirmed_ta"))
        self.assertEqual(c["unclassified"],
                         sum(1 for r in self.fields.values() if r["role"] == "unclassified"))
        self.assertEqual(c["events_cim_gap"],
                         sum(1 for e in self.events.values() if not e["cim"]["normalized"]))

    def test_content_hash_covers_the_bundle(self):
        names = sorted(n for n in os.listdir(self.app)
                       if n.endswith(".json") and n != "manifest.json")
        h = hashlib.sha256()
        for n in names:
            with open(os.path.join(self.app, n), "rb") as fh:
                h.update(fh.read())
        self.assertEqual(self.manifest["content_hash"], h.hexdigest())

    def test_schema_version_is_declared(self):
        self.assertEqual(self.manifest["schema_version"], 1)

    # -- curated input is validated, not trusted ------------------------

    def test_translations_only_name_events_and_fields_that_exist(self):
        t = self.translations["pid_translation"]
        named = set(t["anchor_events"]["events"]) | set(t["needs_join"]["events"]) \
            | set(t["raw_only"]["events"])
        self.assertTrue(named <= set(self.events), named - set(self.events))
        self.assertTrue(set(t["fields"]) <= set(self.fields))

    def test_no_generated_spl_uses_cloud_unsafe_commands(self):
        """queries/README.md commits the library to Splunk Cloud."""
        blob = json.dumps(self.translations)
        for cmd in ("| join ", "| map ", "| transaction "):
            self.assertNotIn(cmd, blob, f"{cmd.strip()} is not available on Splunk Cloud")

    # -- events -----------------------------------------------------------

    def test_cim_gap_events_say_so(self):
        gap = [e for e in self.events.values() if not e["cim"]["normalized"]]
        self.assertEqual(len(gap), 219)
        for e in gap:
            self.assertEqual(e["cim"]["data_models"], [], e["name"])

    def test_detection_events_are_the_external_sourcetype(self):
        self.assertEqual(self.events["Event_DetectionSummaryEvent"]["sourcetype"],
                         "crowdstrike:events:external")
        self.assertEqual(self.events["ProcessRollup2"]["sourcetype"],
                         "crowdstrike:events:sensor")

    def test_detection_events_have_no_process_handles(self):
        """*ProcessId on crowdstrike:events:external is not a process handle."""
        for name in ("Event_DetectionSummaryEvent", "Event_EppDetectionSummaryEvent"):
            e = self.events[name]
            self.assertEqual(e["handles"], [], name)
            self.assertIn("ParentProcessId", e["pid_fields_unestablished"], name)
        # a field that rides only on detection events cannot be one_hop
        r = self.fields["MD5String"]
        self.assertEqual(r["route"]["summary"], "host_only")
        self.assertIn("not established", r["route"]["explain"])
        for ev, v in self.fields["ParentProcessId"]["route"]["by_event"].items():
            if self.events[ev]["sourcetype"] == "crowdstrike:events:external":
                self.assertEqual(v["route"], "host_only", ev)
                self.assertTrue(v.get("external"), ev)

    def test_search_time_lookups_carry_where_they_fire(self):
        """the three confirmed joins are TA LOOKUP stanzas; the bundle
        says on which sourcetypes they fire and which fields they put on the
        record, read from the TA's own rows -- never assumed."""
        for e in self.edges:
            self.assertIn(e["mechanism"], ("query", "search_time_lookup"), e["id"])
            if e["mechanism"] == "search_time_lookup":
                self.assertEqual(e["basis"], "confirmed_ta", e["id"])
                self.assertTrue(e["automatic_on"], e["id"])
                self.assertTrue(e["yields"], e["id"])
                for y in e["yields"]:
                    self.assertEqual(self.fields[y]["layer"], "ta_derived", y)
            else:
                self.assertEqual(e["automatic_on"], [])
        aid = next(e for e in self.edges if e["id"] == "e_aid_to_aidmaster")
        self.assertEqual(aid["automatic_on"], ["crowdstrike:events:sensor"])
        self.assertIn("aid_computer_name", aid["yields"])

    def test_anchor_events_are_flagged(self):
        self.assertTrue(self.events["ProcessRollup2"]["is_anchor"])
        self.assertTrue(self.events["SyntheticProcessRollup2"]["is_anchor"])
        self.assertFalse(self.events["DnsRequest"]["is_anchor"])
        self.assertEqual(self.events["DnsRequest"]["handles"], ["ContextProcessId"])


if __name__ == "__main__":
    unittest.main()
