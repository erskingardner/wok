#!/usr/bin/env python3
"""Controller safety/correctness gates, without starting VM jobs."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("run-campaign.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class CampaignTests(unittest.TestCase):
    def test_matrix_reverses_each_arm_pair_at_each_rate(self):
        rates = [100, 250, 500, 1000]
        jobs = M.matrix(rates, 2)
        self.assertEqual(len(jobs), 24)
        self.assertEqual(len({job["name"] for job in jobs}), 24)
        for rate in rates:
            first = [j["arm"] for j in jobs if j["write_rate"] == rate and j["repetition"] == 1]
            second = [j["arm"] for j in jobs if j["write_rate"] == rate and j["repetition"] == 2]
            self.assertEqual(first, list(reversed(second)))
        self.assertEqual([j["write_rate"] for j in jobs[12::3]], list(reversed(rates)))

    def test_recovery_only_accepts_explicit_arm_changes_and_identical_driver_workload(self):
        old = {"binaries": {arm: arm for arm in (*M.ARMS,"rocksdb")},
               "bench_binary_sha256": "driver", "wok_template_sha256": "config",
               "fastr_environment": {}, "options": {"events":80000,"read_rate":1000,"root":"old"}}
        new = copy.deepcopy(old)
        new["binaries"]["rocksdb"] = "fixed"
        new["options"].update(root="new",rerun_arms=["rocksdb"])
        M.validate_predecessor_identity(old,new,rerun_network=True,rerun_arms=["rocksdb"])
        for key in ["driver","workload","unchanged_arm","config","unknown_arm","old_count"]:
            changed=copy.deepcopy(new);arms=["rocksdb"];rerun=True
            if key=="driver":changed["bench_binary_sha256"]="different"
            if key=="workload":changed["options"]["events"]=5000
            if key=="unchanged_arm":changed["binaries"]["wok"]="different"
            if key=="config":changed["wok_template_sha256"]="different"
            if key=="unknown_arm":arms=["unknown"]
            if key=="old_count":rerun=False
            with self.subTest(key=key),self.assertRaises(AssertionError):
                M.validate_predecessor_identity(old,changed,rerun_network=rerun,rerun_arms=arms)
        with self.assertRaises(AssertionError):
            M.validate_predecessor_identity(old,new,rerun_network=True,rerun_arms=[])

    def test_four_arm_matrix_keeps_all_32_cells_and_reverses_pairs(self):
        rates = [100,250,500,1000]
        arms = (*M.ARMS, "rocksdb")
        jobs = M.matrix(rates,2,arms)
        self.assertEqual(len(jobs),32)
        for rate in rates:
            first=[j["arm"] for j in jobs if j["write_rate"]==rate and j["repetition"]==1]
            second=[j["arm"] for j in jobs if j["write_rate"]==rate and j["repetition"]==2]
            self.assertEqual(first,list(reversed(second)))
            self.assertEqual(set(first),set(arms))
        M.parse_import("rocksdb", "Processed 12 lines. 12 added, 0 rejected, 0 dups",12)

    def test_new_seed_import_resolves_transitive_raw_corpus_without_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);original=root/"original";original.mkdir()
            (original/"corpus.jsonl").write_text("signed events fixture\n")
            M.save(original/"complete.json",{})
            M.save(original/"corpus-manifest.json",{"sha256":M.sha(original/"corpus.jsonl")})
            imported=root/"imported";imported.mkdir()
            M.save(imported/"complete.json",{"imported_corpus_path":str(original)})
            self.assertEqual(M.corpus_source(imported),original/"corpus.jsonl")
            self.assertFalse((imported/"corpus.jsonl").exists())
            (original/"corpus.jsonl").write_text("changed")
            with self.assertRaisesRegex(AssertionError,"source corpus changed"):
                M.corpus_source(imported)

    def test_rocks_audit_selects_full_report_amid_interleaved_final_stats(self):
        report={"ok":True,"events":12,"verified_signatures_and_bodies":12,"covering_records_verified":12,"table_counts":{},"layout":"optimized"}
        text='WOK_ROCKSDB_FINAL_STATS {"column_families":{}}\n'+M.json.dumps(report,indent=2)+'\n'
        self.assertEqual(M.parse_rocksdb_audit(text,12),report)
        with self.assertRaises(AssertionError):M.parse_rocksdb_audit(text,13)
        with self.assertRaises(AssertionError):M.parse_rocksdb_audit(text+M.json.dumps(report),12)

    def test_import_exit_zero_cannot_hide_invalid_records(self):
        M.parse_import("wok", "Done. Processed 12 lines. 12 added, 0 rejected, 0 dups", 12)
        M.parse_import("fastr", "imported: 12  duplicates: 0  failures: 0", 12)
        for arm, text in [("fastr", "imported: 11 duplicates: 0 failures: 1"),
                          ("fastr", "imported: 11 duplicates: 1 failures: 0"),
                          ("wok", "Done. Processed 12 lines. 11 added, 1 rejected, 0 dups"),
                          ("fastr", "exited successfully")]:
            with self.assertRaises(AssertionError):
                M.parse_import(arm, text, 12)

    def report(self):
        return {"format": "network-matched-v1", "ok": True, "corpus_sha256": "corpus", "query_plan_sha256": "queries",
                "write_rate": 250, "read_rate": 100, "read_connections": 2, "publish_connections": 32,
                "corpus_events": 12000, "corpus_retained": 12000, "seed": 257, "drain_secs": 120,
                "offered_writes": 1000, "sent_writes": 1000, "accepted_writes": 1000,
                "offered_reads": 400, "sent_reads": 400, "completed_reads": 400,
                **{key: 0 for key in ["rejected_writes", "unanswered_writes", "unsent_writes", "unanswered_reads", "unsent_reads",
                                      "query_mismatches", "protocol_errors", "postcheck_mismatches"]}}

    def queried_report(self):
        report = self.report()
        report.update(matched_writer_authors="queried", history_cutoff=9999)
        overlap = {shape: {"plans":64,"author_filter_plans":64,"plans_with_writer_authors":64,
                           "minimum_writer_authors":1,"maximum_writer_authors":16}
                   for shape in ["author","feed500"]}
        overlap.update({shape: {"plans":64,"author_filter_plans":0,"plans_with_writer_authors":0,
                               "minimum_writer_authors":None,"maximum_writer_authors":None}
                        for shape in ["tag","id"]})
        report["workload"] = {key:report[key] for key in ["corpus_sha256","query_plan_sha256",
            "history_cutoff","seed","offered_writes","write_rate","read_rate","read_connections",
            "publish_connections","drain_secs","matched_writer_authors"]}
        report["workload"].update(format="network-matched-queried-authors-v1",writer_authors={
            "mode":"queried","author_count":64,"pubkey_set_sha256":"a"*64,
            "timed_event_ids_sha256":"b"*64,"query_shape_overlap":overlap})
        self.rehash_workload(report)
        return report

    def rehash_workload(self, report):
        raw=M.json.dumps(report["workload"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        report["workload_sha256"]=M.hashlib.sha256(raw).hexdigest()

    def test_default_writer_mode_preserves_command_and_accepts_legacy_report(self):
        self.assertEqual(M.matched_writer_arguments("disjoint"),[])
        self.assertEqual(M.matched_writer_arguments("queried"),["--matched-writer-authors","queried"])
        M.validate_writer_workload(self.report(),"disjoint")
        with self.assertRaises(AssertionError):M.validate_writer_workload(self.report(),"queried")

    def test_queried_writer_mode_hash_and_overlap_cannot_be_mixed_or_tampered(self):
        report=self.queried_report()
        M.validate_network(report,1000,250,100,"corpus","queries",matched_writer_authors="queried")
        with self.assertRaises(AssertionError):M.validate_writer_workload(report,"disjoint")
        for field in ["hash","seed","missing_feed","wrong_author_count"]:
            changed=copy.deepcopy(report)
            if field=="hash":changed["workload_sha256"]="0"*64
            if field=="seed":changed["workload"]["seed"]+=1
            if field=="missing_feed":changed["workload"]["writer_authors"]["query_shape_overlap"]["feed500"]["plans_with_writer_authors"]=0
            if field=="wrong_author_count":changed["workload"]["writer_authors"]["author_count"]=32
            if field!="hash":self.rehash_workload(changed)
            with self.subTest(field=field),self.assertRaises(AssertionError):
                M.validate_writer_workload(changed,"queried")

    def test_predecessor_cannot_change_writer_authors(self):
        old={"binaries":{arm:arm for arm in M.ARMS},"bench_binary_sha256":"driver",
             "wok_template_sha256":"config","fastr_environment":{},"options":{"events":80000}}
        new=copy.deepcopy(old);new["options"]["matched_writer_authors"]="queried"
        with self.assertRaisesRegex(AssertionError,"workload/options"):
            M.validate_predecessor_identity(old,new,rerun_network=False,rerun_arms=[])

    def check_report(self, report):
        return M.validate_network(report, 1000, 250, 100, "corpus", "queries", corpus_events=12000, seed=257, drain_secs=120)

    def test_network_counts_rates_identity_and_body_oracle(self):
        self.assertEqual(self.check_report(self.report()), "queries")
        for key, value in [("completed_reads", 399), ("accepted_writes", 999), ("postcheck_mismatches", 1),
                           ("query_mismatches", 1), ("corpus_retained", 11999), ("write_rate", 500),
                           ("query_plan_sha256", "different"), ("drain_secs", 30)]:
            report = self.report()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check_report(report)

    def test_preflight_diagnostic_is_not_misclassified_as_overload_or_missing_hash(self):
        report = {"format": "network-matched-v1", "ok": False, "stage": "preflight_or_setup",
                  "error": "COUNT preload cardinality 1000000 != 15000000"}
        with self.assertRaisesRegex(AssertionError, "COUNT preload cardinality"):
            M.validate_network(report, 80000, 100, 1000, "corpus", None, allow_censored=True)

    def test_import_preserves_original_evidence_and_detects_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old"
            report = old / "main/reports/r1-w100-wok"
            report.mkdir(parents=True)
            M.save(old / "manifest.json", {"identity": "frozen"})
            M.save(report / "result.json", {"ok": True})
            M.save(report / "complete.json", {"outcome": "completed", "artifacts": M.artifact_hashes(report, ["result.json"])})
            original_hash = M.sha(report / "complete.json")
            campaign = M.Campaign.__new__(M.Campaign)
            campaign.args = SimpleNamespace(predecessor=old)
            source = campaign.predecessor_marker(Path("main/reports/r1-w100-wok/complete.json"))
            destination = root / "new/main/reports/r1-w100-wok"
            campaign.import_marker(source, destination)
            imported = M.read(destination / "complete.json")
            M.verify_artifacts(destination, imported["artifacts"])
            self.assertEqual(M.sha(destination / imported["predecessor_marker"]), original_hash)
            self.assertEqual(M.sha(report / "complete.json"), original_hash)
            (report / "result.json").write_text("changed")
            with self.assertRaisesRegex(AssertionError, "evidence changed"):
                campaign.predecessor_marker(Path("main/reports/r1-w100-wok/complete.json"))

    def test_corrected_campaign_requires_terminal_count_proof(self):
        report = self.report()
        with self.assertRaisesRegex(AssertionError, "COUNT was not proven complete"):
            M.validate_network(report, 1000, 250, 100, "corpus", "queries", require_count_settled=True)
        report["preflight"] = {"count_terminal_response": True, "measurement_starts_after_count": True}
        M.validate_network(report, 1000, 250, 100, "corpus", "queries", require_count_settled=True)

    def test_transitive_corpus_import_keeps_original_remote_data_location(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old"
            original = old / "main/corpus"
            original.mkdir(parents=True)
            (original / "corpus.jsonl").write_text("immutable raw corpus")
            M.save(original / "corpus-manifest.json", {"events": 2048, "seed": 257, "base_timestamp": 10000,
                  "sha256": M.sha(original / "corpus.jsonl")})
            M.save(old / "manifest.json", {"identity": {"options": {"load_root": "/load/original"}}})
            M.save(original / "complete.json", {"artifacts": M.artifact_hashes(original, ["corpus.jsonl", "corpus-manifest.json"])})
            previous = root / "previous"
            corpus = previous / "main/corpus"
            corpus.mkdir(parents=True)
            M.shutil.copy2(original / "corpus-manifest.json", corpus / "corpus-manifest.json")
            M.save(corpus / "complete.json", {"artifacts": M.artifact_hashes(corpus, ["corpus-manifest.json"]),
                  "imported_corpus_path": str(original)})
            campaign = M.Campaign.__new__(M.Campaign)
            campaign.args = SimpleNamespace(predecessor=previous, seed=257, base_timestamp=10000)
            campaign.corpus_remote = {}
            campaign.remote_root = Path("/load/new")
            stage = root / "current/main"
            stage.mkdir(parents=True)
            self.assertEqual(campaign.generate(stage, 2048), original)
            self.assertEqual(campaign.corpus_remote["main"], Path("/load/original/main/corpus/corpus.jsonl"))
            marker = M.read(stage / "corpus/complete.json")
            M.verify_artifacts(stage / "corpus", marker["artifacts"])
            self.assertFalse((stage / "corpus/corpus.jsonl").exists())
            self.assertEqual(campaign.generate(stage, 2048), original)

    def test_only_clearly_censored_overload_can_continue_in_main(self):
        report = self.report()
        report.update(ok=False, completed_reads=380, unanswered_reads=20,
                      protocol_errors=1, errors=["query receive ended: Err(Elapsed(()))"])
        with self.assertRaises(AssertionError):
            self.check_report(report)
        M.validate_network(report, 1000, 250, 100, "corpus", "queries", allow_censored=True)
        report["errors"] = ["query disconnected"]
        with self.assertRaises(AssertionError):
            M.validate_network(report, 1000, 250, 100, "corpus", "queries", allow_censored=True)
        report["errors"] = ["query pending safety bound 4096 exceeded; trial invalid"]
        M.validate_network(report, 1000, 250, 100, "corpus", "queries", allow_censored=True)
        report["postcheck_mismatches"] = 1
        with self.assertRaises(AssertionError):
            M.validate_network(report, 1000, 250, 100, "corpus", "queries", allow_censored=True)

    def test_only_owned_completed_clone_is_eligible_for_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "main" / "databases" / "r1-w100-wok"
            database.parent.mkdir(parents=True)
            campaign = M.Campaign.__new__(M.Campaign)
            campaign.root = root
            campaign.own(database, "databases")
            database.mkdir()
            (database / "data").write_text("scratch")
            campaign.cleanup(database)
            self.assertFalse(database.exists())
            outside = root / "unrelated"
            outside.mkdir()
            with self.assertRaises(AssertionError):
                campaign.cleanup(outside)
            self.assertTrue(outside.exists())
            seed = root / "main" / "seeds" / "wok"
            seed.mkdir(parents=True)
            with self.assertRaises(AssertionError):
                campaign.cleanup(seed)
            self.assertTrue(seed.exists())

    def test_evidence_tampering_and_seed_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "load").mkdir()
            path = root / "load" / "report.json"
            path.write_text("evidence")
            values = M.artifact_hashes(root, ["load/report.json"])
            M.verify_artifacts(root, values)
            path.write_text("tampered")
            with self.assertRaises(AssertionError):
                M.verify_artifacts(root, values)
            with self.assertRaises(AssertionError):
                M.verify_artifacts(root, {"../elsewhere": "bad"})
            (root / "link").symlink_to(path)
            with self.assertRaises(AssertionError):
                M.inventory(root, True)

    def test_strfry_seed_directory_exists_after_ownership_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "qualification"
            (stage / "seeds").mkdir(parents=True)
            (stage / "reports").mkdir()
            corpus = stage / "corpus"
            corpus.mkdir()
            (corpus / "corpus.jsonl").write_text("fixture")
            M.save(corpus / "complete.json", {})
            M.save(corpus / "corpus-manifest.json", {"sha256": M.sha(corpus / "corpus.jsonl")})
            binary = root / "strfry"
            binary.write_text("frozen binary")
            campaign = M.Campaign.__new__(M.Campaign)
            campaign.root = root
            campaign.binary = {"strfry": binary}
            campaign.pinned_binaries = {"strfry": M.sha(binary)}
            campaign.template = {"strfry": "db = \"@DATABASE@\""}
            campaign.args = SimpleNamespace(relay_address="10.77.1.2", port=29990, unit_prefix="wok-fastr-bench-test")
            campaign.space = lambda *args: None
            campaign.update = lambda **args: None
            seed = stage / "seeds" / "strfry"
            def import_unit(unit, command, meta, log, **kwargs):
                self.assertTrue(seed.is_dir())
                self.assertEqual(M.read(seed.with_suffix(".owned.json"))["campaign"], str(root))
                (seed / "data.mdb").write_text("imported fixture")
                Path(log).write_text("imported fixture")
                M.save(meta, {"exit_code": 0})
            campaign.unit = import_unit
            with patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="12\n", stderr="")):
                self.assertEqual(campaign.prepare(stage, corpus, "strfry", 12), seed)
            self.assertTrue((stage / "reports" / "seed-strfry" / "complete.json").exists())
            self.assertEqual(campaign.prepare(stage, corpus, "strfry", 12), seed)

    def test_load_affinity_fallback_is_explicit_and_keeps_other_caps_strict(self):
        stats = {"memory.max": str(56 * M.GIB), "cpu.max": "1600000 100000"}
        nofile = {"nofile": {"soft": 65536, "hard": 65536}}
        with patch.object(M, "cgroup_stats", side_effect=lambda: dict(stats)), patch.object(M, "limits", return_value=nofile), patch.object(M.os, "sched_getaffinity", create=True, return_value=set(range(16))):
            result = M.check_caps(56, allow_process_affinity=True)
            self.assertNotIn("cpuset.cpus.effective", result)
            self.assertEqual(result["cpu_affinity_verification"]["actual_cpus"], list(range(16)))
            with self.assertRaises(AssertionError):
                M.check_caps(56)
            stats["memory.max"] = str(64 * M.GIB)
            with self.assertRaises(AssertionError):
                M.check_caps(56, allow_process_affinity=True)
            stats["memory.max"] = str(56 * M.GIB)
            stats["cpu.max"] = "max 100000"
            with self.assertRaises(AssertionError):
                M.check_caps(56, allow_process_affinity=True)
        stats["cpu.max"] = "1600000 100000"
        with patch.object(M, "cgroup_stats", return_value=stats), patch.object(M, "limits", return_value=nofile), patch.object(M.os, "sched_getaffinity", create=True, return_value=set(range(8))):
            with self.assertRaises(AssertionError):
                M.check_caps(56, allow_process_affinity=True)

    def overload_fixture(self, folder):
        r=self.report();r.update(ok=False,completed_reads=380,unanswered_reads=20,notices=0,
            errors=["query receive ended: Ok(Some(Err(Protocol(ResetWithoutClosingHandshake))))", "REQ send failed: Ok(Err(AlreadyClosed))"],protocol_errors=2)
        r["postcheck"]={"queried":1000,"stored":1000,**{key:0 for key in ["acked_missing","changed_or_unexpected","mismatches","refused_stored","unanswered_stored"]}}
        (folder/"load").mkdir()
        M.save(folder/"load/network-matched.json",r)
        text="".join(f'client connected conn_id={n} peer=load\n' for n in range(1,36))
        text+='client terminated conn_id=34 reason="ingress_paused_overflow"\nclient terminated conn_id=35 reason="ingress_paused_overflow"\n'
        (folder/"relay.log").write_text(text)
        M.save(folder/"backend-final-stats.json",{"column_families":{"events":{"rocksdb.background-errors":0}}})
        M.save(folder/"relay.resources.json",{"exit_code":0,"cgroup_before":{"memory.events":"oom 0\noom_kill 0\n"},"cgroup_after":{"memory.events":"oom 0\noom_kill 0\n"}})
        return r,text

    def test_only_verified_read_socket_overflow_is_classified_and_counters_stay(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d);r,text=self.overload_fixture(f)
            proof=M.read_ingress_overload_proof(r,f,1000)
            self.assertEqual(proof["terminated_read_connection_ids"],[34,35])
            self.assertFalse(proof["eligible_for_uncensored_latency_winner"])
            self.assertEqual(proof["protocol_errors_retained"],2)
            with self.assertRaises(AssertionError):
                M.validate_network(r,1000,250,100,"corpus","queries",allow_censored=True)
            M.validate_network(r,1000,250,100,"corpus","queries",allow_censored=True,verified_read_ingress_overload=True)
            bad=copy.deepcopy(r);bad['errors'][1]='publisher disconnected'
            with self.assertRaises(AssertionError):
                M.validate_network(bad,1000,250,100,"corpus","queries",allow_censored=True,verified_read_ingress_overload=True)
            for change in ['wrong_socket','other_reason','no_log','write_missing','postcheck','notices','background','oom']:
                (f/'relay.log').write_text(text);bad=copy.deepcopy(r)
                M.save(f/'backend-final-stats.json',{'column_families':{'events':{'rocksdb.background-errors':0}}})
                if change=='wrong_socket':(f/'relay.log').write_text(text.replace('terminated conn_id=34','terminated conn_id=2'))
                if change=='other_reason':(f/'relay.log').write_text(text.replace('ingress_paused_overflow','pong_timeout'))
                if change=='no_log':(f/'relay.log').write_text('')
                if change=='write_missing':bad['accepted_writes']=999
                if change=='postcheck':bad['postcheck']['acked_missing']=1
                if change=='notices':bad['notices']=1
                if change=='background':M.save(f/'backend-final-stats.json',{'column_families':{'events':{'rocksdb.background-errors':1}}})
                if change=='oom':M.save(f/'relay.resources.json',{'exit_code':0,'cgroup_before':{'memory.events':'oom 0\noom_kill 0\n'},'cgroup_after':{'memory.events':'oom 1\noom_kill 1\n'}})
                with self.subTest(change=change),self.assertRaises(AssertionError):M.read_ingress_overload_proof(bad,f,1000)

    def test_socket_error_variants_require_external_overload_proof(self):
        errors=[
            'query receive ended: Ok(Some(Err(Io(Os { code: 104, kind: ConnectionReset, message: "Connection reset by peer" }))))',
            'REQ send failed: Ok(Err(Io(Os { code: 32, kind: BrokenPipe, message: "Broken pipe" })))',
            'CLOSE send failed: Ok(Err(Io(Os { code: 104, kind: ConnectionReset, message: "Connection reset by peer" })))']
        for error in errors:self.assertTrue(M.known_read_disconnect_error(error),error)
        for error in ['publisher disconnected','publisher receive ended: Ok(Some(Err(Io(Os { code: 104, kind: ConnectionReset, message: "Connection reset by peer" }))))','REQ send failed: certificate error']:
            self.assertFalse(M.known_read_disconnect_error(error),error)
        with tempfile.TemporaryDirectory() as d:
            f=Path(d);r,text=self.overload_fixture(f);r['errors']=errors;r['protocol_errors']=len(errors)
            M.read_ingress_overload_proof(r,f,1000)
            with self.assertRaises(AssertionError):M.validate_network(r,1000,250,100,'corpus','queries',allow_censored=True)
            M.validate_network(r,1000,250,100,'corpus','queries',allow_censored=True,verified_read_ingress_overload=True)
            (f/'relay.log').write_text(text.replace('ingress_paused_overflow','pong_timeout'))
            with self.assertRaises(AssertionError):M.read_ingress_overload_proof(r,f,1000)

    def test_measured_resume_requires_all_binaries_and_driver_unchanged(self):
        old={'binaries':{arm:arm for arm in (*M.ARMS,'rocksdb')},'bench_binary_sha256':'driver','wok_template_sha256':'config','fastr_environment':{},'options':{'events':80000}}
        new=copy.deepcopy(old);new['options'].update(resume_measured=True,allow_read_ingress_overload=True)
        M.validate_predecessor_identity(old,new,rerun_network=True,rerun_arms=[])
        for key in ['rocksdb','wok','driver','workload']:
            bad=copy.deepcopy(new)
            if key in ['rocksdb','wok']:bad['binaries'][key]='changed'
            elif key=='driver':bad['bench_binary_sha256']='changed'
            else:bad['options']['events']=5000
            with self.subTest(key=key),self.assertRaises(AssertionError):M.validate_predecessor_identity(old,bad,rerun_network=True,rerun_arms=[])

    def test_retention_hash_mismatch_never_deletes_source_database(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);c=M.Campaign.__new__(M.Campaign);c.root=root
            c.args=SimpleNamespace(load_host='task@load');c.remote_root=Path('/task');c.remote_helper=Path('/task/helper.py')
            database=root/'main/databases/overloaded';database.parent.mkdir(parents=True)
            c.own(database,'databases');database.mkdir();(database/'data').write_text('preserved bytes')
            evidence=root/'evidence';evidence.mkdir();expected=M.inventory(database,True)
            c.remote=lambda *a,**k:None;c.unit=lambda *a,**k:None
            def transfer(source,destination,pull=False):
                if pull:M.save(destination,[{**expected[0],'sha256':'corrupted'}])
            c.transfer=transfer
            with self.assertRaisesRegex(AssertionError,'retained database copy changed'):
                c.retain_overload(database,evidence,'wok-fastr-bench-test')
            self.assertEqual((database/'data').read_text(),'preserved bytes')
            self.assertFalse((evidence/'retained-database.json').exists())
            c.transfer=lambda source,destination,pull=False:M.save(destination,expected) if pull else None
            c.retain_overload(database,evidence,'wok-fastr-bench-test')
            self.assertTrue(database.exists())
            self.assertTrue(M.read(evidence/'retained-database.json')['all_files_full_sha256_verified'])

    def test_private_unit_caps_slice_and_remote_user_manager(self):
        campaign = M.Campaign.__new__(M.Campaign)
        campaign.args = SimpleNamespace(unit_prefix="wok-fastr-bench-test", load_memory_gib=56,
                                        load_uid=1000, relay_slice="wokfastrbenchtest.slice")
        campaign.ssh = ["ssh", "task-user@load"]
        campaign.remote_helper = Path("/task/run-campaign.py")
        campaign.units = set()
        calls = []
        campaign.remote = lambda command, **kw: calls.append(command)
        with patch.object(M.subprocess, "run", return_value=subprocess.CompletedProcess([], 3)) as run:
            campaign.unit("wok-fastr-bench-test-load", ["bench"], "/task/meta", "/task/log", remote=True)
            launch = calls[-1]
            self.assertIn("XDG_RUNTIME_DIR=/run/user/1000", launch)
            self.assertIn("--user", launch)
            self.assertIn("MemoryMax=56G", launch)
            self.assertIn("LimitNOFILE=65536", launch)
            campaign.unit("wok-fastr-bench-test-relay", ["relay"], "/task/meta", "/task/log", wait=False)
            launch = run.call_args.args[0]
            self.assertIn("wokfastrbenchtest.slice", launch)
            self.assertIn("MemoryMax=64G", launch)
            self.assertIn("CPUQuota=1600%", launch)
            with self.assertRaises(AssertionError):
                campaign.unit("production-relay", ["relay"], "/task/meta", "/task/log")


if __name__ == "__main__":
    unittest.main()
