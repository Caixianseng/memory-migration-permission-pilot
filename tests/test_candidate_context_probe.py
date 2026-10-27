"""Small source-only driver regressions; fake transport, no real model or corpus."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import run_candidate_context_probe as probe
from tests.test_relation_event_probe import envelope
from tests.test_relation_events import pool as simple_pool
from tests.test_relation_probe_scoring import fixture, policy


def complete_pool(text, names):
    result = simple_pool(text, [(name, text.index(name)) for name in names])
    result["raw_result"] = {"entities": {"organization": [
        {k: value for k, value in item.items() if k != "cid"} | {"confidence": .9}
        for item in result["candidates"]]}}
    result["inference_counts"] = probe.base.relation._counts(proposal_infer_invocations=1)
    if len(names) > 2:
        result.update(status="needs_review", error_kind="coverage", errors=["candidate_limit_exceeded"])
    return probe.base.relation._seal(result, "pool_sha256")


class CandidateContextProbeTests(unittest.TestCase):
    def setUp(self):
        self.network = []
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            self.network.append(guard.start()); self.addCleanup(guard.stop)

    def tearDown(self):
        for guard in self.network: guard.assert_not_called()

    def test_twenty_four_requests_keep_all_three_candidates_and_same_contract(self):
        texts = [f"Larch, Alder and Elm are organizations in story {i}." for i in range(12)]
        pools = [complete_pool(text, ["Larch", "Alder", "Elm"]) for text in texts]
        before = deepcopy(pools)
        with patch.object(Path, "read_text", side_effect=AssertionError("no_reference_or_file_reads")):
            requests, checks = probe.requests_for(texts, pools)
        self.assertEqual((len(requests), len(checks)), (24, 24))
        for i, text in enumerate(texts):
            plain, marked = [requests[(i, arm)] for arm in probe.ARMS]
            self.assertEqual(plain["messages"][0], marked["messages"][0])
            self.assertEqual(plain["format"], marked["format"])
            self.assertEqual(plain["options"], marked["options"])
            for body in (plain, marked):
                self.assertEqual(json.loads(body["messages"][1]["content"])["candidates"], pools[i]["candidates"])
            self.assertEqual(json.loads(plain["messages"][1]["content"])["text"], text)
            self.assertNotEqual(json.loads(marked["messages"][1]["content"])["text"], text)
        self.assertEqual(pools, before)
        self.assertTrue(all(row["preflight"]["fits"] for row in checks))

    def test_invalid_generation_is_one_failed_attempt_without_repair_or_negative(self):
        text = "Larch is an organization."
        candidates = complete_pool(text, ["Larch"])
        for arm in probe.ARMS:
            client = Mock(return_value=envelope({"candidates": []}))
            status, response, raw = probe.observe(text, candidates, arm, {}, client)
            self.assertEqual((status, response["status"], response["local_calls"]),
                             ("model_output_invalid", "needs_review", 1))
            self.assertEqual(response["findings"], [])
            self.assertEqual(client.call_count, 1)
            self.assertIsNotNone(raw)

    def test_complete_grid_keeps_blocked_and_unknown_in_their_own_denominators(self):
        texts, reference, historical = fixture(12)
        rename = dict(zip(probe.scoring.ARMS[:2], probe.ARMS))
        rows = [deepcopy(row) for row in historical if row["cell"]["profile"] == probe.base.PROFILE
                and row["cell"]["arm"] in rename]
        for row in rows:
            row["cell"]["arm"] = rename[row["cell"]["arm"]]
            i = row["cell"]["text_index"]
            if i == 0:
                row.update(status="coverage_review", response=probe.base.failure_response("input_budget_exceeded"))
            if i == 1 and row["cell"]["arm"] == "marked":
                row.update(status="ok", response={"status":"ok", "errors":[], "findings":[], "local_calls":0, "elapsed_seconds":0.0})
            row["preparation"] = probe.scoring.prepare_observation(texts[i], policy(probe.base.PROFILE), row["response"])
            row["redaction_trace"] = probe.redaction.audit_observation(texts[i], policy(probe.base.PROFILE), row)
        before = deepcopy(rows)
        scored = probe.score(rows, reference, texts)
        for group in scored["by_arm"].values():
            self.assertEqual((group["cells"], group["known"], group["unknown"]), (12, 11, 1))
            self.assertEqual(group["statuses"]["coverage_review"], 1)
            self.assertEqual(group["known_prepared"], 10)
            self.assertGreater(group["fn"], 0)
            self.assertEqual(group["prepared_incomplete_spans"], 0)
        self.assertEqual(scored["by_arm"]["plain"]["unknown_review"], 1)
        self.assertEqual(scored["by_arm"]["marked"]["unknown_negative"], 1)
        self.assertEqual(rows, before)
        with self.assertRaises(ValueError): probe.score(rows[:-1], reference, texts)
        rows[-1] = deepcopy(rows[0])
        with self.assertRaises(ValueError): probe.score(rows, reference, texts)

    def test_fake_full_execution_freezes_all_predictions_before_loading_reference(self):
        texts, reference, _ = fixture(12)
        pools = [complete_pool(text, ["Fixture Office " + str(i)]) for i, text in enumerate(texts)]
        requests, checks = probe.requests_for(texts, pools)
        plan = {"policy":policy(probe.base.PROFILE), "checks":checks}
        actual_client = probe.base.Client
        def exchange(method, path, body):
            if path == "/api/version": return json.dumps({"version":probe.base.OLLAMA_VERSION})
            if path == "/api/tags": return json.dumps({"models":[{"name":probe.base.MODEL,"digest":probe.base.DIGEST}]})
            data = json.loads(body["messages"][1]["content"])
            return json.dumps(envelope({"candidates":[{"cid":c["cid"], "label":"organization_unknown_relation"}
                                                        for c in data["candidates"]]}))
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output/"evaluation.opaque.json").write_text(json.dumps(reference), encoding="utf-8")
            original_read = Path.read_text
            reads = []
            def guarded_read(path, *args, **kwargs):
                if path.name == "evaluation.opaque.json":
                    self.assertTrue((output/"prediction_phase_closed.json").is_file())
                    self.assertTrue((output/"predictions.json").is_file())
                    reads.append(path)
                return original_read(path, *args, **kwargs)
            with patch.object(probe,"verify",return_value=(plan,texts,pools,requests)), \
                 patch.object(probe.base,"Client",side_effect=lambda out:actual_client(out,exchange=exchange)), \
                 patch.object(probe.sys,"addaudithook"), patch.object(Path,"read_text",guarded_read), patch("builtins.print"):
                report = probe.execute(output,"synthetic-plan-sha")
            self.assertEqual((report["status"], report["generation_posts"]), ("complete",24))
            self.assertEqual(len(reads),1)
            self.assertEqual(len(json.loads((output/"predictions.json").read_text())),24)
            self.assertEqual(len(list(output.glob("transport_*.json"))),28)
            self.assertTrue(all(group["cells"]==12 and group["unknown_negative"]==0 for group in report["by_arm"].values()))


if __name__ == "__main__": unittest.main()
