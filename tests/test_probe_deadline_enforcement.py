"""Deadline regressions with fake probe I/O; never invoke a model or old gold."""
from contextlib import ExitStack, nullcontext, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from memory_migration_study.deadline_http import Deadline, DeadlineExceeded
from scripts import run_source_annotation_probe as source
from scripts import run_qwen35_model_probe as model
from scripts import run_copy_tag_probe as copy_tag
from scripts import run_qwen35_sampling_probe as sampling


DRIVERS = (source, model, copy_tag, sampling)


class ProbeDeadlineTests(unittest.TestCase):
    def test_four_drivers_share_deadline_helper_without_changing_wire_bytes(self):
        body = {"fixture": "原始字节"}
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__), tempfile.TemporaryDirectory() as temp:
                client = driver.BoundedClient(Path(temp)) if driver is source else driver.BoundedClient(Path(temp), {})
                event = {"wire_body": json.dumps(body, ensure_ascii=False, allow_nan=False)}
                client.events.append(event)
                def captured(*args, **kwargs):
                    self.assertIs(kwargs["deadline"], client.deadline)
                    self.assertIs(kwargs["connection_factory"], driver.http.client.HTTPConnection)
                    self.assertEqual(args[2], json.dumps(body, ensure_ascii=False).encode("utf-8"))
                    kwargs["event"].update(http_status=503, raw_response='{"error":"bounded evidence"}')
                    return b'{"error":"bounded evidence"}'
                with patch.object(driver, "exchange_http", side_effect=captured) as helper:
                    with self.assertRaisesRegex(ValueError, "local_http_failure"):
                        if driver is copy_tag:
                            client._exchange(body, event)
                        elif driver is sampling:
                            client._exchange("POST", "/api/chat", body, event)
                        else:
                            client._exchange("POST", "/api/chat", body)
                helper.assert_called_once()
                self.assertEqual(event["raw_response"], '{"error":"bounded evidence"}')

    def test_source_last_post_1799_to_1805_is_captured_as_failure(self):
        clock = [0]
        with tempfile.TemporaryDirectory() as temp, patch.object(source.time, "monotonic", side_effect=lambda: clock[0]):
            def late(*args):
                clock[0] = 1805
                return "{}"
            client = source.BoundedClient(Path(temp), exchange=late)
            client.begin_text(23)
            clock[0] = 1799
            with self.assertRaisesRegex(DeadlineExceeded, "wall_budget_exceeded"):
                client("POST", "/api/chat", {"model": source.base.MODEL, "options": deepcopy(source.base.OPTIONS)})
            event = source.read_json(Path(temp) / "transport_001.json")
            self.assertEqual(event["raw_response"], "{}")
            self.assertEqual(event["error_type"], "DeadlineExceeded")
            self.assertEqual(client.posts, 1)

    def run_fake_execution(self, driver, phase):
        """Exercise each real execute() with synthetic observations and clocks."""
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            output, clock = Path(temp), [0]
            stack.enter_context(patch.object(driver.time, "monotonic", side_effect=lambda: clock[0]))
            network = {"loopback_connects": 0, "blocked_connects": 0}
            response = {"local_calls_complete": True, "local_calls": 0, "elapsed_seconds": 0, "errors": []}
            inventory = {"token_counts_complete": True, "raw_generation_responses": 0}
            client = SimpleNamespace(started=0, posts=0, events=[], per_text_posts={}, closed=False,
                active=None, now=lambda: clock[0], deadline=Deadline(1800, clock=lambda: clock[0]),
                inventory=lambda: inventory, begin_text=Mock(), begin_cell=Mock(return_value=Mock()),
                finish_cell=Mock(), call=Mock(return_value={}))
            client.close = lambda: setattr(client, "closed", True)
            plan = {"policy": {}, "scope": "fixture", "comparison": "fixture", "model_digest": "fixture"}
            texts, historical = ["fixture %d" % i for i in range(24)], [{} for _ in range(24)]
            ids = range(24) if driver in (source, model) else driver.TEXT_IDS
            last = list(ids)[-1]
            def rows(index, *args, **kwargs):
                if phase == "prepare" and index == last:
                    clock[0] = 1805
                if phase == "interrupt":
                    raise KeyboardInterrupt("fixture interrupt")
                return [{"cell": {"text_index": index, "arm": arm}} for arm in driver.ARMS]
            if driver is source:
                verified = (plan, texts, historical)
                def observe(index, *args, **kwargs):
                    annotation = {**response, "agent_elapsed_seconds": 0}
                    if phase == "prepare" and index == last:
                        # A timed-out adapter may return incomplete accounting.
                        # The batch deadline must win over that secondary error.
                        annotation["local_calls_complete"] = False
                    return annotation, rows(index)
                stack.enter_context(patch.object(driver, "observe_case", side_effect=observe))
                stack.enter_context(patch.object(driver, "OccurrenceQwenAgent"))
            elif driver is model:
                verified = (plan, texts, historical, historical, {})
                stack.enter_context(patch.object(driver, "Qwen35OccurrenceAgent", return_value=Mock(return_value=response)))
                stack.enter_context(patch.object(driver, "prepare_case", side_effect=rows))
            else:
                requests = {str(i): {arm: {} for arm in driver.NEW_ARMS} for i in ids}
                verified = (plan, texts, requests)
                stack.enter_context(patch.object(driver, "network_guard", return_value=nullcontext(network)))
                stack.enter_context(patch.object(driver, "prepare_case", side_effect=rows))
                if driver is copy_tag:
                    stack.enter_context(patch.object(driver, "build_contract", return_value={}))
                    stack.enter_context(patch.object(driver, "parse_response", return_value=response))
                else:
                    stack.enter_context(patch.object(driver, "SamplingQwen35Agent", return_value=Mock(return_value=response)))
            if driver in (source, model):
                stack.enter_context(patch.object(source, "install_network_guard"))
            stack.enter_context(patch.object(driver, "verify", return_value=verified))
            stack.enter_context(patch.object(driver, "BoundedClient", return_value=client))
            stack.enter_context(patch.object(driver, "read_json", return_value=historical))
            gold = stack.enter_context(patch.object(driver, "load_closed_reference", return_value={}))
            original_save = driver.save
            def saved(path, value):
                original_save(path, value)
                if phase == "report" and Path(path).name == "report.json":
                    clock[0] = 1805
            stack.enter_context(patch.object(driver, "save", side_effect=saved))
            if phase not in ("prepare", "interrupt"):
                closure = "close_prediction_phase" if driver in (source, model) else "close_predictions"
                stack.enter_context(patch.object(driver, closure, side_effect=lambda *args: original_save(output / "prediction_phase_closed.json", {})))
            def score(*args):
                if phase == "score":
                    clock[0] = 1805
                return {"rows": [], "by_arm": {arm: {"known": 20, "unknown": 4} for arm in driver.ARMS}, "gate_components": {}}
            stack.enter_context(patch.object(driver, "score_rows", side_effect=score))
            if phase == "conflict":
                (output / "report.json").write_text("preserve fixture original", encoding="utf-8")
            expected_error = KeyboardInterrupt if phase == "interrupt" else FileExistsError if phase == "conflict" else DeadlineExceeded
            with redirect_stdout(io.StringIO()), self.assertRaises(expected_error):
                driver.execute(output, "fixture-plan")
            final = json.loads((output / "execution_final.json").read_text(encoding="utf-8"))
            self.assertEqual(final["status"], "interrupted" if phase == "interrupt" else "stopped")
            if driver in (copy_tag, sampling):
                self.assertFalse(final["complete"])
            if phase in ("prepare", "interrupt"):
                gold.assert_not_called()
                self.assertFalse((output / "prediction_phase_closed.json").exists())
            if phase == "conflict":
                self.assertEqual((output / "report.json").read_text(encoding="utf-8"), "preserve fixture original")
            else:
                self.assertFalse((output / "report.json").exists())

    def test_expired_final_preparation_cannot_close_or_read_gold_in_any_driver(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__):
                self.run_fake_execution(driver, "prepare")

    def test_expired_scoring_cannot_publish_success_in_any_driver(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__):
                self.run_fake_execution(driver, "score")

    def test_report_crossing_deadline_is_removed_in_any_driver(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__):
                self.run_fake_execution(driver, "report")

    def test_existing_report_is_preserved_on_exclusive_write_conflict(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__):
                self.run_fake_execution(driver, "conflict")

    def test_keyboard_interrupt_has_explicit_unsuccessful_final_state(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver.__name__):
                self.run_fake_execution(driver, "interrupt")


if __name__ == "__main__":
    unittest.main()
