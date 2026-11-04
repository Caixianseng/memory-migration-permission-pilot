"""Single-request official Flash adapter. Providers are injected; imports are inert.

transport(endpoint, credential, exact_body_bytes) -> (status, raw_response_bytes).
The lock spans reservation, wallet recheck, HTTP and durable evidence. A crashed
lock, unknown billing or rejected response stops this run; no request is retried.
"""
from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import time

ENDPOINT = "https://api.deepseek.com/chat/completions"
MODEL = "deepseek-flash"
PRICES = {"input": Decimal("2"), "output": Decimal("8"), "cache_hit": Decimal("0.04")}
MAX_RESPONSE = 4 * 1024 * 1024
SENSITIVE_KEYS = {"authorization", "api_key", "api-key", "apikey", "credential", "credentials", "headers", "access_token"}


class AdapterError(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise AdapterError(code)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def amount(value):
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise AdapterError("invalid_money") from None
    need(result.is_finite() and result >= 0, "invalid_money")
    return result


def parse(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out
    def invalid(_):
        raise AdapterError("nonfinite_json_number")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def durable(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sensitive(value, credential):
    if isinstance(value, str):
        return credential in value
    if isinstance(value, dict):
        return any(not isinstance(k, str) or k.lower() in SENSITIVE_KEYS or credential in k
                   or sensitive(v, credential) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(sensitive(v, credential) for v in value)
    return False


def http_transport(endpoint, credential, body):
    need(endpoint == ENDPOINT, "endpoint_not_official")
    connection = http.client.HTTPSConnection("api.deepseek.com", timeout=120)
    try:
        connection.request("POST", "/chat/completions", body=body,
                           headers={"Authorization": "Bearer " + credential, "Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, response.read(MAX_RESPONSE + 1)
    finally:
        connection.close()


class ControlledFlashClient:
    def __init__(self, config, budget_root, credential_provider, wallet_provider, transport=None):
        self.config = copy.deepcopy(config)
        need(config.get("model") == MODEL and config.get("endpoint", ENDPOINT) == ENDPOINT, "frozen_official_flash_required")
        self.cap = amount(config["budget_cap_cny"])
        need(self.cap > 0 and callable(credential_provider) and callable(wallet_provider), "budget_and_providers_required")
        allowed = config.get("accepted_response_models", [MODEL, "V4.1-Flash-1017"])
        need(type(allowed) is list and bool(allowed) and all(type(m) is str and m for m in allowed), "accepted_models_invalid")
        self.credential_provider, self.wallet_provider = credential_provider, wallet_provider
        self.transport = transport or http_transport
        self.root = Path(budget_root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        need(self.root.resolve() == self.root, "budget_root_alias")
        frozen = encoded(self.config)
        path = self.root / "config.json"
        try:
            durable(path, frozen)
        except FileExistsError:
            need(path.read_bytes() == frozen, "frozen_config_changed")
        self.config_sha256 = sha(frozen)

    def _totals(self):
        spent, pending, gross = Decimal(0), Decimal(0), Decimal(0)
        for job in self.root.glob("job-*"):
            need(job.is_dir() and job.resolve() == job, "job_path_invalid")
            reservation = parse((job / "reservation.json").read_bytes())
            value = amount(reservation["reservation_cny"])
            gross += value
            receipt_path = job / "receipt.json"
            receipt = parse(receipt_path.read_bytes()) if receipt_path.exists() else None
            if receipt and receipt.get("status") == "ok":
                spent += amount(receipt["estimated_peak_cost_cny"])
            elif receipt and receipt.get("status") == "not_dispatched":
                pass
            else:
                pending += value
        return spent, pending, gross

    def _wallet(self):
        wallet = self.wallet_provider()
        if isinstance(wallet, dict):
            observed = wallet.get("observed_at_unix")
            need(type(observed) in (int, float) and -2 <= time.time() - observed <= 15, "wallet_snapshot_stale")
            balance = amount(wallet.get("wallet_cny"))
            return balance, {"wallet_cny": str(balance), "observed_at_unix": observed,
                             "account_sha256": wallet.get("account_sha256", wallet.get("snapshot_sha256"))}
        balance = amount(wallet)
        return balance, {"wallet_cny": str(balance), "observed_at_unix": time.time(), "account_sha256": None,
                         "provider_supplied_current_scalar": True}

    def _validate(self, response, max_tokens, input_bound):
        need(isinstance(response, dict), "response_not_object")
        choices, usage = response.get("choices"), response.get("usage")
        need(type(choices) is list and len(choices) == 1, "one_choice_required")
        choice = choices[0]
        need(type(choice) is dict and choice.get("finish_reason") == "stop", "response_truncated_or_unfinished")
        message = choice.get("message")
        need(type(message) is dict and message.get("role") == "assistant"
             and not message.get("tool_calls") and not message.get("function_call"), "tool_or_nonassistant_output_rejected")
        output = message.get("content")
        need(type(output) is str and bool(output.strip()) and not message.get("refusal"), "empty_or_refused_output")
        need(message.get("reasoning_content") in (None, "") and message.get("reasoning") in (None, ""), "thinking_output_rejected")
        need(response.get("thinking") in (None, {"type": "disabled"}), "thinking_mode_not_disabled")
        need(type(usage) is dict, "missing_usage")
        need(type(usage.get("reasoning_tokens", 0)) is int and usage.get("reasoning_tokens", 0) == 0, "thinking_usage_rejected")
        prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens")
        need(type(prompt) is int and 0 < prompt <= input_bound and type(completion) is int
             and 0 < completion <= max_tokens, "usage_outside_reservation")
        need(type(usage.get("total_tokens")) is int and usage["total_tokens"] == prompt + completion, "usage_total_mismatch")
        hit, miss = usage.get("prompt_cache_hit_tokens", 0), usage.get("prompt_cache_miss_tokens", prompt)
        need(type(hit) is int and type(miss) is int and hit >= 0 and miss >= 0 and hit + miss == prompt, "cache_usage_mismatch")
        details = usage.get("completion_tokens_details", {})
        need(type(details) is dict and type(details.get("reasoning_tokens", 0)) is int
             and details.get("reasoning_tokens", 0) == 0, "thinking_usage_rejected")
        model, response_id = response.get("model"), response.get("id")
        need(type(model) is str and bool(model) and type(response_id) is str and bool(response_id), "missing_model_or_response_id")
        allowed = self.config.get("accepted_response_models", [MODEL, "V4.1-Flash-1017"])
        need(model.lower() in {m.lower() for m in allowed}, "unexpected_actual_model")
        # Peak input price is deliberately used even for reported cache hits.
        cost = (prompt * PRICES["input"] + completion * PRICES["output"]) / Decimal(1_000_000)
        return output, cost

    def generate(self, messages, job_id, max_tokens, role):
        need(type(job_id) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", job_id), "job_id_invalid")
        need(role in ("source", "target") and type(max_tokens) is int
             and 0 < max_tokens <= (2048 if role == "source" else 4096), "role_or_output_limit_invalid")
        need(type(messages) is list and bool(messages) and all(type(m) is dict and set(m) == {"role", "content"}
             and m["role"] in ("system", "user", "assistant") and type(m["content"]) is str for m in messages), "messages_invalid")
        body = encoded({"model": MODEL, "messages": messages, "max_tokens": max_tokens,
                        "thinking": {"type": "disabled"}, "stream": False})
        input_bound = len(body) + 2048
        reservation = (input_bound * PRICES["input"] + max_tokens * PRICES["output"]) / Decimal(1_000_000)
        lock = self.root / "exclusive.runlock"
        try:
            durable(lock, encoded({"pid": os.getpid(), "job_id": job_id}))
        except FileExistsError:
            raise AdapterError("exclusive_runlock_exists_no_auto_recovery") from None
        safe_unlock = True
        try:
            need((self.root / "config.json").read_bytes() == encoded(self.config), "frozen_config_changed")
            need(not (self.root / "STOPPED.json").exists(), "run_stopped")
            spent, pending, gross = self._totals()
            need(pending == 0, "unresolved_reservation_stops_run")
            need(spent + pending + reservation <= self.cap, "frozen_budget_cap_exceeded")
            job = self.root / ("job-" + job_id)
            need(not job.exists(), "job_already_reserved_no_retry")
            credential = self.credential_provider()
            need(type(credential) is str and len(credential) >= 8 and not any(c in credential for c in "\r\n"), "credential_invalid")
            need(credential.encode() not in body and not sensitive(messages, credential), "credential_in_request_body")
            job.mkdir()
            safe_unlock = False
            durable(job / "request.json", body)
            record = {"job_id": job_id, "role": role, "config_sha256": self.config_sha256,
                      "request_sha256": sha(body), "request_bytes": len(body), "input_token_bound": input_bound,
                      "max_tokens": max_tokens, "reservation_cny": str(reservation), "created_at_unix": time.time(),
                      "prior_spent_bound_cny": str(spent), "prior_pending_cny": str(pending),
                      "prior_gross_reservations_cny": str(gross), "automatic_retries": 0}
            durable(job / "reservation.json", encoded(record))
            receipt = {**record, "status": "not_dispatched", "output": None, "raw_response": None, "usage": None,
                       "model": None, "requested_model": MODEL, "response_id": None, "system_fingerprint": None,
                       "estimated_peak_cost_cny": None, "actual_invoice_cny": None, "http_attempts": 0,
                       "request_path": str(job / "request.json"), "receipt_path": str(job / "receipt.json"),
                       "raw_response_path": None, "thinking_disabled_check": None}
            try:
                wallet, evidence = self._wallet()
                receipt["wallet_snapshot"] = evidence
                need(wallet >= reservation + pending, "wallet_insufficient_after_reservation")
                need((self.root / "config.json").read_bytes() == encoded(self.config), "frozen_config_changed")
                durable(job / "dispatch.json", encoded({"job_id": job_id, "request_sha256": sha(body), "at_unix": time.time()}))
                receipt.update(status="billing_unknown", http_attempts=1)
                status, raw = self.transport(ENDPOINT, credential, body)
                need(type(status) is int and isinstance(raw, (bytes, str)), "transport_result_invalid")
                raw = raw.encode("utf-8") if isinstance(raw, str) else raw
                receipt.update(http_status=status, raw_response_sha256=sha(raw), raw_response_bytes=len(raw))
                need(credential.encode() not in raw, "credential_reflection")
                need(len(raw) <= MAX_RESPONSE, "response_too_large")
                try:
                    response = parse(raw)
                except (ValueError, UnicodeError, AdapterError):
                    durable(job / "response.raw.json", raw)
                    receipt["raw_response_path"] = str(job / "response.raw.json")
                    raise AdapterError("invalid_response_json") from None
                need(not sensitive(response, credential), "sensitive_response_metadata")
                durable(job / "response.raw.json", raw)
                receipt.update(raw_response=response, raw_response_path=str(job / "response.raw.json"))
                if isinstance(response, dict):
                    receipt.update(usage=response.get("usage"), model=response.get("model"),
                                   response_id=response.get("id"), system_fingerprint=response.get("system_fingerprint"))
                need(status == 200, "http_status_not_200")
                output, cost = self._validate(response, max_tokens, input_bound)
                receipt.update(status="ok", output=output, usage=response["usage"], model=response["model"],
                               response_id=response["id"], system_fingerprint=response.get("system_fingerprint"),
                               estimated_peak_cost_cny=str(cost), thinking_disabled_check={"request_type": "disabled",
                               "returned_reasoning_content_empty": True, "reported_reasoning_tokens": 0,
                               "unreported_internal_thinking_verified": None})
            except Exception as error:
                receipt["error"] = str(error) if isinstance(error, AdapterError) else "provider_or_transport_" + type(error).__name__
                # Do not persist reflected secrets, including exception messages.
                if sensitive(receipt, credential):
                    receipt = {**record, "status": "billing_unknown", "output": None, "raw_response": None,
                               "http_attempts": 1, "error": "credential_reflection", "estimated_peak_cost_cny": None,
                               "actual_invoice_cny": None, "receipt_path": str(job / "receipt.json")}
            durable(job / "receipt.json", encoded(receipt))
            if receipt["status"] != "ok":
                durable(self.root / "STOPPED.json", encoded({"job_id": job_id, "status": receipt["status"], "error": receipt.get("error")}))
            safe_unlock = True
            return copy.deepcopy(receipt)
        finally:
            if safe_unlock:
                lock.unlink()
