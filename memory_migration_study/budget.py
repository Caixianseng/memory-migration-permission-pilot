"""Opt-in model connector with persistent worst-case reservations; no retries."""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import uuid
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit


class BudgetError(RuntimeError):
    pass


def money(value):
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise BudgetError("invalid monetary value") from exc
    if not result.is_finite() or result < 0:
        raise BudgetError("monetary values must be finite and nonnegative")
    return result


class ChatCompletionsConnector:
    """No API model is inferred from the model used to program this project."""
    kind = "real_llm"

    def __init__(self, config: dict, ledger_path: Path, *, enable_remote=False, run_id=None, transport=None):
        self.config, self.ledger_path = config, Path(ledger_path)
        self.enable_remote = enable_remote
        self.run_id = run_id or str(uuid.uuid4())
        self.transport = transport or self._transport

    def _save(self, ledger):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.ledger_path.with_suffix(self.ledger_path.suffix + ".tmp")
        temp.write_text(json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.ledger_path)

    def _preflight(self):
        if self.enable_remote is not True:
            raise BudgetError("remote model calls are disabled")
        cfg = self.config
        required = ("model", "endpoint", "api_key_env", "currency", "price_source_url", "verified_prices_date",
                    "input_price_per_million", "output_price_per_million", "existing_cumulative_spend",
                    "existing_spend_confirmed", "total_limit", "run_limit", "max_input_tokens", "max_output_tokens")
        if any(key not in cfg for key in required) or cfg.get("existing_spend_confirmed") is not True:
            raise BudgetError("explicit verified prices, confirmed prior spend, and budgets are required")
        try:
            date = dt.date.fromisoformat(cfg["verified_prices_date"])
        except (ValueError, TypeError) as exc:
            raise BudgetError("price verification date must be ISO date") from exc
        if date > dt.date.today() or not cfg["price_source_url"]:
            raise BudgetError("invalid price verification evidence")
        parsed = urlsplit(cfg["endpoint"])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BudgetError("model endpoint must use HTTPS without embedded secrets")
        if not isinstance(cfg["model"], str) or not cfg["model"]:
            raise BudgetError("an explicit API model identifier is required")
        for key in ("max_input_tokens", "max_output_tokens"):
            if type(cfg[key]) is not int or cfg[key] <= 0:
                raise BudgetError("positive input and output token limits are required")
        for key in ("input_price_per_million", "output_price_per_million", "existing_cumulative_spend", "total_limit", "run_limit"):
            money(cfg[key])
        credential = os.environ.get(cfg["api_key_env"])
        if not credential:
            raise BudgetError("configured credential environment variable is absent")
        if self.ledger_path.exists():
            ledger = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            if ledger.get("stopped") or ledger.get("currency") != cfg["currency"]:
                raise BudgetError("ledger is stopped or currency differs")
            if any(call.get("status") in {"reserved", "billing_unknown"} for call in ledger.get("calls", [])):
                raise BudgetError("unsettled prior request requires manual billing reconciliation")
            if money(ledger["initial_existing_spend"]) != money(cfg["existing_cumulative_spend"]):
                raise BudgetError("confirmed prior spend differs from ledger initialization")
        else:
            ledger = {"schema_version": 1, "currency": cfg["currency"],
                      "initial_existing_spend": str(money(cfg["existing_cumulative_spend"])),
                      "stopped": False, "calls": [], "runs": {}, "supplier_bill_verified": False,
                      "execution_scope": "single_process_serial_only_no_cross_process_lock"}
        run = ledger["runs"].setdefault(self.run_id, {"limit": str(money(cfg["run_limit"]))})
        if money(run["limit"]) != money(cfg["run_limit"]):
            raise BudgetError("persisted run limit cannot change")
        return credential, ledger

    @staticmethod
    def _transport(endpoint, credential, payload):
        parsed = urlsplit(endpoint)
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=30)
        try:
            connection.request("POST", parsed.path or "/", body=json.dumps(payload).encode(),
                               headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 4 * 1024 * 1024:
                raise BudgetError("remote request failed; billing may be unknown")
            return json.loads(raw)
        finally:
            connection.close()

    def __call__(self, *, query, memories, session_id):
        credential, ledger = self._preflight()
        cfg = self.config
        messages = [{"role": "system", "content": "Answer the query using only the provided memories. If unsupported answer UNKNOWN. Return the exact fact value."},
                    {"role": "user", "content": json.dumps({"query": query, "memories": memories}, ensure_ascii=False)}]
        # Bytes give a deliberately conservative preflight estimate, including a fixed envelope reserve.
        input_upper = len(json.dumps(messages, ensure_ascii=False).encode("utf-8")) + 1024
        if input_upper > cfg["max_input_tokens"]:
            raise BudgetError("prompt exceeds conservative input budget")
        input_price, output_price = money(cfg["input_price_per_million"]), money(cfg["output_price_per_million"])
        reserve = (money(cfg["max_input_tokens"]) * input_price + money(cfg["max_output_tokens"]) * output_price) / Decimal(1000000)
        commitments = sum((money(c.get("charged", c["reserved"])) for c in ledger["calls"]), Decimal(0))
        run_commitments = sum((money(c.get("charged", c["reserved"])) for c in ledger["calls"] if c["run_id"] == self.run_id), Decimal(0))
        if money(ledger["initial_existing_spend"]) + commitments + reserve > money(cfg["total_limit"]) or run_commitments + reserve > money(cfg["run_limit"]):
            raise BudgetError("budget would be exceeded")
        call = {"call_id": str(uuid.uuid4()), "run_id": self.run_id, "session_id": session_id,
                "model": cfg["model"], "reserved": str(reserve), "status": "reserved",
                "input_price_per_million": str(input_price), "output_price_per_million": str(output_price),
                "price_source_url": cfg["price_source_url"], "verified_prices_date": cfg["verified_prices_date"],
                "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
        ledger["calls"].append(call)
        self._save(ledger)  # Durable reservation before any network call.
        try:
            response = self.transport(cfg["endpoint"], credential, {"model": cfg["model"], "messages": messages,
                                                                   "max_completion_tokens": cfg["max_output_tokens"], "temperature": 0})
            usage = response.get("usage", {})
            used_input, used_output = usage.get("prompt_tokens"), usage.get("completion_tokens")
            if type(used_input) is not int or type(used_output) is not int or used_input < 0 or used_output < 0 or used_input > cfg["max_input_tokens"] or used_output > cfg["max_output_tokens"]:
                raise BudgetError("unknown or out-of-reservation usage")
            cost = (money(used_input) * input_price + money(used_output) * output_price) / Decimal(1000000)
            answer = response["choices"][0]["message"]["content"]
            if not isinstance(answer, str):
                raise BudgetError("invalid completion")
            call.update(status="accounted", charged=str(cost), prompt_tokens=used_input, completion_tokens=used_output)
            self._save(ledger)
            return answer
        except Exception as exc:
            call.update(status="billing_unknown", error_type=type(exc).__name__)
            ledger["stopped"] = True
            self._save(ledger)
            raise BudgetError("request failed or usage unknown; reservation retained and ledger stopped") from None
