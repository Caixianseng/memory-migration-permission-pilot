"""One copy/tag canary, then non-generative template/token compilation."""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_copy_tag_probe as probe
from memory_migration_study.source_tagging import build_contract, parse_tagged


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8388608), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime-dir", required=True, type=Path)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--qualify", action="store_true")
    mode.add_argument("--finalize-captured-canary", action="store_true")
    mode.add_argument("--compile-prompts", action="store_true")
    a = p.parse_args()
    out = a.runtime_dir.resolve()
    probe.require(out.is_relative_to(ROOT / "results"), "runtime_scope")
    started = probe.read_json(out / "runtime_started.json")
    probe.require(started["endpoint"] == probe.ENDPOINT and started["model_sha256"] == probe.MODEL_SHA256
                  and started["thinking"] is False and started["n_ctx"] == 4096, "runtime_identity_changed")
    probe.require(sha(Path(started["model_path"])) == probe.MODEL_SHA256
                  and sha(Path(started["executable"])) == started["executable_sha256"], "runtime_asset_changed")
    posts = 0

    def request(path, body):
        nonlocal posts
        probe.require(path in {"/apply-template", "/tokenize", "/completion"}, "unexpected_local_api")
        if path == "/completion":
            probe.require(a.qualify and posts == 0, "canary_generation_limit")
            posts += 1
        c = http.client.HTTPConnection("127.0.0.1", 11436, timeout=180)
        try:
            c.request("POST", path, json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                      {"Content-Type": "application/json"})
            r = c.getresponse()
            raw = r.read(1048577)
            if path == "/completion":
                with (out / "canary_response.raw.json").open("xb") as stream:
                    stream.write(raw)
            probe.require(r.status == 200 and len(raw) <= 1048576, "local_metadata_http_failure")
            return json.loads(raw)
        finally:
            c.close()

    texts, policy, _, _, _ = probe.historical_inputs()

    def compile_case(text, i):
        contract = build_contract(text)
        messages = probe.build_messages(text, policy, contract)
        template_request = {"messages": messages, "add_generation_prompt": True,
                            "chat_template_kwargs": {"enable_thinking": False}}
        template_response = request("/apply-template", template_request)
        prompt = template_response.get("prompt")
        probe.require(type(prompt) is str and bool(prompt), "applied_template_missing")
        tokenize_request = {"content": prompt, "add_special": True, "parse_special": True}
        tokenize_response = request("/tokenize", tokenize_request)
        tokens = tokenize_response.get("tokens")
        probe.require(type(tokens) is list and all(type(t) is int and t >= 0 for t in tokens)
                      and 0 < len(tokens) <= 3072, "actual_prompt_budget")
        return {"text_index": i, "messages": messages, "prompt": prompt,
                "token_count": len(tokens), "prompt_sha256": probe.text_sha(prompt),
                "source_sha256": contract["source_sha256"], "policy_sha256": probe.digest(policy),
                "contract_sha256": contract["contract_sha256"],
                "apply_template_request": template_request, "apply_template_response": template_response,
                "tokenize_request": tokenize_request, "tokenize_response": tokenize_response}

    if a.qualify or a.finalize_captured_canary:
        if a.qualify:
            save(out / "canary_started.json", {"max_generation_calls": 1, "formal_texts": 0,
                 "runtime_started_sha256": sha(out / "runtime_started.json"), "script_sha256": sha(Path(__file__))})
        else:
            probe.require((out / "canary_started.json").is_file()
                          and (out / "canary_failure.json").is_file()
                          and not (out / "runtime_qualification.json").exists(), "captured_canary_required")
        try:
            text = "甲😀乙e\u0301"
            case, contract = compile_case(text, -1), build_contract(text)
            body = {"prompt": case["prompt"], "grammar": probe.header_grammar(contract),
                    "n_predict": 128, "temperature": 0, "seed": 42,
                    "stream": False, "cache_prompt": True}
            if a.qualify:
                save(out / "canary_request.json", body)
                result = request("/completion", body)
                save(out / "canary_response.json", result)
            else:
                probe.require(probe.digest(probe.read_json(out / "canary_request.json")) == probe.digest(body),
                              "captured_canary_request_changed")
                result = probe.read_json(out / "canary_response.json")
                probe.require(probe.digest(json.loads((out / "canary_response.raw.json").read_bytes())) == probe.digest(result),
                              "captured_canary_response_changed")
            prompt_n, predicted_n = probe.response_counts(result)
            probe.require(predicted_n <= 128, "canary_output_limit")
            status, separator, tagged = result["content"].partition("\n")
            probe.require(separator == "\n" and status in {"OK", "REVIEW"}, "canary_header_invalid")
            parsed = parse_tagged(text, tagged, contract)
            receipt = dict(started)
            receipt.update(status="qualified", canary={"success": True, "generation_calls": 1,
                "assessment_mode": "existing_capture_no_new_generation" if a.finalize_captured_canary else "initial_generation",
                "formal_texts": 0, "prompt_tokens": prompt_n, "output_tokens": predicted_n,
                "source_sha256": contract["source_sha256"], "findings": parsed["findings"],
                "semantic_accuracy_tested": False, "request_sha256": sha(out / "canary_request.json"),
                "response_sha256": sha(out / "canary_response.json")})
            save(out / "runtime_qualification.json", receipt)
            print(json.dumps({"status": "qualified", "new_generation_calls_this_command": posts,
                              "total_canary_generation_calls": 1,
                              "prompt_tokens": prompt_n, "output_tokens": predicted_n}))
        except Exception as e:
            save(out / ("canary_reassessment_failure.json" if a.finalize_captured_canary else "canary_failure.json"), {"status": "failed", "generation_post_attempts": posts,
                 "formal_texts": 0, "error_type": type(e).__name__, "error": str(e)})
            raise
    else:
        receipt = probe.read_json(out / "runtime_qualification.json")
        probe.require(receipt["canary"]["success"] is True, "canary_required")
        bundle = {"version": "copy_tag_actual_prompt_bundle_v1", "cases": [compile_case(texts[i], i) for i in probe.TEXT_IDS],
                  "runtime_receipt_sha256": sha(out / "runtime_qualification.json"),
                  "script_sha256": sha(Path(__file__)), "generation_calls": 0}
        probe.validate_compilation(receipt, bundle, texts, policy)
        save(out / "prompt_bundle.json", bundle)
        print(json.dumps({"cases": len(bundle["cases"]), "generation_calls": posts,
              "max_prompt_tokens": max(c["token_count"] for c in bundle["cases"])}))


if __name__ == "__main__":
    main()
