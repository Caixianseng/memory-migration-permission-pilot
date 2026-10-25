"""Replay stored generation-time Union labels as an explicit-role baseline.

This reads public artifacts, not live authority or destroyed HMAC keys. It does
not import a mutable producer, execute archived code, or invoke any model.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_reference_memory_study import digest, sha, require, equal, _literal_assignment
from scripts.verify_source_role_probe import role_pattern

REFERENCE_SHA = "8693b5cd8e682de5eee08783ca623dc57b5329cb19d531d7e8be97a41c2926a2"


def project(text, source_id, candidates, aliases):
    """Same frozen nearest-prefix/status grammar; label spans have no score."""
    anchors = [(m.start(), m.end(), role) for role, terms in aliases.items() if role != "status"
               for m in re.finditer(role_pattern(terms), text, re.I)]
    cards = {}
    for f in candidates:
        a, b = f["start"], f["end"]
        require(type(a) is int and type(b) is int and 0 <= a < b <= len(text) and text[a:b] == f["quote"], "candidate_source_span")
        eligible = [(x, y, role) for x, y, role in anchors if 0 <= a-y <= 32
                    and re.fullmatch(r"[\s,:：，=＝|｜]*(?:(?:is|was|是|为)\s*)?", text[y:a], re.I)]
        if not eligible:
            continue
        nearest = max(y for _, y, _ in eligible)
        selected = [(x, role) for x, y, role in eligible if y == nearest]
        if len({role for _, role in selected}) != 1:
            continue
        x, role = selected[0]
        cards[(role, a, b)] = {"role": role, "source_id": source_id, "start": a, "end": b, "quote": text[a:b],
            "anchor_start": x, "anchor_end": nearest, "anchor_quote": text[x:nearest],
            "support_start": x, "support_end": b, "support_quote": text[x:b], "method": "stored_union_label_nearest_explicit_role"}
    pattern = role_pattern(aliases["status"])+r"\s*(?::|：|=|＝|\bis\b|\bwas\b|登记为|是|为)\s*(?P<value>[^。；;\r\n.!?！？]+)"
    for m in re.finditer(pattern, text, re.I):
        left, right = m.span("value")
        a = left+len(text[left:right])-len(text[left:right].lstrip())
        b = right-(len(text[left:right])-len(text[left:right].rstrip()))
        if a < b:
            cards[("status", a, b)] = {"role": "status", "source_id": source_id, "start": a, "end": b, "quote": text[a:b],
                "anchor_start": m.start(), "anchor_end": left, "anchor_quote": text[m.start():left],
                "support_start": m.start(), "support_end": b, "support_quote": text[m.start():b], "method": "explicit_status_field"}
    return sorted(cards.values(), key=lambda f: (f["start"], f["end"], f["role"]))


def source_binding(record, annotation, fact, source):
    """Bind exact origin, fact, public grant and label; never verify an HMAC."""
    text, sid = source["text"], source["source_id"]
    a, b = record["source_start"], record["source_end"]
    require(type(a) is int and type(b) is int and 0 <= a < b <= len(text) and record["text"] == text[a:b], "record_exact_source_slice")
    equal(record["source"], {"source_id": sid, "text": text, "sha256": sha(text)}, "record_full_origin")
    identity = {"source_id": sid, "source_sha256": sha(text), "source_start": a, "source_end": b, "content_sha256": sha(record["text"])}
    equal({k: annotation[k] for k in identity}, identity, "annotation_origin")
    equal(annotation["fact_key"], digest(identity), "annotation_fact_key")
    equal((annotation["fid"], fact["fid"], fact["source_start"], fact["source_end"], fact["text"]),
          (fact["fid"], annotation["fid"], a, b, record["text"]), "selected_fact_identity")
    require(annotation["status"] == annotation["group_status"] == "ok" and annotation["eligible_for_store"] is True, "undeployable_annotation")
    access, label = record["access"], record["label"]
    equal({k: access[k] for k in identity}, identity, "public_access_exact_origin")
    equal({k: label[k] for k in identity if k != "source_id"}, {k: v for k, v in identity.items() if k != "source_id"}, "public_label_exact_origin")
    require(record["source_id"] == record["record_id"] == access["record_id"] == label["record_id"] and record["status"] == label["status"] == "ok", "record_label_identity")
    equal(label["access_sha256"], digest(access), "label_access_binding")
    require(access["owner_id"] == "owner" and access["readers"] == ["owner"] and access["origin_agent_id"] == "source-agent"
            and access["allowed_agent_ids"] == ["target-agent"] and access["scope_version"] == "exact_fact_source_span_v1" and access["epoch"] == label["epoch"] == 0, "unexpected_grant_scope")
    for field in ("access_signature", "label_signature"):
        require(isinstance(record[field], str) and re.fullmatch(r"[a-f0-9]{64}", record[field]), "public_signature_shape")
    expected = {(f["start"], f["end"], f["category"]) for f in annotation["detection"]["findings"]}
    actual = {(f["start"], f["end"], f["category"]) for f in label["findings"]}
    equal(sorted(actual), sorted(expected), "stored_label_not_annotation")
    for f in label["findings"]:
        require(set(f) == {"start", "end", "category"} and type(f["start"]) is int and type(f["end"]) is int
                and 0 <= f["start"] < f["end"] <= len(record["text"]) and f["category"] == "CUSTOMER", "stored_label_bounds")
    return identity


def supported_records(card, records):
    """Value, anchor and support must fit one exact source fact, never a union."""
    bounds = [(card["start"], card["end"]), (card["support_start"], card["support_end"])]
    if "anchor_start" in card:
        bounds.append((card["anchor_start"], card["anchor_end"]))
    return [r["record_id"] for r in records if r["source"]["source_id"] == card["source_id"]
            and all(r["source_start"] <= a < b <= r["source_end"] for a, b in bounds)]


def score(predicted, references, roles):
    p = {(f["role"], f["start"], f["end"]) for f in predicted}
    t = {(f["role"], f["start"], f["end"]) for f in references}
    out = {"tp": len(p&t), "fp": len(p-t), "fn": len(t-p), "reference_count": len(t), "predicted_count": len(p),
           "per_role": {r: {"tp": sum(x[0] == r for x in p&t), "fp": sum(x[0] == r for x in p-t), "fn": sum(x[0] == r for x in t-p)} for r in roles}}
    out.update(precision=out["tp"]/len(p) if p else None, recall=out["tp"]/len(t) if t else None)
    return out


def replay(run, probe, reference_path):
    run, probe, reference_path = map(Path, (run, probe, reference_path))
    receipt = json.loads((run/"independent_verification.json").read_bytes())
    require(receipt["status"] == "passed" and receipt["registered_rows"] == 96, "prior_run_not_independently_checked")
    names = ("runtime", "record_store", "annotations", "builds", "pools", "report", "plan")
    values = {}
    for n in names:
        raw = (run/(n+".json")).read_bytes()
        equal(sha(raw), receipt["evidence_sha256"][n+".json"], "prior_checked_artifact_changed")
        values[n] = json.loads(raw)
    equal(sha((run/"request_transport.jsonl").read_bytes()), receipt["transport_sha256"], "historical_transport_changed")
    require(sha(reference_path.read_bytes()) == REFERENCE_SHA, "fixed_role_reference_changed")
    references = json.loads(reference_path.read_bytes())
    require(references["role_contract_version"] == "explicit_source_business_roles_v1", "role_contract")
    archived = probe/"implementation/scripts/probe_source_roles.py"
    probeplan = json.loads((probe/"plan.json").read_bytes())
    archived_hashes = {name.replace("\\", "/"): value for name, value in probeplan["implementation_sha256"].items()}
    equal(sha(archived.read_bytes()), archived_hashes["scripts/probe_source_roles.py"], "frozen_projection_source")
    aliases, roles = (_literal_assignment(archived, n) for n in ("ALIASES", "ROLES"))
    equal(probeplan["baseline"]["explicit_role_anchors"], aliases, "baseline_anchors_changed")
    require(probeplan["reference_sha256"] == REFERENCE_SHA, "baseline_reference_changed")
    sources = {s["story_id"]: s["source"] for s in values["runtime"]}
    stores = {s["story_id"]: s for s in values["record_store"]}
    builds = {s["story_id"]: s for s in values["builds"]}
    truth = {s["story_id"]: s for s in references["stories"]}
    annotations = {(a["story_id"], a["fact_index"]): a for a in values["annotations"]}
    require(len(sources) == len(stores) == len(builds) == len(truth) == 8 and set(sources) == set(stores) == set(builds) == set(truth), "source_record_matrix")
    expected_annotations = {(sid, i) for sid, b in builds.items() for i in range(len(b["facts"]))}
    require(set(annotations) == expected_annotations and len(annotations) == len(values["annotations"]), "annotation_matrix")
    rows, totals = [], {"source_only": [], "projectable": [], "projectable_reference": []}
    label_count = 0
    for sid, source in sources.items():
        bundle, build, ref = stores[sid]["records"], builds[sid], truth[sid]
        require(stores[sid]["builder"] == "union" and stores[sid]["union_label_set_status"] == build["status"] == "ok"
                and len(bundle) == len(build["facts"]), "common_construction_or_label_failure")
        equal((ref["source_id"], ref["source_sha256"]), (source["source_id"], sha(source["text"])), "reference_origin")
        for f in ref["annotations"]:
            require(f["source_id"] == source["source_id"] and source["text"][f["start"]:f["end"]] == f["quote"]
                    and source["text"][f["support_start"]:f["support_end"]] == f["support_quote"], "reference_source_slices")
        candidates = {}
        fact_receipts = []
        for i, (record, fact) in enumerate(zip(bundle, build["facts"])):
            annotation = annotations[(sid, i)]
            identity = source_binding(record, annotation, fact, source)
            fact_receipts.append({"record_id": record["record_id"], "fid": fact["fid"], "fact_key": digest(identity), **identity})
            label_count += len(record["label"]["findings"])
            for f in record["label"]["findings"]:
                a, b = record["source_start"]+f["start"], record["source_start"]+f["end"]
                key = a, b, f["category"]
                candidate = candidates.setdefault(key, {"source_id": source["source_id"], "source_sha256": sha(source["text"]), "start": a, "end": b,
                    "quote": source["text"][a:b], "category": f["category"], "origin_record_ids": [], "origin_fact_keys": []})
                candidate["origin_record_ids"].append(record["record_id"])
                candidate["origin_fact_keys"].append(digest(identity))
        cards = project(source["text"], source["source_id"], list(candidates.values()), aliases)
        for card in cards:
            card["source_sha256"] = sha(source["text"])
            card["supporting_record_ids"] = supported_records(card, bundle)
        projectable = [c for c in cards if c["supporting_record_ids"]]
        ref_projectable = [f for f in ref["annotations"] if supported_records(f, bundle)]
        # A scored match also needs the reference's factual support in that SAME
        # record, not one record for the value and another for its justification.
        truth_by_key = {(f["role"], f["start"], f["end"]): f for f in ref["annotations"]}
        for card in projectable:
            target = truth_by_key.get((card["role"], card["start"], card["end"]))
            if target:
                card["reference_supporting_record_ids"] = sorted(set(card["supporting_record_ids"]) & set(supported_records(target, bundle)))
                require(card["reference_supporting_record_ids"], "matched_card_reference_support_crosses_fact")
        cell = {"story_id": sid, "source_id": source["source_id"], "source_sha256": sha(source["text"]), "facts": fact_receipts,
                "stored_label_count": sum(len(r["label"]["findings"]) for r in bundle), "source_candidates": list(candidates.values()), "source_only_cards": cards,
                "projectable_cards": projectable, "reference_items": len(ref["annotations"]), "projectable_reference_items": len(ref_projectable),
                "source_only_score": score(cards, ref["annotations"], roles), "projectable_score": score(projectable, ref_projectable, roles)}
        rows.append(cell)
        # Include source identity to avoid collapsing equal strings or offsets
        # from independent sources into a single global experimental unit.
        for key, findings in (("source_only", cards), ("projectable", projectable), ("projectable_reference", ref_projectable)):
            totals[key].extend((sid, f["role"], f["start"], f["end"]) for f in findings)
    alltruth = {(sid, f["role"], f["start"], f["end"]) for sid, ref in truth.items() for f in ref["annotations"]}
    summary = {}
    for mode in ("source_only", "projectable"):
        predicted, expected = set(totals[mode]), alltruth if mode == "source_only" else set(totals["projectable_reference"])
        summary[mode] = {"tp": len(predicted&expected), "fp": len(predicted-expected), "fn": len(expected-predicted), "reference_items": len(expected), "predicted_items": len(predicted),
            "precision": len(predicted&expected)/len(predicted) if predicted else None, "recall": len(predicted&expected)/len(expected) if expected else None}
    events = [json.loads(line) for line in (run/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
    costs = []
    for stage in ("build", "write_annotation"):
        selected = [e for e in events if e["phase"] == "request" and e["stage"] == stage]
        responses = {e["index"]: e for e in events if e["phase"] == "response"}
        costs.append({"stage": stage, "historical_generation_calls": len(selected), "historical_encoder_calls": sum(x["inference_counts"]["local_encoder"] for x in (values["builds"] if stage == "build" else values["annotations"])),
            "prompt_tokens": sum(responses[e["index"]]["response"]["prompt_eval_count"] for e in selected), "output_tokens": sum(responses[e["index"]]["response"]["eval_count"] for e in selected)})
    return {"version": "stored_union_role_baseline_replay_v1", "status": "completed", "source_stories": 8, "reference_sha256": REFERENCE_SHA,
        "stored_label_count": label_count, "deduplicated_source_candidates": sum(len(r["source_candidates"]) for r in rows), "selected_exact_fact_records": sum(len(r["facts"]) for r in rows),
        "scores": summary, "rows": rows, "new_model_calls": 0, "historical_common_A_costs": costs,
        "weak_probe_baseline_historical_api_calls": 8, "role_projection_archive_sha256": sha(archived.read_bytes()),
        "inputs_sha256": {n+".json": receipt["evidence_sha256"][n+".json"] for n in names}, "prior_independent_receipt_sha256": sha((run/"independent_verification.json").read_bytes()),
        "script_sha256": sha(Path(__file__).read_bytes()), "scope": ["Stored-artifact replay only: public source/fact/grant/label hash bindings checked, HMAC authenticity and current revocation not revalidated.",
        "Source-only projection may consult the full original source; projectable cards require value, grammar anchor and support inside one exact selected fact.",
        "Role references enter scoring only, not candidate extraction. Privacy CUSTOMER labels can include public organizations; role projection does not change privacy or authority.",
        "Zero NEW inference does not make the original Union labeling free. Its original shared A-stage cost is shown separately.",
        "Exposed source role scoring is not downstream answering success, blind acceptance, native migration or novelty evidence."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=ROOT/"results/query_schema_transfer_development_20261025_v1")
    parser.add_argument("--probe", type=Path, default=ROOT/"results/source_role_probe_development_20261025_v1")
    parser.add_argument("--reference", type=Path, default=ROOT/"examples/privacy_semantics_v1/development/source_roles_reference_v1.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "new_result_path_required")
    result = replay(args.run, args.probe, args.reference)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
    print(json.dumps({k: result[k] for k in ("status", "scores", "stored_label_count", "selected_exact_fact_records", "historical_common_A_costs", "new_model_calls")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
