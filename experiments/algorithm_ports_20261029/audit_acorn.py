"""Independent audit of captured native IDs against serialized original masks.

No native re-execution, model request, masking repair, or result modification.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/algorithm_ports_20261029/acorn_run01"


def main():
    payload = json.loads((OUT / "small/native/input.json").read_text(encoding="utf-8"))
    raw = json.loads((OUT / "small/native/output.json").read_text(encoding="utf-8"))
    labels = json.loads((OUT / "small/query_groups.json").read_text(encoding="utf-8"))
    result = {"status": "audited", "rows": [], "samples": [],
        "scope": "captured small dataset only; exact original permission bits, not sensitive data disclosure",
        "native_reexecution": 0, "model_calls": 0}
    for method in ("acorn", "hnsw_post", "hnsw_adaptive", "exact"):
        assert len(raw[method]) == len(payload["masks"]) == len(labels)
        for kind in ("all_allowed", "uniform_10percent", "farthest_10percent", "uniform_2percent"):
            illegal = duplicates = bad_queries = 0
            counters_match = True
            for qi, (row, mask, label) in enumerate(zip(raw[method], payload["masks"], labels)):
                if label["filter"] != kind:
                    continue
                assert all(type(i) is int and -1 <= i < len(mask) for i in row["ids"])
                positive = [i for i in row["ids"] if i >= 0]
                bad = [i for i in positive if mask[i] != 1]
                dup = len(positive) - len(set(positive))
                illegal += len(bad)
                duplicates += dup
                bad_queries += bool(bad)
                counters_match &= len(bad) == row["illegal_result_count"] and dup == row["duplicate_id_count"]
                if bad:
                    result["samples"].append({"method": method, "query": qi, "filter": kind,
                        "out_of_mask_ids": bad, "original_bits": [mask[i] for i in bad]})
            result["rows"].append({"method": method, "filter": kind,
                "independent_out_of_mask_positions": illegal,
                "independent_out_of_mask_queries": bad_queries,
                "independent_duplicates": duplicates, "matches_native_counter": counters_match})
    assert all(row["matches_native_counter"] for row in result["rows"]), "native counter disagrees with original mask"
    result["acorn_out_of_mask_positions"] = sum(r["independent_out_of_mask_positions"] for r in result["rows"] if r["method"] == "acorn")
    result["acorn_out_of_mask_queries"] = sum(r["independent_out_of_mask_queries"] for r in result["rows"] if r["method"] == "acorn")
    result["other_methods_out_of_mask_positions"] = sum(r["independent_out_of_mask_positions"] for r in result["rows"] if r["method"] != "acorn")
    target = OUT / "independent_mask_audit.json"
    assert not target.exists(), "do not overwrite audit"
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in {"rows", "samples"}}))


if __name__ == "__main__":
    main()
