"""Frozen zero-model candidate coverage diagnostic, never detector acceptance."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/"scripts"))
from memory_migration_study.open_container_candidates import propose_open_container_candidates, validate_open_container_candidates, VERSION
from verify_candidate_decision_diagnostic import _archive


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path,value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+"\n",encoding="utf-8",newline="\n")


def keys(rows):
    return {(r["source_id"],r["start"],r["end"],r["category"]) for r in rows}


def run(output,*,flat,archive):
    output=Path(output).resolve();flat=Path(flat).resolve()
    if output.exists() or not output.is_relative_to((ROOT/"results").resolve()):
        raise ValueError("new_results_required")
    blobs,_,_,_,_=_archive(Path(archive))
    closed=json.loads((flat/"model_phase_closed.json").read_bytes())
    if closed.get("model_phase_closed") is not True:
        raise ValueError("parent_not_closed")
    for name,expected in closed["artifact_sha256"].items():
        if sha(flat/name)!=expected:raise ValueError("parent_changed")
    material={r["case_id"]:r for r in json.loads((flat/"materials.json").read_bytes())}
    cases=[]
    for split in ("development","heldout"):
        raw=blobs[split+"/runtime.json"]
        if (flat/split/"runtime.json").read_bytes()!=raw:raise ValueError("parent_corpus_changed")
        cases += [r|{"split":split} for r in json.loads(raw)]
    if len(cases)!=120 or len(material)!=120:raise ValueError("parent_count_changed")
    frozen={f:sha(ROOT/f) for f in ("memory_migration_study/open_container_candidates.py","memory_migration_study/candidate_proposals.py",
             "memory_migration_study/privacy.py","scripts/run_open_container_diagnostic.py")}
    output.mkdir(parents=True)
    for name in ("materials.json","model_phase_closed.json"):
        (output/("parent_"+name)).write_bytes((flat/name).read_bytes())
    plan={"version":VERSION,"scope":"old 80 development + 40 exposed regression; grammar candidates only",
          "parent_files":{n:sha(flat/n) for n in ("materials.json","model_phase_closed.json")},
          "fixed_archive_sha256":sha(archive),"implementation_sha256":frozen,
          "materials":120,"new_model_calls":0,"default_changed":False,"semantic_atomicity_proven":False}
    save(output/"plan.json",plan)
    rows=[];network=[]
    def deny(*_args,**_kwargs):
        network.append("blocked")
        raise AssertionError("zero_model_offline_only")
    with patch.object(socket.socket,"connect",deny),patch.object(socket,"create_connection",deny):
        for case in cases:
            before=material[case["case_id"]]
            payload,policy=case["payload"],case["policy"]
            baseline=before["boundary_baseline"]
            result=propose_open_container_candidates(payload,policy,baseline["findings"])
            validate_open_container_candidates(payload,policy,baseline["findings"],result)
            rows.append({"case_id":case["case_id"],"split":case["split"],"language":case["language"],
                         "baseline":baseline,"prior_pool":before["boundary_pool"],"proposals":result})
    save(output/"unscored_rows.json",rows)
    save(output/"proposal_phase_closed.json",{"closed":True,"rows_sha256":sha(output/"unscored_rows.json"),
         "new_model_calls":0,"network_attempts":len(network),"implementation_unchanged":all(sha(ROOT/n)==h for n,h in frozen.items())})
    gold={}
    for split in ("development","heldout"):
        gold.update(json.loads(blobs[split+"/evaluation.json"]))
    for row in rows:
        expected=keys(gold[row["case_id"]]["findings"])
        # Candidate types are optional prior hints. Coverage means the exact
        # source interval is represented, not that classification is correct.
        prior_spans={(r["source_id"],r["start"],r["end"]) for r in row["prior_pool"]["candidates"]}
        prior={g for g in expected if g[:3] in prior_spans}
        proposals=keys(row["proposals"]["completions"])
        qualified=proposals if row["proposals"]["status"]=="candidates_only" and row["proposals"]["complete"] else set()
        new_proposals={p for p in proposals if p[:3] not in prior_spans}
        row["coverage"]={"gold_spans":len(expected),"prior_pool_covered":len(expected&prior),
          "all_proposal_union_covered":len(expected&(prior|proposals)),"fully_qualified_union_covered":len(expected&(prior|qualified)),
          "new_exact_gold_candidates":len(new_proposals&expected),"new_nongold_candidates":len(new_proposals-expected),
          "total_completion_candidates":len(proposals),"baseline_findings_changed":False}
    save(output/"rows.json",rows)
    summary={}
    for split in ("development","heldout"):
        selected=[r for r in rows if r["split"]==split]
        summary[split]={"materials":len(selected),"statuses":dict(Counter(r["proposals"]["status"] for r in selected)),
                       **{k:sum(r["coverage"][k] for r in selected) for k in rows[0]["coverage"] if k!="baseline_findings_changed"},
                       "errors":dict(Counter(e for r in selected for e in r["proposals"]["errors"]))}
    report={"version":VERSION,"summary":summary,"new_model_calls":0,"new_encoder_calls":0,"cloud_calls":0,"new_api_cost_cny":0,
      "network_attempts":len(network),"default_changed":False,"final_detection_unchanged":True,"independent_acceptance":False,
      "semantic_atomicity_proven":False,"implementation_unchanged":all(sha(ROOT/n)==h for n,h in frozen.items()),
      "scope":"candidate representation coverage only; not privacy recall, precision, legal QA, native transfer or novelty"}
    save(output/"report.json",report)
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--flat",type=Path,default=ROOT/"results/flat_candidate_detection_20261026_v1")
    parser.add_argument("--archive",type=Path,default=ROOT/"benchmarks/artifacts/context_candidate_detection_20261026_v2.zip")
    args=parser.parse_args()
    print(json.dumps(run(args.output,flat=args.flat,archive=args.archive),ensure_ascii=False))
