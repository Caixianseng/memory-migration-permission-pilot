"""Capture selected read-only evidence and line anchors; never replay old runs."""
import collections
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'research_paper_v1/stage3_research_pivot/evidence'
PUBLIC=ROOT/'benchmarks/persistent_exchange_v1_public_20261105'
FILES={
 'experiments/persistent_exchange_v1/store.py':['class AgentStore','def add_memory','def retrieve','class TrustedPolicy','def set_permissions','def check_dependencies','def export_package','def import_package','BEGIN IMMEDIATE','consumed_by'],
 'experiments/persistent_exchange_v1/model_runtime.py':['def call_gateway','def native_evidence','def run_workbuddy','source_remote_request_bytes_observed','Only status reads','submission_intent'],
 'experiments/persistent_exchange_v1/source_registry.py':['def _pair','recovery_for_existing_generated_memory_forbidden','recovery_sources_json_bytes_changed','def '],
 'experiments/persistent_exchange_v1/read_receiver.py':['Authorization is checked at import','QUERIES =','def read_batch'],
 'experiments/persistent_exchange_v1/receiver_runtime.py':['def _verify_readback','def _control_command','not OS confinement'],
 'experiments/persistent_exchange_v1/receiver_paid_runtime.py':['It has no','def _qualification','toolCallCount'],
 'experiments/revocation_grouping_v1/sdk_adapter.py':['class FlashSDKClient','def ','timeout','model'],
 'experiments/paper_v1/stage2_evidence_gap/runner.py':['def eligible_operations','def run_method','current_read_policy','SELECT receipt','BEGIN IMMEDIATE']}


def load(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
 OUT.mkdir(parents=True,exist_ok=True)
 manifest=[]
 for rel,needles in FILES.items():
  path=ROOT/rel;lines=path.read_text(encoding='utf-8').splitlines()
  anchors={n:[i for i,l in enumerate(lines,1) if n in l] for n in needles}
  manifest.append({'path':rel,'sha256':sha(path),'lines':len(lines),'anchors':anchors})
 attempts=load(PUBLIC/'source_attempts.public.json')
 summary=load(PUBLIC/'audit_summary.public.json')
 records=load(PUBLIC/'records.public.json')
 evidence={'schema':'stage3-existing-evidence-capture-v1','date':'2026-11-05',
  'scope':'Read-only public projection plus owning code; no native execution replay or private credential access.',
  'source_status_counts':dict(collections.Counter(r['source_attempt_status'] for r in attempts)),
  'source_protocol_audit':summary['source_protocol_audit'],
  'source_recovery_registry':summary['source_recovery_registry'],
  'receiver_recovery':summary['receiver_recovery'],
  'direction_counts':dict(collections.Counter(r['direction'] for r in records)),
  'historical_copy_probe_summary':load(PUBLIC/'security_probes.public.json')['summary'],
  'code_anchors':manifest,
  'historical_inputs':[{'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p)} for p in
    [PUBLIC/n for n in ('source_attempts.public.json','audit_summary.public.json','records.public.json','security_probes.public.json')]],
  'new_model_calls':0,'historical_runs_repeated':0}
 target=OUT/'existing_evidence_capture.json'
 with target.open('x',encoding='utf-8') as f:json.dump(evidence,f,ensure_ascii=False,indent=2)
 print(json.dumps({'source_status_counts':evidence['source_status_counts'],'directions':evidence['direction_counts'],'code_files':len(manifest),'new_model_calls':0}))


if __name__=='__main__':main()
