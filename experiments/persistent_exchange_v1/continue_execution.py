"""Monitor the first already-running phase, then finish all authorized phases.

No retry of unknown model dispatches. Cached jobs supervise their original IDs.
Progress is durable so stopping the supervisor never implies model cancellation.
"""
from __future__ import annotations
import json
from pathlib import Path
import time
from .run_study import (DEFAULT_ROOT, material, freeze, source_phase, withdraw,
                        deliver, receiver_phase, snapshot, load)
from .model_runtime import write_json, digest


def main():
    root=DEFAULT_ROOT.resolve()
    while True:
        progress=load(root/'initial_progress.json')
        if progress['finished']+progress['failed']>=progress['planned']:break
        snapshot(root/'pipeline_progress.json',{'phase':'waiting_original_initial_supervisor',
            'finished':progress['finished'],'monitor_failures':progress['failed'],'planned':progress['planned']})
        time.sleep(5)
    incident=root/'initial_original_supervisor_final.json'
    if not incident.exists():write_json(incident,progress)
    cases,contract=material();freeze(root,contract)
    snapshot(root/'pipeline_progress.json',{'phase':'recover_original_initial_tasks_no_redispatch'})
    source_phase(root,cases,'initial',4)
    snapshot(root/'pipeline_progress.json',{'phase':'withdraw_and_repair'})
    withdraw(root,cases);source_phase(root,cases,'repair',4)
    snapshot(root/'pipeline_progress.json',{'phase':'gateway_persistent_deliveries'})
    manifest=deliver(root,cases)
    snapshot(root/'pipeline_progress.json',{'phase':'real_receivers_after_reopen'})
    records=receiver_phase(root,manifest,4)
    snapshot(root/'pipeline_progress.json',{'phase':'two_real_multilayer_return_experiments'})
    from .run_mechanisms import run_mechanisms
    run_mechanisms(root,manifest,load(Path(__file__).parent/'data/evaluation_only.json'))
    snapshot(root/'pipeline_progress.json',{'phase':'independent_readback_ledger_and_evaluation'})
    from .finalize import finalize
    result=finalize(root)
    snapshot(root/'pipeline_progress.json',{'phase':'complete','main_records':len(records),
             'result_files':['audit_and_ledger.json','evaluation_with_payload.json','mechanisms/records.json']})
    print(json.dumps({'status':'complete','main_records':len(records)},ensure_ascii=False),flush=True)


if __name__=='__main__':main()
