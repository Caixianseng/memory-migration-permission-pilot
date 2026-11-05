"""Audit a completed-but-truncated SDK attempt without retrying the model.

The original failure receipt and reservation are preserved. A max-token stop
has known actual usage even though the strict adapter cannot approve memory.
Only explicit noncredential audit artifacts are opened, never the SDK home.
"""
from __future__ import annotations
import json
import re
from decimal import Decimal
from pathlib import Path
from .model_runtime import digest, write_json
from experiments.revocation_grouping_v1.sdk_adapter import (encoded, dispatch_text, usage_costs,
                                                            normalize_usage, MODEL)


def inspect_failure(job_dir,job_id,expected_user,max_tokens):
    if not isinstance(job_id,str)or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}',job_id):
        raise RuntimeError('failed_attempt_invalid_job_id')
    folder=Path(job_dir)/'sdk.private'/('job-'+job_id)
    if folder.resolve()!=folder.absolute()or any(p.is_symlink()for p in (folder,folder.parent)):
        raise RuntimeError('failed_attempt_symlink_path_rejected')
    receipt=json.loads((folder/'receipt.json').read_bytes())
    if receipt.get('status')!='failed':raise RuntimeError('failure_audit_requires_original_failed_receipt')
    inputs=json.loads((folder/'input.json').read_bytes());messages=inputs['messages']
    if len(messages)!=2 or messages[1].get('content')!=expected_user:raise RuntimeError('failed_attempt_business_inputs_changed')
    prompt=dispatch_text(messages)
    if inputs['dispatch_sha256']!=digest(prompt)or inputs['business_messages_sha256']!=digest(encoded(messages)):
        raise RuntimeError('failed_attempt_input_hash_mismatch')
    guard=json.loads((folder/'guard.json').read_bytes())
    evidence={'platform':'Harness official SDK','actual_model':None,'receipt':receipt,
        'model_attempt_closed':True,'source_protocol_conformance':False,
        'protocol_issues':['supplier_response_not_approved_no_auto_retry'],
        'messages':messages,'artifact_sha256':None,'physical_supplier_calls':None,
        'original_failed_receipt_sha256':digest((folder/'receipt.json').read_bytes()),
        'guard_counts':{k:guard.get(k)for k in ('agent_attempt_count','stream_attempt_count','allowed_stream_count')},
        'protocol_failure_action':'fail closed; keep original reservation; no new request'}
    response=folder/'response.json';partial=None
    if response.exists():
        summary=json.loads(response.read_bytes())
        source=summary.get('final_assistant_source')or{}
        if (summary.get('last_terminal_reason')=={'kind':'max-tokens'}
            and summary.get('final_assistant_interrupted')is False
            and source.get('provider')=='deepseek-account'and source.get('model')==MODEL):
            counts=[guard.get(k)for k in ('agent_attempt_count','stream_attempt_count','allowed_stream_count')]
            requests=guard.get('requests',[])
            if counts!=[1,1,1]or guard.get('reject_code')is not None or len(requests)!=1:
                raise RuntimeError('failed_attempt_guard_not_single_request')
            request=requests[0];raw=(folder/'actual_request.json').read_bytes()
            if (digest(raw)!=request['bodyhash']or len(raw)!=request['bytes']
                or request['business_input_sha256']!=digest(prompt)):
                raise RuntimeError('failed_attempt_request_binding_mismatch')
            usage_events=summary.get('assistant_usage_events')or[]
            if len(usage_events)!=1:raise RuntimeError('failed_attempt_usage_events_not_unique')
            usage=usage_events[0]['usage'];tokens,peak,cache=usage_costs(usage)
            reservation=json.loads((folder/'reservation.json').read_bytes())
            if not(0<tokens['output_tokens']<=max_tokens==reservation['max_tokens']
                   and 0<tokens['input_total_tokens']<=len(raw)+2048
                   and tokens['input_total_tokens']<=reservation['input_token_bound']
                   and peak<=Decimal(reservation['reservation_cny'])):
                raise RuntimeError('failed_attempt_usage_budget_mismatch')
            partial=summary.get('final_assistant_text')
            if not isinstance(partial,str):raise RuntimeError('failed_attempt_partial_output_missing')
            recovered={'status':'max_tokens_closed','actual_model':MODEL,'provider':'deepseek-account',
                'completed':False,'usage':usage,'physical_request_count':1,
                'input_total_tokens':tokens['input_total_tokens'],'input_uncached_tokens':tokens['input_uncached_tokens'],
                'cache_read_tokens':tokens['cache_read_tokens'],'cache_write_tokens':tokens['cache_write_tokens'],
                'output_tokens':tokens['output_tokens'],'estimated_peak_cost_cny':str(peak),
                'estimated_cache_aware_peak_cost_cny':str(cache)if cache is not None else None,
                'cost_is_supplier_bill':False,'request_sha256':digest(raw),'response_sha256':digest(partial),
                'business_messages_sha256':digest(encoded(messages)),'dispatch_sha256':digest(prompt),
                'original_failed_receipt_sha256':evidence['original_failed_receipt_sha256'],
                'original_reservation_sha256':digest((folder/'reservation.json').read_bytes()),
                'original_reservation_cny':reservation['reservation_cny'],'original_input_token_bound':reservation['input_token_bound'],
                'original_failure_and_reservation_preserved':True,'automatic_retry':False}
            evidence.update(actual_model=MODEL,receipt=recovered,physical_supplier_calls=1,
                partial_output_sha256=digest(partial),protocol_issues=['source_output_token_budget_exhausted'],
                original_terminal_reason={'kind':'max-tokens'})
    audit=Path(job_dir)/'failed_completion_audit.json'
    if not audit.exists():write_json(audit,{'evidence':evidence,'partial_model_output':partial,
                                          'usable_generated_memory':False})
    return evidence,partial
