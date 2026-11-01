"""Read-only stdlib reaggregation of saved observations and fixed AI labels."""
from pathlib import Path
from collections import Counter
from decimal import Decimal
import hashlib,json,math,re

ROOT=Path(__file__).resolve().parent
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8'))
def sha(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()
def need(ok,reason):
    if not ok:raise ValueError(reason)

def select(sources,questions):
    tokens=lambda s:re.findall(r'[^\W_]+',s.lower(),re.UNICODE)
    frequency=[Counter(tokens(s['text'])) for s in sources]
    lengths=[sum(f.values()) for f in frequency];average=sum(lengths)/3
    df=Counter(t for f in frequency for t in f);scores=[0.0]*3
    for question in questions:
        for term,count in Counter(tokens(question['question'])).items():
            for i,counts in enumerate(frequency):
                tf=counts.get(term,0)
                if tf:scores[i]+=count*math.log1p((3-df[term]+.5)/(df[term]+.5))*tf*2.2/(tf+1.2*(.25+.75*lengths[i]/average))
    rank=sorted(range(3),key=lambda i:(-scores[i],sources[i]['source_id']))[:2]
    return [s['source_id'] for i,s in enumerate(sources) if i in rank]

def main():
    manifest=read('manifest.json')
    for name,expected in manifest['files'].items():
        p=ROOT/name;need(p.resolve().is_relative_to(ROOT),'unsafe_path')
        need(hashlib.sha256(p.read_bytes()).hexdigest()==expected,'file_changed:'+name)
    data=read('experiment.json');positions=data['positions'];cases={c['case_id']:c for c in data['cases']}
    need(len(cases)==5 and len(positions)==10,'wrong_denominator')
    by_slot={p['slot']:p for p in positions};usage=Counter();counts={};bytes_by_arm={}
    for p in positions:
        case=cases[p['case_id']];legal=case['sources'][1:]
        selected=['S02','S03','S04'] if p['arm']=='raw_legal_S02_S04' else select(legal,case['questions'])
        need(selected==p['selected_content_source_ids'],'selector_changed')
        memory='# Authorized task evidence\n\n'+'\n\n'.join('['+s['source_id']+']\n'+s['text'] for s in legal if s['source_id'] in selected)+'\n'
        need(memory==p['memory'] and sha(memory)==p['memory_sha256']==p['loaded_memory_sha256'],'actual_memory_binding')
        need(p['registered_input_source_ids']==['S02','S03','S04'],'index_dependency_changed')
        need(p['status']=='ok' and p['invocation_started'] and p['native_instruction_loaded'],'native_result_unqualified')
        need(json.loads(p['raw_response'])==p['answers'] and len(p['answers'])==3,'answer_binding')
        for event in p['assistant_usage_events']:
            u=event['usage'];need(u['totalTokens']==sum(u[k] for k in ('inputTokens','cacheReadTokens','cacheWriteTokens','outputTokens')),'token_conservation')
            usage.update(u)
        g=p['guard_counts'];need(g['allowed_stream_count']==1 and len(g['requests'])==1,'guard_counts')
        request=g['requests'][0];need(request['memory_sha256']==sha(memory) and request['memory_bytes']==len(memory.encode()),'guard_memory')
        bytes_by_arm.setdefault(p['arm'],{'calls':0,'memory_bytes':0,'request_bytes':0,'seconds':Decimal(0)})
        a=bytes_by_arm[p['arm']];a['calls']+=1;a['memory_bytes']+=len(memory.encode());a['request_bytes']+=request['bytes'];a['seconds']+=Decimal(str(p['elapsed_seconds']))
    need(dict(usage)==data['usage_totals'],'usage_totals')
    estimate=(sum(usage[k] for k in ('inputTokens','cacheReadTokens','cacheWriteTokens'))*Decimal(4)+usage['outputTokens']*Decimal(8))/1000000
    need(estimate==Decimal(data['conservative_estimate_cny']),'estimate_changed')
    seen=set();quote_count=0
    for row in data['ai_review_rows']:
        key=(row['slot'],row['question_id']);need(key not in seen,'duplicate_review');seen.add(key)
        p=by_slot[row['slot']];i=next(i for i,q in enumerate(p['questions']) if q['question_id']==row['question_id'])
        need(row['answer']==p['answers'][i] and row['answer_sha256']==sha(row['answer']),'review_answer_binding')
        section='legal' if i<2 else 'controls';counts.setdefault(p['arm'],{'legal':Counter(),'controls':Counter()})[section][row['classification']]+=1
        sources={s['source_id']:s['text'] for s in cases[p['case_id']]['sources']}
        for q in row['source_quotes']:
            need(q['quote'] in sources[q['source_id']] and sha(q['quote'])==q['quote_sha256'],'quote_binding')
            need(q['in_actual_payload']==(q['quote'] in p['memory']),'quote_payload_binding');quote_count+=1
    need(len(seen)==30,'review_inventory')
    for arm,c in counts.items():
        expected=data['ai_review_summary'][arm]
        need(sum(c['legal'].values())==10 and sum(c['controls'].values())==5,'arm_denominators')
        need(dict(c['legal'])==expected['legal_classifications'] and dict(c['controls'])==expected['control_classifications'],'review_count_changed')
    assisted=read('paired_assisted_labels.json')['rows'];need(len(assisted)==60,'assisted_inventory')
    axes=('legal_context_answerability','payload_support','answer_quality','explicit_refusal')
    agreement={axis:sum(r['A'][axis]==r['B'][axis] for r in assisted) for axis in axes}
    need(agreement==read('assisted_review_summary.json')['diagnostic_axis_exact_agreement_counts'],'assisted_counts')
    bridge=read('workbuddy_handoff.json')
    need(bridge['sender']['agent_id']=='workbuddy' and bridge['audience']['agent_id']=='deepseek-harness','workbuddy_principals')
    need(sha(bridge['memory'])==bridge['memory_sha256']==bridge['actual_loaded_memory_sha256'],'workbuddy_loaded_memory')
    need(bridge['state_after']['S01']['export_allowed'] is False
         and bridge['state_after']['S01']['source_read']=='allow'
         and bridge['state_after']['M']['export_allowed'] is False
         and bridge['state_after']['R']['export_allowed'] is True,'workbuddy_revocation_replay')
    need(set(bridge['revocation_errors'])=={'old_mixed_packet_validate','new_mixed_export'},'old_package_rejection')
    need(bridge['target_status']=='ok' and bridge['answers'][0]=='Penang' and bridge['answers'][2]=='UNKNOWN'
         and bridge['registered_withdrawn_value_matches']==[],'workbuddy_target_result')
    need(bridge['usage']['totalTokens']==708 and sum(bridge['usage'][k] for k in ('inputTokens','cacheReadTokens','cacheWriteTokens','outputTokens'))==708,'bridge_usage')
    print(json.dumps({'status':'reproduced','harness_calls':10,'development_stories':5,'fixed_AI_classifications':counts,
        'verified_source_quotes':quote_count,'usage':usage,'conservative_estimate_cny':str(estimate),
        'assisted_label_matches_not_human_reliability':agreement,'human_gold':False,
        'separate_workbuddy_handoff_calls':1,'workbuddy_source_capture':'user_forwarded_not_native_automatic',
        'scope':'Offline reconstruction and fixed-label arithmetic; no live model rerun, human truth, supplier invoice or new-method claim.'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
