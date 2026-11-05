"""Supplementary blinded AI review packet; original EM/F1 remains unchanged."""
import hashlib
import json
from pathlib import Path
import random

from .eval_fusion import extract_answer
from experiments.revocation_grouping_v1.lifecycle_host import save

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]


def main():
    output=REPO/'results/memory_module_fusion_v1/semantic-blind-20261105-v1'
    output.mkdir(parents=True,exist_ok=False)
    cases={c['case_id']:c for c in [json.loads(line) for line in
        (HERE/'data_hotpot/cases.public.jsonl').read_text(encoding='utf-8').splitlines()]}
    roots=[REPO/'results/memory_module_fusion_v1'/name for name in
           ('hotpot-native-20261105-v2','hotpot-native-strong-20261105-v1')]
    groups,views={},{}
    for root in roots:
        for path in sorted((root/'rows').glob('*.json')):
            row=json.loads(path.read_text(encoding='utf-8'))
            case=cases[row['case_id']]
            allowed=tuple(sorted(row['allowed']))
            view_key=row['case_id'],allowed
            if view_key not in views:
                views[view_key]={'question':case['question'],
                    'all_current_authorized_sources':{s['source_id']:s['text'] for s in case['sources']
                                                      if s['source_id'] in allowed}}
            answer,parse=extract_answer(row['output'],row['case_id'])
            identity=(view_key,row['context_sha256'],str(answer).strip().casefold())
            groups.setdefault(identity,{'view_key':view_key,'answer':answer,'parse':parse,
                'delivered_context':row['context'],'selected_source_ids':row['selected'],'rows':[]})['rows'].append(str(path))
    rng=random.Random(2026110567)
    view_keys=list(views)
    rng.shuffle(view_keys)
    view_ids={key:f'V{i+1:02d}' for i,key in enumerate(view_keys)}
    items=list(groups.values())
    rng.shuffle(items)
    public=[]
    mapping=[]
    for number,item in enumerate(items,1):
        jid=f'J{number:03d}'
        public.append({'item_id':jid,'view_id':view_ids[item['view_key']],
            'answer':item['answer'],'delivered_context':item['delivered_context'],
            'selected_source_ids':item['selected_source_ids']})
        mapping.append({'item_id':jid,'raw_row_paths':item['rows']})
    save(output/'packet.json',{'scope':'supplementary AI source-grounded semantic audit; not human gold',
        'views':{view_ids[key]:value for key,value in views.items()},'items':public,
        'review_schema':{'item_id':'same ID','full_authorized_answerability':'yes/no/uncertain',
            'delivered_answerability':'yes/no/uncertain',
            'answer_assessment':'supported_correct / correct_but_unsupported / incorrect / unknown / unclear',
            'support_source_ids':'list from delivered context for supported answer',
            'reason':'brief source-grounded reasoning; no method/cost/gold lookup'},
        'method_names_costs_reference_answers_withheld':True,'human_gold':None})
    save(output/'mapping.private.json',{'items':mapping,'deduplicated_rows':sum(len(i['rows']) for i in items),
        'unique_items':len(items),'original_metrics_unchanged':True})
    print(json.dumps({'items':len(items),'rows':sum(len(i['rows']) for i in items),
        'views':len(views),'packet':str(output/'packet.json')}))


if __name__=='__main__':
    main()
