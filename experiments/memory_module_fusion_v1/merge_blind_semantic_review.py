"""Supplementary consensus AI diagnostics; preserve all original benchmark scores."""
from collections import defaultdict
import json
from pathlib import Path

from experiments.revocation_grouping_v1.lifecycle_host import save

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]


def main():
    root=REPO/'results/memory_module_fusion_v1/semantic-blind-20261105-v1'
    packet=json.loads((root/'packet.json').read_text(encoding='utf-8'))
    mapping=json.loads((root/'mapping.private.json').read_text(encoding='utf-8'))
    expected={item['item_id'] for item in packet['items']}
    reviews=[]
    for name in ('a','b'):
        review=json.loads((root/f'review_{name}.json').read_text(encoding='utf-8'))
        rows=review['items']
        if {r['item_id'] for r in rows}!=expected or len(rows)!=len(expected):
            raise ValueError('incomplete_or_duplicate_blind_review')
        reviews.append({r['item_id']:r for r in rows})
    labels=json.loads((HERE/'data_hotpot/evaluation_only.json').read_text(encoding='utf-8'))
    out,arms= [],defaultdict(list)
    for item in mapping['items']:
        a,b=(review[item['item_id']] for review in reviews)
        consensus=a['answer_assessment']==b['answer_assessment']
        supported=all(r['answer_assessment']=='supported_correct' for r in (a,b))
        for path in item['raw_row_paths']:
            row=json.loads(Path(path).read_text(encoding='utf-8'))
            eligible=set(labels[row['case_id']]['support_ids'])<=set(row['allowed'])
            record={'item_id':item['item_id'],'row':path,'case_id':row['case_id'],'arm':row['arm'],
                'time':row['time'],'original_primary_eligible':eligible,
                'review_a':a,'review_b':b,'assessment_agreement':consensus,
                'consensus_supported_correct':supported,'human_gold':None}
            out.append(record)
            arms[row['arm']].append(record)
    summary={}
    for arm,rows in arms.items():
        primary=[r for r in rows if r['original_primary_eligible']]
        grouped=defaultdict(list)
        for row in primary:
            grouped[row['case_id']].append(row)
        summary[arm]={'all_views':len(rows),'primary_views':len(primary),'question_clusters':len(grouped),
            'consensus_supported_correct_primary':sum(r['consensus_supported_correct'] for r in primary),
            'consensus_supported_correct_all':sum(r['consensus_supported_correct'] for r in rows),
            'primary_disagreements':sum(not r['assessment_agreement'] for r in primary),
            'question_macro_consensus_supported_rate':sum(sum(r['consensus_supported_correct'] for r in rs)/len(rs)
                                                         for rs in grouped.values())/len(grouped)}
    result={'scope':'supplementary two-agent blinded consensus, not human gold or replacement EM/F1',
        'original_scores_unchanged':True,'human_gold':None,'unique_blind_items':len(expected),
        'original_rows':len(out),'unique_item_assessment_agreement':sum(reviews[0][i]['answer_assessment']==reviews[1][i]['answer_assessment'] for i in expected),
        'aggregate':summary}
    save(root/'consensus_rows.json',{'rows':out,'human_gold':None})
    save(root/'consensus_summary.json',result)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    main()
