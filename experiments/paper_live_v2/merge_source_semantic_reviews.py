"""Merge three actually read partitions without rewriting individual reasons."""
import hashlib
import json
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/source_evaluation'
FILES=('semantic_review_p01_p03.jsonl','semantic_review_p04_p06.jsonl','semantic_review_p07_p10.jsonl')


def key(r):return r['case_id'],r['phase'],r['scenario']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def reason(r):
    return r.get('review_reason',r.get('text_specific_semantic_review',r.get('public_relation_and_rule_check')))


def main():
    canonical={key(r):r for r in [json.loads(l) for l in (OUT/'source_slots.jsonl').read_text(encoding='utf-8').splitlines()]}
    assert len(canonical)==360
    combined={};versions={};partitions=[]
    for name in FILES:
        path=OUT/name;versions[name]=sha(path);records=[json.loads(l) for l in path.read_text(encoding='utf-8').splitlines()]
        for index,r in enumerate(records,1):
            k=key(r);assert k not in combined,k;assert k in canonical,k;original=canonical[k]
            memory_sha=r.get('source_memory_sha256',r.get('memory_sha256',r.get('rawMemorySHA')))
            assert memory_sha==hashlib.sha256(original['memory_text'].encode('utf-8')).hexdigest(),k
            assert r['judge']=='AI' and r['human_confirmed'] is False
            support=r['asserted_facts_supported'];assert support is True or support is False or support=='unknown'
            derived=r.get('explicit_derived_conclusion_present',r.get('explicit_derived_conclusion_stated',r.get('derived_result_explicit')))
            assert isinstance(derived,bool)
            assert r['omitted_requested_derived_result']==(not derived)
            omissions=r['omitted_required_input_facts'];assert isinstance(omissions,list)
            review_reason=reason(r);assert isinstance(review_reason,str) and review_reason.strip()
            combined[k]={'case_id':r['case_id'],'project_id':r['project_id'],'direction':r['direction'],'repeat_index':r['repeat_index'],
                'phase':r['phase'],'scenario':r['scenario'],'memory_sha256':memory_sha,'rawMemorySHA':memory_sha,
                'source_platform':original['source_platform'],'observed_source_model':original['observed_source_model'],
                'judge':'AI','same_family_AI':True,'human_confirmed':False,'asserted_facts_supported':support,
                'review_reason':review_reason,'omitted_required_input_facts':omissions,
                'detected_input_omission':bool(omissions),
                'input_omission_check_scope':r.get('input_completeness_scope',r.get('omission_check_scope',r.get('review_scope'))),
                'derived_result_explicit':derived,'omitted_requested_derived_result':not derived,
                'ambiguous_wording':r['ambiguous_wording'],'unsupported_or_wrong_claims':r['unsupported_or_wrong_claims'],
                'source_review_file':str(path),'source_review_file_sha256':versions[name],'source_review_record_index':index,
                'source_evidence_paths':original['evidence_paths'],'original_review':r,
                'new_commercial_model_calls':0}
        assert sha(path)==versions[name],'Concurrent source-review changes; repeat a consistent snapshot'
        partitions.append({'file':name,'rows':len(records),'sha256':versions[name],
            'support_judgments':dict(Counter('supported' if r['asserted_facts_supported'] is True else 'contradicted' if r['asserted_facts_supported'] is False else 'unknown' for r in records)),
            'omission_scope_note':'Different reviewers explicitly recorded scopes; not independently calibrated for an interchangeable exhaustive completeness threshold.'})
    assert set(combined)==set(canonical),'Every real text must be reviewed exactly once'
    rows=[combined[k] for k in sorted(combined)]
    supported=sum(r['asserted_facts_supported'] is True for r in rows);contradicted=sum(r['asserted_facts_supported'] is False for r in rows);unknown=sum(r['asserted_facts_supported']=='unknown' for r in rows)
    grouping={}
    for phase in ('initial_generation','legal_rebuild'):
        for scenario in ('raw','summary','multi_source'):
            subset=[r for r in rows if r['phase']==phase and r['scenario']==scenario]
            grouping[phase+'.'+scenario]={'text_count':len(subset),'supported':sum(r['asserted_facts_supported'] is True for r in subset),
                'contradicted':sum(r['asserted_facts_supported'] is False for r in subset),'unknown':sum(r['asserted_facts_supported']=='unknown' for r in subset),
                'at_least_texts_with_detected_input_omissions':sum(r['detected_input_omission'] for r in subset),
                'explicit_derived_conclusion_texts':sum(r['derived_result_explicit'] for r in subset),
                'requested_derived_conclusion_not_explicit':sum(r['omitted_requested_derived_result'] for r in subset)}
    details=[{'case_id':r['case_id'],'phase':r['phase'],'scenario':r['scenario'],'asserted_facts_supported':r['asserted_facts_supported'],
        'reason':r['review_reason'],'unsupported_or_wrong_claims':r['unsupported_or_wrong_claims'],'ambiguous_wording':r['ambiguous_wording']} for r in rows if r['asserted_facts_supported'] is not True]
    summary={'schema':'live-v2-full-source-text-semantic-review-v1','snapshot_utc':datetime.now(timezone.utc).isoformat(),
        'actual_contextually_reviewed_source_texts':len(rows),'expected_source_texts':360,'exactly_once_complete':True,
        'all_memory_hashes_match_real_source_outputs':True,'independent_project_units':10,
        'AI_review_design':'Three same-family Codex workers each actually read disjoint project partitions and the frozen input/gold. One review per source text; not three independent ratings per text. No external paid judge or human reviewer was run.',
        'text_level_asserted_fact_consistency':{'supported':supported,'contradicted':contradicted,'unknown':unknown},
        'at_least_texts_with_detected_input_omissions':sum(r['detected_input_omission'] for r in rows),
        'omission_inference_scope':'At least this many texts have documented input-fact omissions. Do not compute a purported exhaustive unified completeness rate from different reviewers\' recorded scopes. Missing requested derived results are separate from input-fact omissions.',
        'explicit_derived_conclusion_texts':sum(r['derived_result_explicit'] for r in rows),
        'requested_derived_conclusion_not_explicit':sum(r['omitted_requested_derived_result'] for r in rows),
        'groups':grouping,'non_supported_or_uncertain_cases':details,'source_partitions':partitions,
        'human_confirmed':0,'new_commercial_model_calls':0,
        'metric_boundary':'Text-level controlled-input consistency, not atomic-fact precision/recall, necessary causal support, human gold or universal factual accuracy. These are descriptive nested observations, not 360 independent projects.',
        'script_sha256':sha(Path(__file__))}
    all_path=OUT/'semantic_review_all.jsonl';all_path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
    summary['merged_review_sha256']=sha(all_path)
    (OUT/'semantic_review_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'groups','non_supported_or_uncertain_cases','source_partitions'}},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
