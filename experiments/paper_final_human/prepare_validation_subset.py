"""Prepare 48 blank human validation items, never copy AI recommendations in."""
import csv
import importlib.util
import json
import random
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HUMAN=ROOT/'research_paper_v1/paper_final/evidence/human'
OUT=ROOT/'research_paper_v1/paper_final/evidence/ai_evaluation/human_validation_subset'


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'selection.json').exists():raise SystemExit('Existing validation subset preserved; use a new version rather than overwrite.')
    spec=importlib.util.spec_from_file_location('prepare_human',Path(__file__).with_name('prepare.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original=json.loads((HUMAN/'items.blinded.json').read_text(encoding='utf-8'))
    mapping=json.loads((HUMAN/'private_unblinding_key.json').read_text(encoding='utf-8'))['key']
    rng=random.Random(2026110604);selected=[]
    projects=sorted({m['case_id'] for m in mapping.values()})
    for project in projects:
        for arm in ('raw','whole_drop','full_rebuild','selective'):
            options=[q for q in original['items'] if mapping[q['item_id']]['case_id']==project and mapping[q['item_id']]['arm']==arm]
            selected.append(rng.choice(options))
    assert len(selected)==48
    for slot in (1,2):
        rows=selected.copy();random.Random(2026110604+slot).shuffle(rows)
        data={**original,'items':rows,'rater_slot':100+slot,'fields':module.FIELDS,'labels':module.LABELS}
        text=module.HTML.replace('__DATA__',json.dumps(data,ensure_ascii=False).replace('<','\\u003c'))
        text=text.replace('共768题','共48题').replace('max="768"','max="48"').replace('Math.min(767,','Math.min(47,')
        (OUT/f'validation_rater_{slot}.html').write_text(text,encoding='utf-8')
        with (OUT/f'validation_rater_{slot}_blank.csv').open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=module.FIELDS);w.writeheader()
            for q in rows:w.writerow({'item_id':q['item_id']})
    (OUT/'selection.json').write_text(json.dumps({'schema':'human-validation-subset-v1','date_local':'2026-11-06','items':48,'selection':'one uniformly selected question within each project-by-method stratum (12×4); fixed before human ratings; AI results already available so not retrospective preregistration','seed':2026110604,'item_ids':[q['item_id'] for q in selected],'human_raters_completed':0,'AI_recommendations_shown':False,'human_confirmed':False},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Prepared 48 blank items per human rater, method masked, no AI recommendations displayed.')


if __name__=='__main__':main()
