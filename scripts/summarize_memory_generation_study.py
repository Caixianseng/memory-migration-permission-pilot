"""Publish aggregate-only evidence from a frozen local generation-label study."""
import argparse
import hashlib
import json
from pathlib import Path


def export(root, destination):
    root=Path(root)
    read=lambda p:json.loads(p.read_text(encoding='utf-8'))
    report,plan,rows=read(root/'report.json'),read(root/'plan.json'),read(root/'rows.json')
    extraction=[]
    for split in ('all','dev','heldout'):
        selected=[r for r in report['extraction_per_story'] if split=='all' or r['split']==split]
        extraction.append({'split':split,'stories':len(selected),**{k:sum(r[k] for r in selected) for k in
            ('source_sensitive_characters','retained_sensitive_characters','missing_extraction_sensitive_characters',
             'fully_retained_source_spans','partially_retained_source_spans','missing_source_spans')}})
    paired=[]
    for split in ('all','heldout'):
        lookup={(r['task_id'],r['mode']):r for r in rows if (split=='all' or r['split']==split) and r['score']['authorized']}
        tasks=sorted({t for t,m in lookup})
        for challenger in ('generation','two_stage'):
            pairs=[(lookup[(t,'migration')],lookup[(t,challenger)]) for t in tasks]
            both=[(a,b) for a,b in pairs if a.get('masking',{}).get('ready') and b.get('masking',{}).get('ready')]
            gaps=lambda r:r['masking']['partial']+r['masking']['unmasked']>0
            paired.append({'split':split,'baseline':'migration','challenger':challenger,'registered_authorized_tasks':len(pairs),
                'both_ready_tasks':len(both),'baseline_gaps_on_both_ready':sum(gaps(a) for a,b in both),
                'both_ready_stories':len({a['case_id'] for a,b in both}),
                'baseline_gap_stories':len({a['case_id'] for a,b in both if gaps(a)}),
                'challenger_gap_stories':len({b['case_id'] for a,b in both if gaps(b)}),
                'baseline_correct_on_both_ready':sum(a['score']['correct'] for a,b in both),
                'challenger_correct_on_both_ready':sum(b['score']['correct'] for a,b in both),
                'challenger_gaps_on_both_ready':sum(gaps(b) for a,b in both),
                'challenger_correct_baseline_wrong':sum(b['score']['correct'] and not a['score']['correct'] for a,b in pairs),
                'baseline_correct_challenger_wrong':sum(a['score']['correct'] and not b['score']['correct'] for a,b in pairs)})
    build_rows=read(root/'builds.json')
    build_results=[]
    for split in ('all','dev','heldout'):
        bs=[b for b in build_rows if split=='all' or b['split']==split]
        build_results.append({'split':split,'stories':len(bs),
            'ready_stories':sum(b['status']=='ok' and bool(b['facts']) for b in bs),
            'needs_review_stories':sum(b['status']!='ok' for b in bs)})
    summary={k:v for k,v in report.items() if k not in {'extraction_per_story'}}
    summary.update({'dataset':'examples/memory_generation_eval','synthetic':True,'human_review':None,
        'build_results':build_results,'extraction_summary':extraction,'paired_comparisons':paired,
        'implementation_sha256':plan['implementation_sha256'],'answer_prompt_sha256':plan['answer_prompt_sha256'],
        'local_report_sha256':hashlib.sha256((root/'report.json').read_bytes()).hexdigest(),
        'cloud_task_quality':None,'native_cross_agent_integration':False,
        'signing_key_scope':'in-memory for this controlled run; not persisted to report; signatures do not certify detection completeness',
        'research_status':'Local masking and reuse mechanism evaluated; end-to-end usefulness and general privacy not validated',
        'builder_provenance':{k:build_rows[0].get(k) for k in ('builder_version','prompt_sha256','model','digest')}})
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(json.dumps(summary,ensure_ascii=False,indent=2).encode('utf-8'))
    # Extend the local viewer without changing the already-frozen experiment code.
    local=root/'index.html'
    if local.exists():
        esc=lambda v:__import__('html').escape(str(v))
        table=''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in (b['split'],b['ready_stories'],b['stories'],
            next(x['missing_extraction_sensitive_characters'] for x in extraction if x['split']==b['split'])))+'</tr>' for b in build_results)
        addition='<h2>先看生成完整性</h2><table><tr><th>范围</th><th>生成成功</th><th>登记故事</th><th>未进入正式记忆的敏感字符</th></tr>'+table+'</table><p>字符按每个故事只计一次。生成失败或抽取遗漏不能算作脱敏成功；部分敏感字段即使已遮住保留部分，也不计完整字段保护。</p><p>本地两个角色的身份由宿主程序模拟，签名密钥在内存中；尚未验证原生跨平台Agent互通、云端回答效用或完整隐私。先前开发失败证据保留。</p><h2>同一任务、共同可准备输入的配对对照</h2><table><tr><th>范围</th><th>对比方法</th><th>共同可准备任务</th><th>原方法有缺口</th><th>新方法有缺口</th></tr>'
        addition+=''.join('<tr>'+''.join('<td>'+esc(p[k])+'</td>' for k in ('split','challenger','both_ready_tasks','baseline_gaps_on_both_ready','challenger_gaps_on_both_ready'))+'</tr>' for p in paired)+'</table><p>配对子集仍受生成和放行选择影响，不是全部任务的总体安全率；同一故事下的题目不独立。</p>'
        text=local.read_text(encoding='utf-8')
        if '<h2>先看生成完整性</h2>' not in text:
            local.write_text(text.replace('</html>',addition+'</html>'),encoding='utf-8')
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=export(args.root,args.output)
    print(json.dumps({'published_aggregate':str(args.output),'new_cloud_calls':result['new_cloud_calls']},ensure_ascii=False))
