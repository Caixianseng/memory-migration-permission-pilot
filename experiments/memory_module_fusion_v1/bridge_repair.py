"""One-hop exact-title linking over CURRENT authorized text only.

This is a small lexical graph-retrieval adaptation, not a new graph algorithm.
It never sees answers/support labels or a revoked source's body. The registered
one-hop/two-new-parent limits are fixed before its development outcomes.
"""
import re


def expand_authorized_links(current_sources, seed_ids, hierarchy, question, *, max_new_parents=2):
    records = {s['source_id']:s for s in current_sources}
    if any(sid not in records for sid in seed_ids):
        raise ValueError('bridge_seeds_must_be_current_authorized')
    parents, titles = {}, {}
    for source in current_sources:
        if source.get('allow',True) is not True:
            raise ValueError('bridge_received_forbidden_body')
        parent=hierarchy[source['source_id']]['parent_id']
        parents.setdefault(parent,[]).append(source)
        titles[parent]=source.get('origin',{}).get('title',source['text'].split('\n',1)[0])
    seed_parents={hierarchy[sid]['parent_id'] for sid in seed_ids}
    bodies=['\n'.join(s['text'] for s in parents[parent]) for parent in sorted(seed_parents)]
    qwords=set(re.findall(r'\w+',question.casefold()))
    candidates=[]
    for parent,title in titles.items():
        if parent in seed_parents or len(title.strip())<3:
            continue
        pattern=r'(?<!\w)'+re.escape(title)+r'(?!\w)'
        mentions=sum(len(re.findall(pattern,body,flags=re.IGNORECASE)) for body in bodies)
        if mentions:
            overlap=len(qwords & set(re.findall(r'\w+',title.casefold())))
            candidates.append((-overlap,-mentions,parent))
    chosen=[parent for _,_,parent in sorted(candidates)[:max_new_parents]]
    result=list(dict.fromkeys(list(seed_ids)+[s['source_id'] for parent in chosen for s in parents[parent]]))
    return result,{'method':'current_authorized_exact_title_one_hop','seed_parents':sorted(seed_parents),
        'linked_parents':chosen,'max_new_parents':max_new_parents,'hops':1,
        'unauthorized_bodies_used':False,'added_source_ids':[sid for sid in result if sid not in seed_ids]}
