"""Lossless extraction of source text with unescaped embedded quote marks.

This is a serialization recovery, NOT a conforming model JSON result. Only the
fixed three memory_text/empty-claims records are accepted; no facts are edited.
"""
import json,re
SCENARIOS=('raw','summary','multi_source')
def parse_json_object(text):
    try:return json.loads(text),{'strict_json':True,'repair_applied':False}
    except json.JSONDecodeError as original:
        try:obj,end=json.JSONDecoder().raw_decode(text.lstrip())
        except json.JSONDecodeError:raise original
        suffix=text.lstrip()[end:].strip()
        if not isinstance(obj,dict) or not suffix or set(suffix)!={'}'}:raise original
        return obj,{'strict_json':False,'repair_applied':True,'kind':'remove_only_redundant_closing_braces_after_complete_object',
                    'removed_braces':len(suffix),'model_format_failure_retained':True,'model_facts_modified':False,'new_model_calls':0}
def parse_source(text):
    try:return parse_json_object(text)
    except json.JSONDecodeError:pass
    blocks=[r'"'+s+r'"\s*:\s*\{\s*"memory_text"\s*:\s*"(.*?)"\s*,\s*"claims"\s*:\s*\[\s*\]\s*\}' for s in SCENARIOS]
    pattern=r'\s*\{\s*"scenarios"\s*:\s*\{\s*'+r'\s*,\s*'.join(blocks)+r'\s*\}\s*\}\s*'
    m=re.fullmatch(pattern,text,re.S)
    if not m:raise ValueError('source_format_not_losslessly_recoverable')
    result={};edits=[]
    for name,body in zip(SCENARIOS,m.groups()):
        if '\n' in body or '\r' in body:raise ValueError('unescaped_source_newline_not_recovered')
        repaired=[];slashes=0;positions=[]
        for i,c in enumerate(body):
            if c=='"' and slashes%2==0:repaired.append('\\');positions.append(i)
            repaired.append(c);slashes=slashes+1 if c=='\\' else 0
        value=json.loads('"'+''.join(repaired)+'"')
        result[name]={'memory_text':value,'claims':[]}
        edits.append({'scenario':name,'escaped_quote_positions_in_raw_value':positions,'raw_value_unchanged':True})
    if not any(e['escaped_quote_positions_in_raw_value'] for e in edits):raise ValueError('source_failure_not_embedded_quote_error')
    return {'scenarios':result},{'strict_json':False,'repair_applied':True,
        'kind':'escape_only_unescaped_embedded_quotes_fixed_schema','edits':edits,
        'new_model_calls':0,'model_format_failure_retained':True,'model_facts_modified':False}
