"""One reserved native HY3 paid-route preflight; never retries a dispatch."""
import json, subprocess, time, uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
GATEWAY=ROOT.parent/'codex-workbuddy-gateway-windows'
OUT=ROOT/'research_paper_v1/paper_live_v2/raw_experiment_data/preflight/workbuddy'
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    source=OUT/'input.json'; envelope=OUT/'envelope.json'
    if not source.exists():
        job={'schema':'workbuddy-hy3-paid-one-shot-job-v1','jobId':'live-v2-hy3-preflight-20261106',
             'jobType':'qualification','sessionId':str(uuid.uuid4()),'workspace':str(OUT),
             'model':'hy3-x','instruction':'Read the quoted facts and answer the question. Return only JSON {"answer":number}. Do not use tools.',
             'businessInput':{'facts':['The fictional test container holds 17 blue units and 8 red units.'],
                              'question':'How many units are in the container?'},
             'quotaRestorationConfirmed':True,'timeoutSeconds':120,'softOutputCharacters':300,
             'cdpPort':18491,'cliElectronPath':'D:/workbuddy/WorkBuddy.exe',
             'workbuddyConfigDir':'[USER_HOME]/.workbuddy'}
        source.write_text(json.dumps(job,ensure_ascii=False,indent=2),encoding='utf-8')
    started=time.time()
    result=subprocess.run(['D:/node/node.exe',str(GATEWAY/'scripts/hy3-native-paid-one-shot.mjs'),
        '--input',str(source),'--output',str(envelope)],cwd=GATEWAY,capture_output=True,text=True,
        encoding='utf-8',timeout=240)
    receipt={'started_unix':started,'elapsed_seconds':time.time()-started,'returncode':result.returncode,
             'stdout':result.stdout,'stderr':result.stderr,'envelope_exists':envelope.exists(),
             'note':'native one-shot, not queue; no automatic resubmission'}
    (OUT.parent/'workbuddy_invocation.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(receipt,ensure_ascii=False))
if __name__=='__main__': main()
