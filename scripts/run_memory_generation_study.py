"""Run a bounded, zero-cloud-cost generation-labeling comparison."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from memory_migration_study.memory_generation_experiment import run_study, render_report

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus',type=Path,default=Path('examples/memory_generation_eval'))
    parser.add_argument('--config',type=Path,default=Path('configs/local_privacy_detector.json'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--split',choices=['dev','heldout','all'],default='all')
    args=parser.parse_args()
    config=json.loads(args.config.read_text(encoding='utf-8'))
    splits=('dev','heldout') if args.split=='all' else (args.split,)
    report=run_study(args.corpus,args.output,config,splits=splits)
    render_report(args.output,report)
    print(json.dumps({'output':str(args.output),'build_successes':report['build_successes'],'new_cloud_calls':0},ensure_ascii=False))
