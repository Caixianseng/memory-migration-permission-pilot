"""Restartable public-data reads only; never retries any model request."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import urllib.request

from .acquire_hotpot_hf import DATA, FILE, HOST, REPOSITORY, REVISION
from .prepare_hotpot import write_once


def main():
    entry = next(row for row in json.loads((DATA/'hf_tree_pinned.json').read_text()) if row['path']==FILE)
    total, expected = entry['size'], entry['lfs']['oid']
    part_dir = DATA/'parquet_parts'
    part_dir.mkdir(exist_ok=True)
    chunk = 1024*1024
    url = f'{HOST}/datasets/{REPOSITORY}/resolve/{REVISION}/{FILE}'

    def fetch(start):
        end = min(total-1,start+chunk-1)
        target = part_dir/f'{start:010d}-{end:010d}.bin'
        if target.exists() and target.stat().st_size == end-start+1:
            return start
        last = None
        for attempt in range(2):
            try:
                request = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0',
                    'Range':f'bytes={start}-{end}'})
                with urllib.request.urlopen(request, timeout=25) as response:
                    content_range = response.headers.get('Content-Range','')
                    if response.status != 206 or content_range != f'bytes {start}-{end}/{total}':
                        raise ValueError('server_did_not_honor_exact_range')
                    body = response.read(end-start+2)
                if len(body) != end-start+1:
                    raise ValueError('incomplete_range')
                write_once(target, body)
                return start
            except Exception as error:
                last = type(error).__name__
        raise RuntimeError(f'public_range_failed:{start}:{last}')

    # Check range support before dispatching independent reads concurrently.
    fetch(0)
    offsets = list(range(0,total,chunk))
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fetch,start) for start in offsets[1:]]
        for completed, future in enumerate(as_completed(futures),2):
            future.result()
            print(json.dumps({'parts_complete':completed,'parts_total':len(offsets)}), flush=True)
    body = b''.join((part_dir/f'{start:010d}-{min(total-1,start+chunk-1):010d}.bin').read_bytes() for start in offsets)
    if len(body)!=total or hashlib.sha256(body).hexdigest()!=expected:
        raise ValueError('full_pinned_LFS_hash_failed')
    write_once(DATA/'upstream_validation.parquet',body)
    print(json.dumps({'complete':True,'bytes':len(body),'sha256':expected}))


if __name__=='__main__':
    main()
