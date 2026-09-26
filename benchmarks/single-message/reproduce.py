#!/usr/bin/env python3
"""Rebuild the saved baseline/final kernels and alternate benchmarks on one CPU.

Run from any directory: python3 reproduce.py --cpu 8 --repeats 3 --benchtime 300ms
Outputs go to a new temporary directory printed by the script; repository files
are not modified. Requires Go 1.26 and an amd64 CPU with AES/AVX.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cpu', default='8')
parser.add_argument('--build-cpus', default='0,2,4,6')
parser.add_argument('--repeats', type=int, default=3)
parser.add_argument('--benchtime', default='300ms')
args = parser.parse_args()
artifact = Path(__file__).resolve().parent
repo = artifact.parent.parent
work = Path(tempfile.mkdtemp(prefix='ige-single-bench-'))
print(work, flush=True)
env = dict(os.environ, GOEXPERIMENT='simd', GOMAXPROCS='1')
for name in ('baseline', 'final'):
    module = work / name
    module.mkdir()
    for source in [*repo.glob('*.go'), repo / 'go.mod', repo / 'go.sum']:
        shutil.copyfile(source, module / source.name)
    shutil.copyfile(artifact / (name + '.go.txt'), module / 'aes256_simd_amd64.go')
    subprocess.run(['taskset', '-c', args.build_cpus, 'go', 'test', '-c', '-o', str(work / (name + '.test'))], cwd=module, env=env, check=True)
for repeat in range(args.repeats):
    for name in (('baseline', 'final') if repeat % 2 == 0 else ('final', 'baseline')):
        print(f'repeat {repeat+1}: {name}', flush=True)
        with (work / (name + '.txt')).open('a') as log:
            subprocess.run(['taskset', '-c', args.cpu, str(work / (name + '.test')), '-test.run', '^$', '-test.bench', '^BenchmarkIGE$/Candidate/(Encrypt|Decrypt)/(Preexpanded|WithSetup)/(16|64|4096|524288)$', '-test.benchtime', args.benchtime, '-test.count', '1'], cwd=repo, env=env, stdout=log, check=True)
