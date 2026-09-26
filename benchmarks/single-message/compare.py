#!/usr/bin/env python3
"""Compare ns/op medians from alternating baseline/final benchmark runs."""
from pathlib import Path
import re
import statistics

root = Path(__file__).parent

def read(name):
    out = {}
    for line in (root / name).read_text().splitlines():
        match = re.match(r'(Benchmark\S+)\s+\d+\s+([\d.]+) ns/op', line)
        if match:
            out.setdefault(match[1], []).append(float(match[2]))
    return out

before, after = read('baseline-verified.txt'), read('decrypt-order-verified.txt')
print('| Operation / setup / bytes | Baseline ns | Final ns | Speedup |')
print('| --- | ---: | ---: | ---: |')
for name, values in before.items():
    if name not in after:
        continue
    a, b = statistics.median(values), statistics.median(after[name])
    print(f'| {name.removeprefix("BenchmarkIGE/Candidate/")} | {a:g} | {b:g} | {a/b:.3f}x |')
