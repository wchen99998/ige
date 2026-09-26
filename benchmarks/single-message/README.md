# Single-message SIMD optimization

Measured on AMD EPYC 9V74, Go 1.26.1, `GOEXPERIMENT=simd`, one caller and
`GOMAXPROCS=1`, pinned to CPU 8. Baseline is production commit
`798915846b22dad5222b8d35416c75464e91e286`; final is the saved `final.go.txt`.
These compare raw AES-256 IGE, not Telegram packet hashing, scheduler, or network.

The retained changes are vector key expansion using AESKEYGENASSIST and a
four-word prefix XOR, pre-XORing each input with round key zero, and folding the
IGE output XOR into the final AES round key. The two XOR rearrangements keep
work off the serial inter-block AES dependency. Decryption loads its chaining
state first so Go 1.26's register allocation avoids an extra dependent move.
Public API, cipher layout, runtime feature gates, FIPS/purego fallbacks, and the
four-lane backend are unchanged. The shared constructor also benefits batching.

## Final comparison

Three alternating baseline/final repetitions, 300ms per benchmark. Medians:

| Operation / setup / bytes | Baseline ns | Final ns | Speedup |
| --- | ---: | ---: | ---: |
| Encrypt/Preexpanded/16 | 12.04 | 11.6 | 1.038x |
| Encrypt/WithSetup/16 | 211 | 97.32 | 2.168x |
| Decrypt/Preexpanded/16 | 11.43 | 11.95 | 0.956x |
| Decrypt/WithSetup/16 | 216 | 103.9 | 2.079x |
| Encrypt/Preexpanded/64 | 41.72 | 41.48 | 1.006x |
| Encrypt/WithSetup/64 | 258.8 | 148.5 | 1.743x |
| Decrypt/Preexpanded/64 | 43.67 | 41.1 | 1.063x |
| Decrypt/WithSetup/64 | 254.7 | 145.5 | 1.751x |
| Encrypt/Preexpanded/4096 | 4119 | 3971 | 1.037x |
| Encrypt/WithSetup/4096 | 4461 | 4232 | 1.054x |
| Decrypt/Preexpanded/4096 | 4143 | 4019 | 1.031x |
| Decrypt/WithSetup/4096 | 4451 | 4172 | 1.067x |
| Encrypt/Preexpanded/524288 | 540254 | 518864 | 1.041x |
| Encrypt/WithSetup/524288 | 540403 | 515637 | 1.048x |
| Decrypt/Preexpanded/524288 | 540463 | 516037 | 1.047x |
| Decrypt/WithSetup/524288 | 535264 | 516009 | 1.037x |

Preexpanded cases allocate zero bytes; WithSetup includes constructing a fresh
cipher per message and retains one 512-byte allocation in both implementations.
The substantial small-message gain comes from key expansion. Bulk single-message
throughput improves about 4%; these results do not support claiming a 2x bulk
single-message speedup. The tiny 16-byte preexpanded measurements vary by less
than a nanosecond and show no reliable improvement; preexpanded throughput is
not the constructor-per-packet path used by MTProto.

`baseline-verified.txt` and `decrypt-order-verified.txt` contain the final raw
runs; `compare.py` prints this table. Earlier measurements and rejected variants
are preserved to show the experiment progression. Hoisting all 15 round keys
outside the single-message loop regressed bulk performance approximately 2–3%
and was rejected. Its register pressure increased spills. The first XOR-folded
variant left an extra decryption register move; `*-order.txt` records the
alternating test that justified the final declaration ordering.

## Remaining serial limit

`BenchmarkAES256RoundChain` measures fourteen dependent AES instructions with a
constant zero round key, omitting IGE XORs, message loads/stores, validation and
key expansion. It is deliberately not a cipher implementation. The final output
is consumed, and the saved GNU objdump shows all fourteen rounds remain in
registers with no per-round memory traffic. A counted `b.N` loop is necessary:
Go's `b.Loop` keep-alive behavior otherwise forces SIMD values to memory between
intrinsics and invalidates the intended measurement.

Five 500ms runs measured a median **15.42ns per 16-byte round chain**. The final
512KiB IGE measurements correspond to about **15.74–15.83ns per block**. This is
an empirical bound for the same dependent AES instructions on this host, not a
universal limit across CPUs or implementations. It leaves roughly 2–3% between
this IGE loop and the stripped round chain; doubling bulk single-message speed
requires a different source of parallelism or faster hardware. Independent
messages can use the existing four-lane backend because their IGE chains do not
depend on each other.

## Reproduce

From this directory or elsewhere:

```sh
python3 benchmarks/single-message/reproduce.py --cpu 8 --build-cpus 0,2,4,6 --repeats 3 --benchtime 300ms
GOEXPERIMENT=simd GOMAXPROCS=1 taskset -c 8 go test -run '^$' -bench '^BenchmarkAES256RoundChain$' -benchtime=500ms -count=5
```

The script builds both saved kernels in isolated temporary modules, prints the
output directory, then alternates their benchmarks. It leaves the repository
unchanged. Choose allowed CPUs on the target machine. The .test binaries used
here are ignored rather than committed. GNU objdump is used because this Go
version's own disassembler does not reliably decode the SIMD instructions.

## Verification

All checks in `validation.txt` passed: portable tests, SIMD race tests, purego,
AES and AVX disabled, AVX512 disabled with single SIMD retained, FIPS fallback,
arm64 cross-compilation, and vet. Existing tests cover the AES-256 known answer,
randomized reference comparisons, in-place operation, unequal batch lengths,
alias rejection and concurrent reuse. Five-second fuzz campaigns executed
440,710 single-message and 351,479 batch cases without failure. Independent
review confirmed the key recurrence, XOR identities, feature coverage and
constant-time structure; no secret-indexed lookup or secret-dependent branch
was added.
