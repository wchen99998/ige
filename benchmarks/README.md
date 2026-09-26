# AES-256-IGE optimization measurements

Measured on AMD EPYC 9V74, Go 1.26.1 linux/amd64, pinned to CPU 8 with
`GOMAXPROCS=1 GOEXPERIMENT=simd`. Each operation processes four independent
512 KiB messages. Results are CPU measurements, not network transfer rates.

The ported baseline loads its AES round keys inside each block iteration.
`batch-before.txt` measures that implementation. `batch-hoist.txt` measures the
same algorithm with round keys loaded before the loop. Preexpanded median
encryption decreased from 578408 ns to 563176 ns (2.7% more throughput), and
decryption from 578543 ns to 563045 ns (2.8%).

The final implementation also embeds four cipher states in the batch, reducing
construction from five heap allocations to one. `batch-final.txt` includes key
setup: encryption median 565284 ns; decryption median 568564 ns; 4096 bytes and
one allocation per four-message batch. Timing variation is visible in the raw
samples; this change primarily improves allocation count.

Commands:

```sh
taskset -c 8 env GOMAXPROCS=1 GOEXPERIMENT=simd go test -run '^$' \
  -bench '^BenchmarkBatch4$/Candidate' -benchtime=700ms -count=3
taskset -c 8 env GOMAXPROCS=1 GOEXPERIMENT=simd go test -run '^$' \
  -bench '^BenchmarkBatch4$/Candidate/(Encrypt|Decrypt)/WithSetup' \
  -benchtime=700ms -count=3
```

The benchmark also has `Reference` cases for the existing generic IGE API.
