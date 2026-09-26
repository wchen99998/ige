//go:build goexperiment.simd && amd64 && !purego && !goexperiment.boringcrypto

package ige

import (
	"simd/archsimd"
	"testing"
)

var roundChainSink [16]byte

// BenchmarkAES256RoundChain measures a serial chain of fourteen AES rounds
// without IGE XORs, message loads/stores, or key expansion. The repeated zero
// round key deliberately makes this a latency bound, not an AES cipher.
func BenchmarkAES256RoundChain(b *testing.B) {
	if !AES256Available() {
		b.Skip("AES/AVX SIMD unavailable")
	}
	b.SetBytes(16)
	var key archsimd.Uint32x4
	var x archsimd.Uint8x16
	// b.Loop keeps every intermediate alive and forces SIMD spills here; use
	// a counted loop and consume the final vector explicitly instead.
	for i := 0; i < b.N; i++ {
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptOneRound(key)
		x = x.AESEncryptLastRound(key)
	}
	x.Store(&roundChainSink)
}
