//go:build !goexperiment.simd || !amd64 || purego || goexperiment.boringcrypto

package ige

func batch4Available() bool { return false }
func encryptBatch4(keys *[15][16]uint32, dst, src [4][]byte, iv [4][32]byte) {
	panic("SIMD unavailable")
}
func decryptBatch4(keys *[15][16]uint32, dst, src [4][]byte, iv [4][32]byte) {
	panic("SIMD unavailable")
}
