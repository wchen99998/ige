//go:build !goexperiment.simd || !amd64 || purego || goexperiment.boringcrypto

package ige

func aes256Available() bool                                { return false }
func initSIMD(c *AES256, key []byte) bool                  { return false }
func encryptSIMD(keys *[15][4]uint32, dst, src, iv []byte) { panic("SIMD unavailable") }
func decryptSIMD(keys *[15][4]uint32, dst, src, iv []byte) { panic("SIMD unavailable") }
