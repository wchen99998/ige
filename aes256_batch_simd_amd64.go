//go:build goexperiment.simd && amd64 && !purego && !goexperiment.boringcrypto

package ige

import "simd/archsimd"

func batch4Available() bool {
	// Check the base features independently: Go 1.26's derived VAES flag is
	// calculated before GODEBUG feature overrides are applied.
	return archsimd.X86.AVX2() && archsimd.X86.AVX512() && archsimd.X86.AVX512VAES()
}

func join4(a, b, c, d archsimd.Uint8x16) archsimd.Uint8x64 {
	var lo, hi archsimd.Uint8x32
	var out archsimd.Uint8x64
	return out.SetLo(lo.SetLo(a).SetHi(b)).SetHi(hi.SetLo(c).SetHi(d))
}

func encryptBatch4(keys *[15][16]uint32, dst, src [4][]byte, iv [4][32]byte) {
	c := join4(archsimd.LoadUint8x16Slice(iv[0][:16]), archsimd.LoadUint8x16Slice(iv[1][:16]), archsimd.LoadUint8x16Slice(iv[2][:16]), archsimd.LoadUint8x16Slice(iv[3][:16]))
	p := join4(archsimd.LoadUint8x16Slice(iv[0][16:]), archsimd.LoadUint8x16Slice(iv[1][16:]), archsimd.LoadUint8x16Slice(iv[2][16:]), archsimd.LoadUint8x16Slice(iv[3][16:]))
	k0 := archsimd.LoadUint32x16(&keys[0])
	k1 := archsimd.LoadUint32x16(&keys[1])
	k2 := archsimd.LoadUint32x16(&keys[2])
	k3 := archsimd.LoadUint32x16(&keys[3])
	k4 := archsimd.LoadUint32x16(&keys[4])
	k5 := archsimd.LoadUint32x16(&keys[5])
	k6 := archsimd.LoadUint32x16(&keys[6])
	k7 := archsimd.LoadUint32x16(&keys[7])
	k8 := archsimd.LoadUint32x16(&keys[8])
	k9 := archsimd.LoadUint32x16(&keys[9])
	k10 := archsimd.LoadUint32x16(&keys[10])
	k11 := archsimd.LoadUint32x16(&keys[11])
	k12 := archsimd.LoadUint32x16(&keys[12])
	k13 := archsimd.LoadUint32x16(&keys[13])
	k14 := archsimd.LoadUint32x16(&keys[14])
	for off := 0; off < len(src[0]); off += 16 {
		input := join4(archsimd.LoadUint8x16Slice(src[0][off:off+16]), archsimd.LoadUint8x16Slice(src[1][off:off+16]), archsimd.LoadUint8x16Slice(src[2][off:off+16]), archsimd.LoadUint8x16Slice(src[3][off:off+16]))
		x := input.Xor(c).Xor(k0.AsUint8x64())
		x = x.AESEncryptOneRound(k1)
		x = x.AESEncryptOneRound(k2)
		x = x.AESEncryptOneRound(k3)
		x = x.AESEncryptOneRound(k4)
		x = x.AESEncryptOneRound(k5)
		x = x.AESEncryptOneRound(k6)
		x = x.AESEncryptOneRound(k7)
		x = x.AESEncryptOneRound(k8)
		x = x.AESEncryptOneRound(k9)
		x = x.AESEncryptOneRound(k10)
		x = x.AESEncryptOneRound(k11)
		x = x.AESEncryptOneRound(k12)
		x = x.AESEncryptOneRound(k13)
		c = x.AESEncryptLastRound(k14).Xor(p)
		c.GetLo().GetLo().StoreSlice(dst[0][off : off+16])
		c.GetLo().GetHi().StoreSlice(dst[1][off : off+16])
		c.GetHi().GetLo().StoreSlice(dst[2][off : off+16])
		c.GetHi().GetHi().StoreSlice(dst[3][off : off+16])
		p = input
	}
}

func decryptBatch4(keys *[15][16]uint32, dst, src [4][]byte, iv [4][32]byte) {
	c := join4(archsimd.LoadUint8x16Slice(iv[0][:16]), archsimd.LoadUint8x16Slice(iv[1][:16]), archsimd.LoadUint8x16Slice(iv[2][:16]), archsimd.LoadUint8x16Slice(iv[3][:16]))
	p := join4(archsimd.LoadUint8x16Slice(iv[0][16:]), archsimd.LoadUint8x16Slice(iv[1][16:]), archsimd.LoadUint8x16Slice(iv[2][16:]), archsimd.LoadUint8x16Slice(iv[3][16:]))
	k0 := archsimd.LoadUint32x16(&keys[0])
	k1 := archsimd.LoadUint32x16(&keys[1])
	k2 := archsimd.LoadUint32x16(&keys[2])
	k3 := archsimd.LoadUint32x16(&keys[3])
	k4 := archsimd.LoadUint32x16(&keys[4])
	k5 := archsimd.LoadUint32x16(&keys[5])
	k6 := archsimd.LoadUint32x16(&keys[6])
	k7 := archsimd.LoadUint32x16(&keys[7])
	k8 := archsimd.LoadUint32x16(&keys[8])
	k9 := archsimd.LoadUint32x16(&keys[9])
	k10 := archsimd.LoadUint32x16(&keys[10])
	k11 := archsimd.LoadUint32x16(&keys[11])
	k12 := archsimd.LoadUint32x16(&keys[12])
	k13 := archsimd.LoadUint32x16(&keys[13])
	k14 := archsimd.LoadUint32x16(&keys[14])
	for off := 0; off < len(src[0]); off += 16 {
		input := join4(archsimd.LoadUint8x16Slice(src[0][off:off+16]), archsimd.LoadUint8x16Slice(src[1][off:off+16]), archsimd.LoadUint8x16Slice(src[2][off:off+16]), archsimd.LoadUint8x16Slice(src[3][off:off+16]))
		x := input.Xor(p).Xor(k0.AsUint8x64())
		x = x.AESDecryptOneRound(k1)
		x = x.AESDecryptOneRound(k2)
		x = x.AESDecryptOneRound(k3)
		x = x.AESDecryptOneRound(k4)
		x = x.AESDecryptOneRound(k5)
		x = x.AESDecryptOneRound(k6)
		x = x.AESDecryptOneRound(k7)
		x = x.AESDecryptOneRound(k8)
		x = x.AESDecryptOneRound(k9)
		x = x.AESDecryptOneRound(k10)
		x = x.AESDecryptOneRound(k11)
		x = x.AESDecryptOneRound(k12)
		x = x.AESDecryptOneRound(k13)
		p = x.AESDecryptLastRound(k14).Xor(c)
		p.GetLo().GetLo().StoreSlice(dst[0][off : off+16])
		p.GetLo().GetHi().StoreSlice(dst[1][off : off+16])
		p.GetHi().GetLo().StoreSlice(dst[2][off : off+16])
		p.GetHi().GetHi().StoreSlice(dst[3][off : off+16])
		c = input
	}
}
