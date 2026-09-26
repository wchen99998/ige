package ige

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"unsafe"
)

// AES256 is an AES-256 cipher specialized for IGE. Its expanded key is immutable;
// a cipher may be shared by goroutines operating on independent buffers.
type AES256 struct {
	enc, dec [15][4]uint32
	block    cipher.Block
	simd     bool
}

// NewAES256 expands a 32-byte AES key once. Operations accept a fresh 32-byte IGE
// IV. Hardware acceleration is optional; unsupported builds and CPUs use the
// standard library AES implementation.
func NewAES256(key []byte) (*AES256, error) {
	if len(key) != 32 {
		return nil, errors.New("ige: AES-256 requires a 32-byte key")
	}
	c := new(AES256)
	initAES256(c, key)
	return c, nil
}

// initAES256 initializes storage owned by a single cipher or a batch. Every
// caller supplies exactly 32 key bytes, so aes.NewCipher cannot reject the key.
func initAES256(c *AES256, key []byte) {
	if initSIMD(c, key) {
		c.simd = true
		return
	}
	c.block, _ = aes.NewCipher(key)
}

// SIMD reports whether this cipher uses the fused hardware implementation.
func (c *AES256) SIMD() bool { return c.simd }

// AES256Available reports whether NewAES256 will use the fused SIMD backend.
// It performs no key expansion or allocation.
func AES256Available() bool { return aes256Available() }

func validate(dst, src, iv []byte) {
	if len(iv) != 32 {
		panic("IGE requires a 32-byte IV")
	}
	if len(src)%16 != 0 {
		panic("input is not full blocks")
	}
	if len(dst) < len(src) {
		panic("output is too short")
	}
	if len(src) == 0 {
		return
	}
	d, s := uintptr(unsafe.Pointer(unsafe.SliceData(dst))), uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	if d != s && d < s+uintptr(len(src)) && s < d+uintptr(len(src)) {
		panic("invalid buffer overlap")
	}
	v := uintptr(unsafe.Pointer(unsafe.SliceData(iv)))
	if d < v+32 && v < d+uintptr(len(src)) {
		panic("IV overlaps output")
	}
}

func slicesOverlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return x < y+uintptr(len(b)) && y < x+uintptr(len(a))
}

// Encrypt encrypts src into dst without changing iv. Exact in-place use is supported.
func (c *AES256) Encrypt(dst, src, iv []byte) {
	validate(dst, src, iv)
	if c.simd {
		encryptSIMD(&c.enc, dst, src, iv)
		return
	}
	cryptFallback(c.block, dst, src, iv, true)
}

// Decrypt decrypts src into dst without changing iv. Exact in-place use is supported.
func (c *AES256) Decrypt(dst, src, iv []byte) {
	validate(dst, src, iv)
	if c.simd {
		decryptSIMD(&c.dec, dst, src, iv)
		return
	}
	cryptFallback(c.block, dst, src, iv, false)
}

func cryptFallback(block cipher.Block, dst, src, iv []byte, encrypt bool) {
	c, p := [16]byte(iv[:16]), [16]byte(iv[16:])
	var input [16]byte
	for off := 0; off < len(src); off += 16 {
		copy(input[:], src[off:off+16])
		out := dst[off : off+16]
		if encrypt {
			subtle.XORBytes(out, input[:], c[:])
			block.Encrypt(out, out)
			subtle.XORBytes(out, out, p[:])
			p, c = input, [16]byte(out)
		} else {
			subtle.XORBytes(out, input[:], p[:])
			block.Decrypt(out, out)
			subtle.XORBytes(out, out, c[:])
			c, p = input, [16]byte(out)
		}
	}
}
