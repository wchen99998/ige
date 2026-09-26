package ige

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"
)

func TestDispatch(t *testing.T) {
	c, _ := NewAES256(make([]byte, 32))
	b := NewAES256Batch4([4][32]byte{})
	t.Logf("SIMD=%v BatchSIMD=%v", c.SIMD(), b.SIMD())
	if expected := os.Getenv("IGE_EXPECT_SIMD"); expected != "" && fmt.Sprint(c.SIMD()) != expected {
		t.Fatalf("SIMD=%v want%s", c.SIMD(), expected)
	}
	if expected := os.Getenv("IGE_EXPECT_BATCH_SIMD"); expected != "" && fmt.Sprint(b.SIMD()) != expected {
		t.Fatalf("BatchSIMD=%v want%s", b.SIMD(), expected)
	}
}

func TestBatch4AgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(73, 17))
	for _, size := range []int{0, 16, 32, 64, 4096, 524288} {
		for trial := range 5 {
			t.Run(fmt.Sprintf("%d/%d", size, trial), func(t *testing.T) {
				var keys, iv [4][32]byte
				var src, dst, want [4][]byte
				for lane := range 4 {
					copy(keys[lane][:], deterministic(32, rng))
					copy(iv[lane][:], deterministic(32, rng))
					src[lane], dst[lane], want[lane] = deterministic(size, rng), make([]byte, size), make([]byte, size)
					block, _ := aes.NewCipher(keys[lane][:])
					EncryptBlocks(block, iv[lane][:], want[lane], src[lane])
				}
				b := NewAES256Batch4(keys)
				b.Encrypt(dst, src, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], want[lane]) {
						t.Fatalf("encrypt mismatch lane%d", lane)
					}
				}
				b.Decrypt(dst, want, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], src[lane]) {
						t.Fatalf("decrypt mismatch lane%d", lane)
					}
				}
				b.Encrypt(dst, dst, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], want[lane]) {
						t.Fatalf("in-place encrypt mismatch lane%d", lane)
					}
				}
				b.Decrypt(dst, dst, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], src[lane]) {
						t.Fatalf("in-place decrypt mismatch lane%d", lane)
					}
				}
			})
		}
	}
}

func TestBatch4Validation(t *testing.T) {
	b := NewAES256Batch4([4][32]byte{})
	for _, mode := range []string{"partial-block", "cross-source", "cross-output"} {
		t.Run(mode, func(t *testing.T) {
			var src, dst [4][]byte
			for lane := range 4 {
				src[lane], dst[lane] = make([]byte, 32), make([]byte, 32)
			}
			switch mode {
			case "partial-block":
				src[1] = src[1][:15]
			case "cross-source":
				dst[0] = src[1]
			case "cross-output":
				dst[0] = dst[1]
			}
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			b.Encrypt(dst, src, [4][32]byte{})
		})
	}
}

func BenchmarkBatch4(b *testing.B) {
	const size = 524288
	var keys, iv [4][32]byte
	var src, dst [4][]byte
	for lane := range 4 {
		src[lane], dst[lane] = make([]byte, size), make([]byte, size)
		keys[lane][0] = byte(lane)
	}
	for _, decrypt := range []bool{false, true} {
		operation := "Encrypt"
		if decrypt {
			operation = "Decrypt"
		}
		for _, setup := range []bool{false, true} {
			label := "Preexpanded"
			if setup {
				label = "WithSetup"
			}
			b.Run(fmt.Sprintf("Reference/%s/%s", operation, label), func(b *testing.B) {
				var blocks [4]cipher.Block
				for lane := range 4 {
					blocks[lane], _ = aes.NewCipher(keys[lane][:])
				}
				b.SetBytes(4 * size)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					for lane := range 4 {
						if setup {
							blocks[lane], _ = aes.NewCipher(keys[lane][:])
						}
						if decrypt {
							DecryptBlocks(blocks[lane], iv[lane][:], dst[lane], src[lane])
						} else {
							EncryptBlocks(blocks[lane], iv[lane][:], dst[lane], src[lane])
						}
					}
				}
			})
			b.Run(fmt.Sprintf("Candidate/%s/%s", operation, label), func(b *testing.B) {
				batch := NewAES256Batch4(keys)
				b.SetBytes(4 * size)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if setup {
						batch = NewAES256Batch4(keys)
					}
					if decrypt {
						batch.Decrypt(dst, src, iv)
					} else {
						batch.Encrypt(dst, src, iv)
					}
				}
			})
		}
	}
}
