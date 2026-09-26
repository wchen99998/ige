package ige

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"math/rand/v2"
	"testing"
)

func deterministic(n int, rng *rand.Rand) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func TestAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 7))
	for _, size := range []int{0, 16, 32, 48, 64, 1024, 524288} {
		for trial := range 10 {
			t.Run(fmt.Sprintf("%d/%d", size, trial), func(t *testing.T) {
				key, iv, src := deterministic(32, rng), deterministic(32, rng), deterministic(size, rng)
				ivCopy := bytes.Clone(iv)
				c, err := NewAES256(key)
				if err != nil {
					t.Fatal(err)
				}
				block, _ := aes.NewCipher(key)
				want, got := make([]byte, size), make([]byte, size)
				EncryptBlocks(block, iv, want, src)
				c.Encrypt(got, src, iv)
				if !bytes.Equal(got, want) {
					t.Fatal("encrypt differs from reference")
				}
				refPlain := make([]byte, size)
				DecryptBlocks(block, iv, refPlain, want)
				c.Decrypt(got, want, iv)
				if !bytes.Equal(got, refPlain) || !bytes.Equal(got, src) {
					t.Fatal("decrypt differs from reference")
				}
				inplace := bytes.Clone(src)
				c.Encrypt(inplace, inplace, iv)
				if !bytes.Equal(inplace, want) {
					t.Fatal("in-place encrypt differs")
				}
				c.Decrypt(inplace, inplace, iv)
				if !bytes.Equal(inplace, src) {
					t.Fatal("in-place decrypt differs")
				}
				if !bytes.Equal(ivCopy, iv) {
					t.Fatal("IV was modified")
				}
			})
		}
	}
}

func TestValidation(t *testing.T) {
	if _, err := NewAES256(make([]byte, 16)); err == nil {
		t.Fatal("accepted non-256 key")
	}
	c, _ := NewAES256(make([]byte, 32))
	iv := make([]byte, 32)
	for name, fn := range map[string]func(){
		"short-IV":      func() { c.Encrypt(nil, nil, iv[:16]) },
		"partial-block": func() { c.Decrypt(make([]byte, 17), make([]byte, 17), iv) },
		"short-output":  func() { c.Encrypt(nil, make([]byte, 16), iv) },
		"overlap":       func() { b := make([]byte, 33); c.Encrypt(b[1:], b[:32], iv) },
		"IV-overlap":    func() { c.Encrypt(iv, make([]byte, 32), iv) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			fn()
		})
	}
}

func FuzzReference(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 64))
	f.Add(bytes.Repeat([]byte{255}, 32), bytes.Repeat([]byte{127}, 32), []byte("sixteen-byte-msg"))
	f.Fuzz(func(t *testing.T, key, iv, data []byte) {
		if len(key) != 32 || len(iv) != 32 || len(data) > 65536 {
			t.Skip()
		}
		data = data[:len(data)/16*16]
		c, _ := NewAES256(key)
		block, _ := aes.NewCipher(key)
		want, got := make([]byte, len(data)), make([]byte, len(data))
		EncryptBlocks(block, iv, want, data)
		c.Encrypt(got, data, iv)
		if !bytes.Equal(got, want) {
			t.Fatal("encrypt mismatch")
		}
		DecryptBlocks(block, iv, want, data)
		c.Decrypt(got, data, iv)
		if !bytes.Equal(got, want) {
			t.Fatal("decrypt mismatch")
		}
	})
}

func BenchmarkIGE(b *testing.B) {
	for _, size := range []int{64, 4096, 524288, 1048576} {
		key, iv, src, dst := make([]byte, 32), make([]byte, 32), make([]byte, size), make([]byte, size)
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
				b.Run(fmt.Sprintf("Reference/%s/%s/%d", operation, label, size), func(b *testing.B) {
					block, _ := aes.NewCipher(key)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if setup {
							block, _ = aes.NewCipher(key)
						}
						if decrypt {
							DecryptBlocks(block, iv, dst, src)
						} else {
							EncryptBlocks(block, iv, dst, src)
						}
					}
				})
				b.Run(fmt.Sprintf("Candidate/%s/%s/%d", operation, label, size), func(b *testing.B) {
					c, _ := NewAES256(key)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if setup {
							c, _ = NewAES256(key)
						}
						if decrypt {
							c.Decrypt(dst, src, iv)
						} else {
							c.Encrypt(dst, src, iv)
						}
					}
				})
			}
		}
	}
}
