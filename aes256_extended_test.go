package ige

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
)

func TestAES256KnownAnswer(t *testing.T) {
	// FIPS 197 AES-256 example. A single IGE block with zero IV halves equals
	// an ordinary AES block, providing a fixed answer independent of our oracle.
	decode := func(s string) []byte {
		out, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	key := decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	plain := decode("00112233445566778899aabbccddeeff")
	want := decode("8ea2b7ca516745bfeafc49904b496089")
	c, err := NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}
	got, iv := make([]byte, 16), make([]byte, 32)
	c.Encrypt(got, plain, iv)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypt: %x want %x", got, want)
	}
	c.Decrypt(got, want, iv)
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypt: %x want %x", got, plain)
	}
	if AES256Available() != c.SIMD() {
		t.Fatal("capability query differs from selected cipher")
	}
	if b := NewAES256Batch4([4][32]byte{}); b.SIMD() != AES256Batch4Available() {
		t.Fatal("batch capability differs from selected cipher")
	}
}

func TestAES256BatchUnequalLengths(t *testing.T) {
	rng := rand.New(rand.NewPCG(97, 91))
	for _, sizes := range [][4]int{{0, 0, 0, 0}, {0, 16, 32, 48}, {16, 0, 32, 16}, {16, 32, 48, 64}, {4096, 4112, 4192, 4128}, {524288, 524304, 524320, 524336}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			var keys, iv [4][32]byte
			var src, dst, want [4][]byte
			for lane := range 4 {
				copy(keys[lane][:], deterministic(32, rng))
				copy(iv[lane][:], deterministic(32, rng))
				src[lane], dst[lane], want[lane] = deterministic(sizes[lane], rng), make([]byte, sizes[lane]+16), make([]byte, sizes[lane])
				block, _ := aes.NewCipher(keys[lane][:])
				EncryptBlocks(block, iv[lane][:], want[lane], src[lane])
			}
			b := NewAES256Batch4(keys)
			b.Encrypt(dst, src, iv)
			for lane := range 4 {
				if !bytes.Equal(dst[lane][:sizes[lane]], want[lane]) {
					t.Fatalf("encrypt lane %d", lane)
				}
				if !bytes.Equal(dst[lane][sizes[lane]:], make([]byte, 16)) {
					t.Fatal("output tail modified")
				}
			}
			b.Decrypt(dst, want, iv)
			for lane := range 4 {
				if !bytes.Equal(dst[lane][:sizes[lane]], src[lane]) {
					t.Fatalf("decrypt lane %d", lane)
				}
				dst[lane] = dst[lane][:sizes[lane]]
			}
			b.Encrypt(dst, dst, iv)
			for lane := range 4 {
				if !bytes.Equal(dst[lane], want[lane]) {
					t.Fatalf("in-place encrypt lane %d", lane)
				}
			}
			b.Decrypt(dst, dst, iv)
			for lane := range 4 {
				if !bytes.Equal(dst[lane], src[lane]) {
					t.Fatalf("in-place decrypt lane %d", lane)
				}
			}
		})
	}
}

func TestAES256Parallel(t *testing.T) {
	var keys, iv [4][32]byte
	var src, want [4][]byte
	for lane := range 4 {
		keys[lane][0], iv[lane][0] = byte(lane+1), byte(lane+7)
		src[lane], want[lane] = bytes.Repeat([]byte{byte(lane)}, 4096+lane*16), make([]byte, 4096+lane*16)
		block, _ := aes.NewCipher(keys[lane][:])
		EncryptBlocks(block, iv[lane][:], want[lane], src[lane])
	}
	c, _ := NewAES256(keys[0][:])
	batch := NewAES256Batch4(keys)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			var dst [4][]byte
			for lane := range 4 {
				dst[lane] = make([]byte, len(src[lane]))
			}
			for range 20 {
				c.Encrypt(dst[0], src[0], iv[0][:])
				if !bytes.Equal(dst[0], want[0]) {
					t.Error("parallel single encrypt")
				}
				c.Decrypt(dst[0], want[0], iv[0][:])
				if !bytes.Equal(dst[0], src[0]) {
					t.Error("parallel single decrypt")
				}
				batch.Encrypt(dst, src, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], want[lane]) {
						t.Error("parallel batch encrypt")
					}
				}
				batch.Decrypt(dst, want, iv)
				for lane := range 4 {
					if !bytes.Equal(dst[lane], src[lane]) {
						t.Error("parallel batch decrypt")
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestAES256OverlapBothDirections(t *testing.T) {
	c, _ := NewAES256(make([]byte, 32))
	for _, decrypt := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("decrypt=%v/reverse=%v", decrypt, reverse), func(t *testing.T) {
				storage := make([]byte, 65)
				dst, src := storage[1:33], storage[:32]
				if reverse {
					dst, src = src, dst
				}
				defer func() {
					if recover() == nil {
						t.Error("expected overlap panic")
					}
				}()
				if decrypt {
					c.Decrypt(dst, src, make([]byte, 32))
				} else {
					c.Encrypt(dst, src, make([]byte, 32))
				}
			})
		}
	}
}

func FuzzAES256Batch4(f *testing.F) {
	f.Add(make([]byte, 128), make([]byte, 128), bytes.Repeat([]byte{37}, 64), uint8(3))
	f.Add(bytes.Repeat([]byte{255}, 128), bytes.Repeat([]byte{91}, 128), []byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, keyBytes, ivBytes, data []byte, shape uint8) {
		if len(keyBytes) != 128 || len(ivBytes) != 128 || len(data) > 8192 {
			t.Skip()
		}
		var keys, iv [4][32]byte
		var src, want, got [4][]byte
		for lane := range 4 {
			copy(keys[lane][:], keyBytes[lane*32:(lane+1)*32])
			copy(iv[lane][:], ivBytes[lane*32:(lane+1)*32])
			n := len(data)/16*16 + lane*int(shape%4)*16
			src[lane], want[lane], got[lane] = make([]byte, n), make([]byte, n), make([]byte, n)
			copy(src[lane], data)
			block, _ := aes.NewCipher(keys[lane][:])
			EncryptBlocks(block, iv[lane][:], want[lane], src[lane])
		}
		batch := NewAES256Batch4(keys)
		batch.Encrypt(got, src, iv)
		for lane := range 4 {
			if !bytes.Equal(got[lane], want[lane]) {
				t.Fatalf("encryption lane%d", lane)
			}
		}
		batch.Decrypt(got, got, iv)
		for lane := range 4 {
			if !bytes.Equal(got[lane], src[lane]) {
				t.Fatalf("in-place decryption lane%d", lane)
			}
		}
		batch.Encrypt(got, got, iv)
		for lane := range 4 {
			if !bytes.Equal(got[lane], want[lane]) {
				t.Fatalf("in-place encryption lane%d", lane)
			}
		}
	})
}
