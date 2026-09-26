package ige

// AES256Batch4 processes four independent IGE messages. Each message has its own
// key, IV and length; no individual IGE chain is divided into lanes. The expanded
// keys are immutable and may be shared by goroutines using independent buffers.
type AES256Batch4 struct {
	enc, dec [15][16]uint32
	ciphers  [4]AES256
	simd     bool
}

// NewAES256Batch4 expands the four independent AES-256 keys. It always supports
// the batch API, using individual ciphers when vector acceleration is unavailable.
func NewAES256Batch4(keys [4][32]byte) *AES256Batch4 {
	b := new(AES256Batch4)
	for lane := range 4 {
		initAES256(&b.ciphers[lane], keys[lane][:])
		for round := range 15 {
			copy(b.enc[round][lane*4:lane*4+4], b.ciphers[lane].enc[round][:])
			copy(b.dec[round][lane*4:lane*4+4], b.ciphers[lane].dec[round][:])
		}
	}
	b.simd = b.ciphers[0].simd && batch4Available()
	return b
}

// SIMD reports whether batches can use the four-message SIMD backend.
func (b *AES256Batch4) SIMD() bool { return b.simd }

// AES256Batch4Available reports whether four-message SIMD is available without
// allocating or expanding any keys.
func AES256Batch4Available() bool { return aes256Available() && batch4Available() }

// Encrypt encrypts four messages without modifying iv. Each source/destination
// pair may be identical (exact in-place use); output must not overlap another
// message. Lengths may differ but must be multiples of 16 bytes. The common
// prefix is processed together; any remaining tails use their individual ciphers.
//
//nolint:dupl // Keep in-place tail chaining explicit: preserve plaintext before encryption.
func (b *AES256Batch4) Encrypt(dst, src [4][]byte, iv [4][32]byte) {
	common, equal := validateBatch4(dst, src, iv)
	if b.simd && common > 0 {
		if equal {
			encryptBatch4(&b.enc, dst, src, iv)
			return
		}
		var prefix, output [4][]byte
		var tailIV [4][32]byte
		for lane := range 4 {
			prefix[lane], output[lane] = src[lane][:common], dst[lane][:common]
			// Preserve the last plaintext block before an in-place encryption.
			copy(tailIV[lane][16:], src[lane][common-16:common])
		}
		encryptBatch4(&b.enc, output, prefix, iv)
		for lane := range 4 {
			copy(tailIV[lane][:16], dst[lane][common-16:common])
			b.ciphers[lane].Encrypt(dst[lane][common:], src[lane][common:], tailIV[lane][:])
		}
		return
	}
	for lane := range 4 {
		b.ciphers[lane].Encrypt(dst[lane], src[lane], iv[lane][:])
	}
}

// Decrypt decrypts four messages. Buffer and length requirements match Encrypt.
//
//nolint:dupl // Keep in-place tail chaining explicit: preserve ciphertext before decryption.
func (b *AES256Batch4) Decrypt(dst, src [4][]byte, iv [4][32]byte) {
	common, equal := validateBatch4(dst, src, iv)
	if b.simd && common > 0 {
		if equal {
			decryptBatch4(&b.dec, dst, src, iv)
			return
		}
		var prefix, output [4][]byte
		var tailIV [4][32]byte
		for lane := range 4 {
			prefix[lane], output[lane] = src[lane][:common], dst[lane][:common]
			// Preserve the last ciphertext block before an in-place decryption.
			copy(tailIV[lane][:16], src[lane][common-16:common])
		}
		decryptBatch4(&b.dec, output, prefix, iv)
		for lane := range 4 {
			copy(tailIV[lane][16:], dst[lane][common-16:common])
			b.ciphers[lane].Decrypt(dst[lane][common:], src[lane][common:], tailIV[lane][:])
		}
		return
	}
	for lane := range 4 {
		b.ciphers[lane].Decrypt(dst[lane], src[lane], iv[lane][:])
	}
}

func validateBatch4(dst, src [4][]byte, iv [4][32]byte) (common int, equal bool) {
	common, equal = len(src[0]), true
	for lane := range 4 {
		validate(dst[lane], src[lane], iv[lane][:])
		common = min(common, len(src[lane]))
		equal = equal && len(src[lane]) == len(src[0])
	}
	for lane := range 4 {
		for other := range 4 {
			if lane == other {
				continue
			}
			out := dst[lane][:len(src[lane])]
			if slicesOverlap(out, src[other]) || slicesOverlap(out, dst[other][:len(src[other])]) {
				panic("batch messages overlap")
			}
		}
	}
	return common, equal
}
