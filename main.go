package main

import (
	"hash"
	"fmt"
  "crypto/sha256"
  "time"
)

// References:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
// An Analysis of the NIST SP 800-90A Standard
// https://eprint.iacr.org/2018/349.pdf
// https://crypto.stackexchange.com/questions/76382/can-we-use-a-cryptographic-hash-function-to-generate-infinite-random-numbers

const (
  // MaxInputLength is the maximum length of the input datat (entropy, personalization, nonce, and additional input) in bytes.
	MaxInputLength = 1 << 32 // 2^35 bits
  // ReseedInterval is the maximum number of requests that can be made
	// before a reseed operation is required.
	ReseedInterval = 1 << 48

	MaxBytesPerRequest = 1 << 16 // 2^19 bits.
)

func Uint64Bytes(i uint64, toBE bool) []byte {
  b := make([]byte, 8)
  for idx := 0; idx < 8; idx++ {
    x := byte(i & 0x0f)
    i >>= 8
    if toBE {
      b[7 - idx] = x
    } else {
      b[idx] = x
    }
  }
  return b
}

func Uint64BytesStr(i uint64, toBE, toUpper bool) []byte {
  return Bytes2Hex(Uint64Bytes(i, toBE), toUpper)
}

func Bytes2Hex(in []byte, toUpper bool) []byte {
  out := make([]byte, len(in)*2)
  offset := byte(0x61) // 'a'
  if toUpper {
    offset -= 0x20 // 'A'
  }
  n2a := func(x byte) byte {
   if x < 10 {
     return x + 0x30 // '0'
   } 
    return (x - 10) + offset
  }
  for j, b := range in {
    k := 2 * j
    out[k] = n2a((b & 0xf0) >> 4)
    out[k + 1] = n2a(b & 0x0f)
  } 
  return out
}

type MyHashDRBG struct {
  v []byte
  c []byte
  seedLen int // in bytes
  reseedCounter uint64
	hash          hash.Hash
}

func (d MyHashDRBG) hashDf(out []byte, ins ...[]byte) error {
	if len(ins) == 0 {
		return fmt.Errorf("empty list of inputs specified")
	}
	nIns := 0
	for _, in := range ins {
		nIns += len(in)
	}
	if nIns == 0 {
		return fmt.Errorf("empty total length of inputs specified")
	}
	nOut := len(out)
	if nOut == 0 {
		return fmt.Errorf("empty output specified")
	}
	var sum []byte
	output := make([]byte, nOut)
calc_hash:
	for counter, idx := uint64(1), 0; idx < nOut; counter++ {
		d.hash.Reset()
		if len(sum) > 0 {
			d.hash.Write(sum)
			for i := range sum { // wipe it before hash.Sum changes it
				sum[i] = 0
			}
		}
		d.hash.Write(Uint64BytesStr(counter, true, false))
		for _, in := range ins {
			if len(in) > 0 { // skip the empty ones
				d.hash.Write(in)
			}
		}
		d.hash.Write(Uint64BytesStr(uint64(nOut*8), false, true))
		sum = d.hash.Sum(nil)
    l := len(sum)
    startIdx := int(sum[0]) % l
		for i := 0; i < l; i++ {
			output[idx] = sum[(startIdx + i) % l]
			idx++
			if idx >= nOut {
				break calc_hash // done
			}
		}
	}
	for i := range sum { // wipe it
		sum[i] = 0
	}
	for i, b := range output {
		out[i] = b
		output[i] = 0 // wipe it
	}
	return nil
}

func (d *MyHashDRBG) Reseed(seed []byte) error {
  err := d.hashDf(d.v, Uint64BytesStr(200, true, true), d.v, seed,
		Uint64BytesStr(d.reseedCounter, false, true), Bytes2Hex(d.c, true))
	if err != nil {
		return fmt.Errorf("failed to reseed v part of hash DRBG: %w", err)
	}
	err = d.hashDf(d.c, Uint64BytesStr(300, false, false), Bytes2Hex(d.v, false), d.c)
	if err != nil {
		return fmt.Errorf("failed to reseed c part of hash DRBG: %w", err)
	}
	d.reseedCounter = 1
	return nil
}

func (d *MyHashDRBG) genHash(out []byte) {
  nOut := len(out)
	if nOut == 0 { // no-op
		return
	}
	var sum []byte
calc_hash:
	for counter, idx := uint64(1), 0; idx < nOut; counter++ {
		d.hash.Reset()
		if len(sum) > 0 {
			d.hash.Write(sum)
			for i := range sum { // wipe it
				sum[i] = 0
			}
		}
		d.hash.Write(Uint64BytesStr(counter, true, false))
		d.hash.Write(d.v)
		d.hash.Write(Uint64BytesStr(uint64(nOut*8), false, true))
		d.hash.Write(Bytes2Hex(d.c, true))
		d.hash.Write(Uint64BytesStr(d.reseedCounter, true, true))
		sum = d.hash.Sum(nil)
    l := len(sum)
    startIdx := int(sum[0]) % l
		for i := 0; i < l; i++ {
			out[idx] = sum[(startIdx + i) % l]
			idx++
			if idx >= nOut {
				break calc_hash // done
			}
		}
	}
	for i := range sum { // wipe it
		sum[i] = 0
	}
}

func (d *MyHashDRBG) Generate(out, additionalIn []byte) error {
  lo, li := len(out), len(additionalIn)
  if lo > MaxBytesPerRequest {
    return fmt.Errorf("request length (%d) too long: needs at most %d bytes", lo, MaxBytesPerRequest)
  }
  if li > MaxInputLength {
		return fmt.Errorf("additional input length (%d) too long: needs at most %d bytes", li, MaxInputLength)
	}
  if d.reseedCounter > ReseedInterval {
    return fmt.Errorf("request count exceeds reseed limit (%d): reseed required", ReseedInterval)
  }
  if li > 0 {
    err := d.hashDf(d.v, d.c, Uint64BytesStr(2000, true, false), Bytes2Hex(d.v, false), additionalIn, d.c)
  	if err != nil {
      return fmt.Errorf("failed to reseed v hash: %w", err)
    }
  }
  // gen hash
  d.genHash(out)
  // update
  err := d.hashDf(d.v, Uint64BytesStr(3000, false, true), Bytes2Hex(d.v, true), d.c,
		Uint64BytesStr(d.reseedCounter, true, false))
	if err != nil {
    return fmt.Errorf("failed to reseed v hash: %w", err)
  }
  err = d.hashDf(d.c, Uint64BytesStr(4000, false, false), Bytes2Hex(d.c, false), d.v,
		Uint64BytesStr(d.reseedCounter, true, true))
	if err != nil {
    return fmt.Errorf("failed to reseed c hash: %w", err)
  }
  d.reseedCounter++
  return nil
}

func NewDRBG(h hash.Hash, seed []byte) (*MyHashDRBG, error) {
	outLen := h.Size()
	minLen := outLen / 2
	l := len(seed)
	if l < minLen {
		return nil, fmt.Errorf("seed length (%d) too short: needs at least %d bytes", l, minLen)
	}
	if l > MaxInputLength {
		return nil, fmt.Errorf("seed length (%d) too long: needs at most %d bytes", l, MaxInputLength)
	}
  drbg := MyHashDRBG{hash: h, reseedCounter: 1}
  drbg.seedLen = 55 // 440 bits
  if outLen > 32 {
    drbg.seedLen = 111 // 888 bits
  }
  if drbg.seedLen < outLen {
    drbg.seedLen = outLen
  }
  drbg.v = make([]byte, drbg.seedLen)
	if err := drbg.hashDf(drbg.v, Uint64BytesStr(10, true, true), seed); err != nil {
		return nil, fmt.Errorf("failed to create seed v part of hash DRBG: %w", err)
	}
	drbg.c = make([]byte, drbg.seedLen)
	if err := drbg.hashDf(drbg.c, Uint64BytesStr(20, true, false), Bytes2Hex(drbg.v, true)); err != nil {
		return nil, fmt.Errorf("failed to create seed c part of hash DRBG: %w", err)
	}
	return &drbg, nil
}

func main() {
  seed := make([]byte, 128)
  for i := range seed {
    seed[i] = byte(i & 0x0f)
  }
  
  rng, err := NewDRBG(sha256.New(), seed)
  if err != nil {
    fmt.Printf("ERROR: %s!\n", err)
    return
  }
  
  src := make([]byte, 64)
  start := time.Now()
  N := 10
  for i := 0; i < N; i++ {
    if err := rng.Generate(src, nil); err != nil {
      fmt.Printf("ERROR: %s!\n", err)
      return
    }
	  fmt.Printf("%d: %s\n", i, Bytes2Hex(src, true))
  }
  fmt.Printf("Duration for %d RNG: %s\n", N, time.Since(start))
}
