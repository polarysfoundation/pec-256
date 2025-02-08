package pec256

import (
	"encoding/hex"
	"math/big"
)

const (
	sharedKeyLen = 16
	privKeyLen   = 32
	pubKeyLen    = 32
)

type SharedKey [sharedKeyLen]byte

func BytesToSharedKey(b []byte) SharedKey {
	var s SharedKey
	s.SetBytes(b)
	return s
}

func (s SharedKey) BigInt() *big.Int {
	return new(big.Int).SetBytes(s[:])
}

func (s SharedKey) Bytes() []byte {
	return s[:]
}

func (s SharedKey) String() string {
	return hex.EncodeToString(s[:])
}

func (s *SharedKey) SetBytes(b []byte) {
	if len(b) > len(s) {
		b = b[len(b)-sharedKeyLen:]
	}

	copy(s[sharedKeyLen-len(b):], b)
}

type PrivKey [privKeyLen]byte

func BytesToPrivKey(b []byte) PrivKey {
	var p PrivKey

	p.SetBytes(b)

	return p
}

func BigToPrivKey(n *big.Int) PrivKey {
	return BytesToPrivKey(n.Bytes())
}

func StringToPrivKey(s string) PrivKey {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("Error decoding the PrivKey")
	}

	return BytesToPrivKey(b)
}

func (p PrivKey) BigInt() *big.Int {
	return new(big.Int).SetBytes(p[:])
}

func (p PrivKey) String() string {
	return hex.EncodeToString(p[:])
}

func (p PrivKey) ToBytes() []byte {
	return p[:]
}

func (p PrivKey) BitLen() int {
	return p.BigInt().BitLen()
}

func (p *PrivKey) SetBytes(b []byte) {
	if len(b) > len(p) {
		b = b[len(b)-privKeyLen:]
	}

	copy(p[privKeyLen-len(b):], b)
}

type PubKey [pubKeyLen]byte

func BytesToPubKey(b []byte) PubKey {
	var p PubKey

	p.SetBytes(b)

	return p
}

func (p PubKey) BitLen() int {
	return p.BigInt().BitLen()
}

func StringToPubKey(s string) PubKey {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("Error decoding the PubKey")
	}

	return BytesToPubKey(b)
}

func BigToPubKey(n *big.Int) PubKey {
	return BytesToPubKey(n.Bytes())
}

func (p PubKey) BigInt() *big.Int {
	return new(big.Int).SetBytes(p[:])
}

func (p PubKey) String() string {
	return hex.EncodeToString(p[:])
}

func (p PubKey) Bytes() []byte {
	return p[:]
}

func (p *PubKey) SetBytes(b []byte) {
	if len(b) > len(p) {
		b = b[len(b)-pubKeyLen:]
	}

	copy(p[pubKeyLen-len(b):], b)
}
