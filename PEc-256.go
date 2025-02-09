package pec256

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"

	pm256 "github.com/polarysfoundation/pm-256"
)

const (
	keySize = 256 // Size of the keys in bits
)

var PModular = new(Modular) // Initialize the global struct

// Modular struct represents the modular arithmetic structure used for cryptographic operations.
type Modular struct {
	PrimeA   *big.Int // Prime number A used in elliptic curve calculations
	PrimeB   *big.Int // Prime number B used in elliptic curve calculations
	BModular *big.Int // Current base modular used for operations
	KeySize  int      // Size of the cryptographic key in bits
}

// BaseModular returns the current base modular.
func (m *Modular) BaseModular() *big.Int {
	return m.BModular
}

// Builder generates private-public keys from the bytes 'b', checks for constant-time execution,
// and returns the private key, public key, checksum, and shared key.
func (m *Modular) Builder(b []byte) (*big.Int, *big.Int, []byte, SharedKey, error) {
	n, err := generateExactBitLengthPrimes(m.KeySize, 1)
	if err != nil {
		return nil, nil, nil, SharedKey{}, fmt.Errorf("error generating exact bit length primes: %v", err)
	}

	s := m.structurer(b, n[0])

	priv := m.generatePrivKey(s)
	pub, checksum := m.derivatePubKey(priv)

	tpub := pm256.Sum256(pub.Bytes())

	if !constantTimeEqual(tpub[:4], checksum) {
		return nil, nil, nil, SharedKey{}, errors.New("checksum mismatch: potential timing attack detected")
	}

	sharedKey := m.generateSharedKey(priv.BigInt(), pub)

	return priv.BigInt(), pub, checksum, sharedKey, nil
}

// structurer generates a big integer 'y' by performing modular operations with the byte array 'b' and prime 'n'.
func (m *Modular) structurer(b []byte, n *big.Int) *big.Int {
	seed := generateSecureRandomBytes(32)

	x := new(big.Int).Mul(m.PrimeA, m.PrimeB)
	r := new(big.Int).Mul(x.Add(x, m.PrimeA), m.PrimeB)

	seedBigInt := bytesToBigInt(seed)
	seedBigInt.Add(r, n)

	y := new(big.Int).SetInt64(0)

	for i := 0; i < len(b)*8; i++ {
		if (b[i/8] & (0x80 >> uint(i%8))) != 0 {
			y.Add(y, seedBigInt)
			y.Mod(y, m.PrimeA)
		}
		seedBigInt.Mul(seedBigInt, seedBigInt)
		seedBigInt.Mod(seedBigInt, m.PrimeA)
	}

	return y
}

// ShiftBaseModular updates the base modular (BModular) by generating a random seed and applying modular exponentiation.
func (m *Modular) ShiftBaseModular() {
	seed := generateSecureRandomBytes(32)
	s := bytesToBigInt(seed)
	s.Mod(s, m.PrimeA)

	bm := new(big.Int).Exp(m.PrimeB, s, m.PrimeA)
	m.BModular = bm
}

// GenerateKeyPair generates a new private and public key pair and returns them along with a checksum.
func (m *Modular) GenerateKeyPair() (PrivKey, PubKey, []byte, error) {
	return m.generateKeyPair()
}

// generateKeyPair creates a key pair securely by performing dummy operations to ensure constant-time execution.
func (m *Modular) generateKeyPair() (PrivKey, PubKey, []byte, error) {
	initialSeed := generateSecureRandomBytes(64)

	start := makeTimestamp()

	priv, pub, check, _, err := m.Builder(initialSeed)
	if err != nil {
		return PrivKey{}, PubKey{}, nil, err
	}

	dummyLoop := make([]byte, 64)
	for i := range dummyLoop {
		dummyLoop[i] = initialSeed[i] ^ byte(i)
	}

	targetTime := 25 * 1e3 // Target time in microseconds (25ms)
	elapsed := makeTimestamp() - start

	for elapsed < int64(targetTime) {
		_ = subtle.ConstantTimeByteEq(dummyLoop[0], dummyLoop[1])
		elapsed = makeTimestamp() - start
	}

	return BigToPrivKey(priv), BigToPubKey(pub), check, nil
}

// makeTimestamp returns the current time in microseconds.
func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}

// GetPubKey derives the public key and checksum from a given private key.
func (m *Modular) GetPubKey(p PrivKey) (PubKey, []byte) {
	pub, checksum := m.derivatePubKey(p)
	return BigToPubKey(pub), checksum
}

// SharedKey generates a shared secret key using modular exponentiation with a private key.
func (m *Modular) SharedKey(priv PrivKey) SharedKey {
	pub, _ := m.derivatePubKey(priv)
	return m.generateSharedKey(priv.BigInt(), pub)
}

// derivatePubKey calculates the public key and checksum from a given private key.
func (m *Modular) derivatePubKey(p PrivKey) (*big.Int, []byte) {
	priv := bytesToBigInt(p[:])
	pub := new(big.Int).Exp(m.PrimeB, priv, m.PrimeA)
	checksum := pm256.Sum256(pub.Bytes())

	if len(checksum) < 4 {
		panic("public key is too short")
	}
	return pub, checksum[:4]
}

// generatePrivKey creates a private key by performing modular exponentiation with the base modular (BModular).
func (m *Modular) generatePrivKey(n *big.Int) PrivKey {
	p := new(big.Int).Exp(m.BModular, n, m.PrimeA)
	p.Mod(p, m.PrimeA)

	h := pm256.Sum256(p.Bytes())
	return BytesToPrivKey(h[:])
}

// generateSharedKey creates a shared secret key using modular exponentiation with a private and public key.
func (m *Modular) generateSharedKey(privKey, pubKey *big.Int) SharedKey {
	p := new(big.Int).Exp(pubKey, privKey, m.PrimeA)
	h := pm256.Sum256(p.Bytes())
	return BytesToSharedKey(h[:])
}

// bytesToBigInt converts a byte array to a big.Int type for use in modular operations.
func bytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// generateExactBitLengthPrimes generates 'count' number of primes with the exact bit length specified by 'bits'.
func generateExactBitLengthPrimes(bits int, count int) ([]*big.Int, error) {
	primes := make([]*big.Int, 0, count)

	for i := 0; i < count; i++ {
		for {
			randomNum, err := rand.Prime(rand.Reader, bits)
			if err != nil {
				return nil, err
			}

			if randomNum.BitLen() == bits {
				primes = append(primes, randomNum)
				break
			}
		}
	}
	return primes, nil
}

// IsValidPubKey verifies if the 'q' PubKey is valid.
func (m *Modular) IsValidPubKey(q *big.Int) bool {
	return q.Cmp(big.NewInt(1)) > 0 && q.Cmp(m.PrimeA) < 0
}

// generateSecureK generates a secure random integer 'k' in the range [1, n-1].
func generateSecureK(n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(n, one)

	for i := 0; i < 1000; i++ {
		k, err := rand.Int(rand.Reader, nMinusOne)
		if err != nil {
			return nil, err
		}
		k.Add(k, one)

		if isValidK(k, n) {
			return k, nil
		}
	}

	return nil, errors.New("failed to generate valid k after multiple attempts")
}

// isValidK checks if 'k' is a valid random integer for cryptographic operations.
func isValidK(k, n *big.Int) bool {
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(n, one)

	return k.Cmp(one) > 0 && k.Cmp(nMinusOne) < 0 &&
		new(big.Int).GCD(nil, nil, k, nMinusOne).Cmp(one) == 0
}

// Sign generates a cryptographic signature (r, s) for the given data using the private key.
func (m *Modular) Sign(data []byte, privateKey *big.Int) (*big.Int, *big.Int, error) {
	if privateKey == nil || privateKey.Sign() <= 0 || privateKey.Cmp(m.PrimeA) >= 0 {
		return nil, nil, errors.New("invalid private key")
	}

	hash := pm256.Sum256(data)
	e := bytesToBigInt(hash[:])

	n := new(big.Int).Sub(m.PrimeA, big.NewInt(1))
	n.Div(n, big.NewInt(2))

	var r, s *big.Int

	for {
		k, err := generateSecureK(n)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate secure k: %v", err)
		}

		r = new(big.Int).Exp(m.PrimeB, k, m.PrimeA)
		if r.Sign() == 0 {
			continue
		}

		kInv := new(big.Int).ModInverse(k, n)
		if kInv == nil {
			continue
		}

		s = new(big.Int).Mul(r, privateKey)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, n)

		// Ensure s is not 0 and has a modular inverse
		if s.Sign() != 0 && new(big.Int).GCD(nil, nil, s, n).Cmp(big.NewInt(1)) == 0 {
			return r, s, nil
		}
	}
}

// Verify checks the validity of a signature (r, s) over the given 'data' using the public key.
func (m *Modular) Verify(data []byte, r, s, publicKey *big.Int) (bool, error) {
	if publicKey == nil || r == nil || s == nil {
		return false, errors.New("invalid input parameters")
	}

	n := new(big.Int).Sub(m.PrimeA, big.NewInt(1))
	n.Div(n, big.NewInt(2))

	if r.Cmp(big.NewInt(1)) <= 0 || r.Cmp(m.PrimeA) >= 0 {
		return false, errors.New("r is out of range")
	}
	if s.Cmp(big.NewInt(1)) <= 0 || s.Cmp(n) >= 0 {
		return false, errors.New("s is out of range")
	}

	// Ensure s has a modular inverse
	if new(big.Int).GCD(nil, nil, s, n).Cmp(big.NewInt(1)) != 0 {
		return false, errors.New("s has no modular inverse")
	}

	hash := pm256.Sum256(data)
	e := bytesToBigInt(hash[:])

	w := new(big.Int).ModInverse(s, n)
	if w == nil {
		return false, errors.New("s has no modular inverse")
	}

	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, n)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, n)

	v := new(big.Int).Exp(m.PrimeB, u1, m.PrimeA)
	temp := new(big.Int).Exp(publicKey, u2, m.PrimeA)
	v.Mul(v, temp)
	v.Mod(v, m.PrimeA)

	return v.Cmp(r) == 0, nil
}

func init() {
	PModular.PrimeA, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	PModular.PrimeB, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	PModular.KeySize = keySize
	PModular.ShiftBaseModular()
}

// PEC256 returns the global Modular instance.
func PEC256() *Modular {
	return PModular
}

// constantTimeEqual compares two byte slices in constant time, ensuring no early exit points.
func constantTimeEqual(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

// generateSecureRandomBytes generates a secure random byte array of the specified length.
func generateSecureRandomBytes(length int) []byte {
	seed := make([]byte, length)
	if _, err := rand.Read(seed); err != nil {
		panic("failed to generate secure random seed")
	}
	return seed
}
