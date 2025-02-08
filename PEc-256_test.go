package pec256

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	rnd "math/rand"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	pm256 "github.com/polarysfoundation/pm-256"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

const (
	privA = "dd13568bc4cb292be0fc1ffa3714e286eb82260c37c0d6115cbe4b79ccf34d9e"
	pubA  = "d80958cc5263ccb182d1739d23c0b7cfc186ad99ac934912a3e7c9b1a1a3b83c"
	privB = "463eb2aaac46acde4912a049cdd65f2aaa34a7ac85830afcad7fb459a26fef8d"
	pubB  = "5fe68b723b413bfded07fef4724da34086d0ce0fb0a7a50dd9b64ce5f1269bac"
)

func init() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	var err error
	logger, err = config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize zap logger: %v", err))
	}
}

func TestMain(m *testing.M) {
	// Set up logging
	f, err := os.Create("pec256_test.log")
	if err != nil {
		logger.Fatal("Failed to create log file", zap.Error(err))
	}
	defer f.Close()

	// Run tests
	code := m.Run()

	// Teardown
	logger.Sync()
	os.Exit(code)
}

func TestPubKeyValidation(t *testing.T) {
	logger.Info("Starting pubkey test validation")

	m := PEC256()

	priv := StringToPrivKey(privA)

	pub, _ := m.GetPubKey(priv)

	logger.Info("Pubkey generated", zap.String("pubkey", pub.String()))

	if pub.String() != pubA {
		t.Errorf("Error in obtaining the public key, the key does not match the original. A: %v, B: %v", pubA, pub)
	}

	logger.Info("Pubkey validation completed", zap.String("generated", pub.String()), zap.String("expected", pubA))
}

func TestSignature(t *testing.T) {
	logger.Info("Starting signature test validation")

	m := PEC256()

	message := []byte("este es un mensaje de prueba")

	msgHash := pm256.Sum256(message)

	// Sign the message
	logger.Info("Signing message")
	r, s, err := m.Sign(msgHash[:], StringToPrivKey(privA).BigInt())
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	// Create a slice of 64 bytes to store the signature (32 bytes for r, 32 bytes for s)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	logger.Info("Signature generated", zap.String("signature", hex.EncodeToString(signature)))

	isValid, err := m.Verify(msgHash[:], r, s, StringToPubKey(pubA).BigInt())
	if err != nil {
		t.Errorf("Error verifying signature: %v", err)
	}

	// Verify the signature
	if !isValid {
		t.Errorf("Signature verification failed: %v", hex.EncodeToString(signature))
	} else {
		logger.Info("Signature verified successfully")
	}
}

func TestSignature2(t *testing.T) {
	logger.Info("Starting signature test validation")
	message := []byte("Test message")

	priv, pub, _, err := PModular.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
	}
	logger.Info("Generated Private Key", zap.String("private_key", hex.EncodeToString(priv[:])))

	if !PModular.IsValidPubKey(pub.BigInt()) {
		t.Errorf("Invalid pubkey: %s", pub.String())
	}

	logger.Info("Signing message")
	r, s, err := PModular.Sign(message, priv.BigInt())
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	logger.Info("Public Key", zap.String("public_key", hex.EncodeToString(pub[:])))

	isValid, err := PModular.Verify(message, r, s, pub.BigInt())
	if err != nil {
		t.Errorf("Error verifying signature: %v", err)
	}

	if !isValid {
		t.Errorf("Signature verification failed: %x", signature)
	} else {
		logger.Info("Signature verified successfully")
	}
}

func TestModifiedSignature(t *testing.T) {
	logger.Info("Starting modified signature test validation")

	message := []byte("Test message")
	priv, pub, _, err := PModular.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
	}
	logger.Info("Generated Private Key", zap.String("private_key", hex.EncodeToString(priv[:])))

	logger.Info("Signing message")
	r, s, err := PModular.Sign(message, priv.BigInt())
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	logger.Info("Public Key", zap.String("public_key", hex.EncodeToString(pub[:])))

	messageModified := []byte("Test message 2")

	isValid, err := PModular.Verify(messageModified, r, s, pub.BigInt())
	if err != nil {
		logger.Error("Error verifying signature", zap.Error(err))
	}

	if isValid {
		t.Errorf("Signature with invalid message verified: %x", signature)
	} else {
		logger.Info("Test completed successfully")
	}
}

func TestInvalidPubKey(t *testing.T) {
	logger.Info("Starting invalid pubkey test validation")

	message := []byte("Test message")
	priv, pub, _, err := PModular.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
	}
	logger.Info("Generated Private Key", zap.String("private_key", hex.EncodeToString(priv[:])))

	logger.Info("Signing message")
	r, s, err := PModular.Sign(message, priv.BigInt())
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	logger.Info("Public Key", zap.String("public_key", hex.EncodeToString(pub[:])))

	isValid, err := PModular.Verify(message, r, s, StringToPubKey(pubB).BigInt())
	if err != nil {
		logger.Error("Error verifying signature", zap.Error(err))
	}

	if isValid {
		t.Errorf("Signature with invalid pubkey verified: %x", signature)
	} else {
		logger.Info("Test completed successfully")
	}
}

func TestConstantTimeKeyGeneration(t *testing.T) {
	m := PEC256()

	times := make([]time.Duration, 100)
	logger.Info("Starting constant-time key generation test")

	for i := 0; i < 100; i++ {
		start := time.Now()
		_, _, _, err := m.GenerateKeyPair()
		if err != nil {
			t.Errorf("Error generating key pair: %v", err)
		}
		duration := time.Since(start)
		times[i] = duration
		logger.Debug("Key generation duration", zap.Int("iteration", i+1), zap.Duration("duration", duration))
	}

	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	var sum time.Duration
	for _, d := range times {
		sum += d
	}
	avg := sum / time.Duration(len(times))

	median := times[len(times)/2]
	min, max := times[0], times[len(times)-1]

	logger.Info("Key generation time statistics",
		zap.Duration("average", avg),
		zap.Duration("median", median),
		zap.Duration("min", min),
		zap.Duration("max", max),
	)

	maxDiff := max - min

	if maxDiff > 2*time.Millisecond {
		t.Errorf("Key generation times varied by more than 2ms (max difference: %v)", maxDiff)
	}

	// Print histogram
	buckets := make(map[int]int)
	for _, d := range times {
		bucket := int(d / time.Millisecond)
		buckets[bucket]++
	}

	logger.Info("Histogram of generation times (each * represents one generation):")
	for i := 25; i <= 35; i++ {
		logger.Info(fmt.Sprintf("%2dms: %s", i, strings.Repeat("*", buckets[i])))
	}
}

func TestSideChannelResistance(t *testing.T) {
	m := PEC256()

	logger.Info("Starting side channel resistance test")

	priv1, _, _, err := m.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
	}
	priv2, _, _, err := m.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
	}

	logger.Debug("Generated private keys",
		zap.String("priv1", hex.EncodeToString(priv1[:])),
		zap.String("priv2", hex.EncodeToString(priv2[:])),
	)

	if bytes.Equal(priv1[:], priv2[:]) {
		logger.Error("Generated identical private keys")
		t.Fatal("Generated identical private keys")
	}

	start1 := time.Now()
	pub1, _ := m.derivatePubKey(priv1)
	time1 := time.Since(start1)

	start2 := time.Now()
	pub2, _ := m.derivatePubKey(priv2)
	time2 := time.Since(start2)

	logger.Info("Public key derivation times",
		zap.Duration("time1", time1),
		zap.Duration("time2", time2),
		zap.Duration("difference", time1-time2),
	)

	if time1-time2 > 100*time.Microsecond {
		logger.Warn("Public key derivation time varies too much",
			zap.Duration("time1", time1),
			zap.Duration("time2", time2),
			zap.Duration("difference", time1-time2),
		)
		t.Errorf("Public key derivation time varies too much. Time1: %v, Time2: %v", time1, time2)
	}

	if pub1.Cmp(pub2) == 0 {
		logger.Error("Generated identical public keys for different private keys")
		t.Fatal("Generated identical public keys for different private keys")
	}
}

func TestMemoryUsage(t *testing.T) {
	m := PEC256()

	logger.Info("Starting memory usage test")

	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	iterations := 1000
	logger.Info("Performing key operations", zap.Int("iterations", iterations))

	for i := 0; i < iterations; i++ {
		priv, pub, _, err := m.GenerateKeyPair()
		if err != nil {
			t.Errorf("Error generating key pair: %v", err)
		}
		shared := m.generateSharedKey(priv.BigInt(), pub.BigInt())

		if i%100 == 0 {
			logger.Debug("Memory test progress",
				zap.Int("iteration", i),
				zap.String("shared_key", hex.EncodeToString(shared[:])),
			)
		}

		runtime.KeepAlive(shared)
	}

	runtime.ReadMemStats(&m2)

	allocDiff := m2.TotalAlloc - m1.TotalAlloc
	mallocDiff := m2.Mallocs - m1.Mallocs

	logger.Info("Memory usage",
		zap.Uint64("alloc_bytes", allocDiff),
		zap.Uint64("num_mallocs", mallocDiff),
		zap.Float64("bytes_per_iteration", float64(allocDiff)/float64(iterations)),
		zap.Float64("mallocs_per_iteration", float64(mallocDiff)/float64(iterations)),
	)
}

func TestFuzzingInputs(t *testing.T) {
	m := PEC256()

	iterations := 1000
	logger.Info("Starting fuzzing test", zap.Int("iterations", iterations))

	for i := 0; i < iterations; i++ {
		inputLength := rnd.Intn(1000)
		input := make([]byte, inputLength)
		_, err := rand.Read(input)
		if err != nil {
			logger.Error("Failed to generate random input", zap.Error(err))
			t.Fatal(err)
		}

		n, err := generateExactBitLengthPrimes(m.KeySize, 1)
		if err != nil {
			t.Errorf("Error generating exact bit length primes: %v", err)
		}
		result := m.structurer(input, n[0])

		if i%100 == 0 {
			logger.Debug("Fuzzing iteration",
				zap.Int("iteration", i),
				zap.Int("input_length", inputLength),
				zap.String("result", result.String()),
			)
		}

		if result.Cmp(m.PrimeA) >= 0 {
			logger.Warn("structurer output out of range",
				zap.Int("input_length", inputLength),
				zap.String("result", result.String()),
			)
			t.Errorf("structurer output out of range for input length %d", inputLength)
		}
	}

	logger.Info("Fuzzing test completed")
}

func BenchmarkKeyGeneration(b *testing.B) {
	m := PEC256()
	logger.Info("Starting key generation benchmark", zap.Int("iterations", b.N))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := m.GenerateKeyPair()
		if err != nil {
			b.Errorf("Error generating key pair: %v", err)
		}
	}

	b.StopTimer()
	logger.Info("Key generation benchmark completed", zap.Int("iterations", b.N))
}

func BenchmarkKeyExchange(b *testing.B) {
	m := PEC256()
	alicePriv, alicePub, _, err := m.GenerateKeyPair()
	if err != nil {
		b.Errorf("Error generating key pair: %v", err)
	}
	bobPriv, bobPub, _, err := m.GenerateKeyPair()
	if err != nil {
		b.Errorf("Error generating key pair: %v", err)
	}

	logger.Info("Starting key exchange benchmark",
		zap.Int("iterations", b.N),
		zap.String("alice_pub", hex.EncodeToString(alicePub[:])),
		zap.String("bob_pub", hex.EncodeToString(bobPub[:])),
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.generateSharedKey(alicePriv.BigInt(), bobPub.BigInt())
		m.generateSharedKey(bobPriv.BigInt(), alicePub.BigInt())
	}

	b.StopTimer()
	logger.Info("Key exchange benchmark completed", zap.Int("iterations", b.N))
}
