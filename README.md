# PEC256: A Cryptographic Library for Elliptic Curve Operations

## Overview

**PEC256** is a Go-based cryptographic library designed for secure elliptic curve operations, including key generation, signing, verification, and shared secret derivation. It leverages modular arithmetic and constant-time algorithms to ensure robust security and resistance against timing attacks. The library is built around a custom elliptic curve defined by two prime numbers (`PrimeA` and `PrimeB`) and supports 256-bit key sizes.

This library is ideal for applications requiring secure cryptographic operations, such as digital signatures, key exchange, and secure communication protocols.

---

## Features

- **Key Pair Generation**: Securely generate private and public key pairs.
- **Digital Signatures**: Sign data using private keys and verify signatures using public keys.
- **Shared Secret Derivation**: Generate shared secrets for secure communication.
- **Constant-Time Execution**: Prevent timing attacks by ensuring all operations execute in constant time.
- **Modular Arithmetic**: Perform cryptographic operations using custom primes and modular arithmetic.
- **Checksum Validation**: Ensure data integrity with checksum validation during key derivation.

---

## Installation

To use the PEC256 library in your Go project, install it using `go get`:

```bash
go get github.com/polarysfoundation/pec-256
```

---

## Usage

### Initialization

The library initializes a global `Modular` instance with predefined primes (`PrimeA` and `PrimeB`). You can access this instance using the `PEC256()` function:

```go
modular := pec256.PEC256()
```

### Key Pair Generation

Generate a new private-public key pair:

```go
privKey, pubKey, checksum, err := modular.GenerateKeyPair()
if err != nil {
    log.Fatalf("Failed to generate key pair: %v", err)
}
fmt.Printf("Private Key: %x\n", privKey)
fmt.Printf("Public Key: %x\n", pubKey)
fmt.Printf("Checksum: %x\n", checksum)
```

### Signing Data

Sign a message using a private key:

```go
data := []byte("Hello, PEC256!")
r, s, err := modular.Sign(data, privKey.ToBig())
if err != nil {
    log.Fatalf("Failed to sign data: %v", err)
}
fmt.Printf("Signature (r, s): (%x, %x)\n", r, s)
```

### Verifying Signatures

Verify a signature using a public key:

```go
valid, err := modular.Verify(data, r, s, pubKey.ToBig())
if err != nil {
    log.Fatalf("Failed to verify signature: %v", err)
}
if valid {
    fmt.Println("Signature is valid!")
} else {
    fmt.Println("Signature is invalid!")
}
```

### Shared Secret Derivation

Generate a shared secret using a private key and a peer's public key:

```go
sharedKey := modular.SharedKey(privKey)
fmt.Printf("Shared Key: %x\n", sharedKey)
```

---

## Advanced Features

### Custom Primes

The library uses predefined primes (`PrimeA` and `PrimeB`), but you can modify them for custom use cases:

```go
modular.PrimeA, _ = new(big.Int).SetString("YourPrimeAHex", 16)
modular.PrimeB, _ = new(big.Int).SetString("YourPrimeBHex", 16)
modular.ShiftBaseModular() // Update the base modular
```

### Constant-Time Operations

All operations are designed to execute in constant time to prevent timing attacks. For example, the `constantTimeEqual` function ensures secure comparison of byte slices:

```go
isEqual := constantTimeEqual([]byte("abc"), []byte("abc"))
fmt.Println("Byte slices are equal:", isEqual)
```

### Secure Randomness

The library uses `crypto/rand` for secure random number generation, ensuring unpredictable behavior during cryptographic operations:

```go
seed := make([]byte, 32)
_, err := rand.Read(seed)
if err != nil {
    log.Fatalf("Failed to generate secure random seed: %v", err)
}
```

---

## Security Considerations

- **Timing Attacks**: The library ensures constant-time execution for all critical operations.
- **Randomness**: Secure random number generation is used for key generation and signing.
- **Checksum Validation**: Checksums are used to detect tampering during key derivation.
- **Prime Selection**: The predefined primes are carefully chosen to ensure cryptographic security.

---

## Example Workflow

1. **Generate Key Pair**:
   ```go
   privKey, pubKey, checksum, err := modular.GenerateKeyPair()
   ```

2. **Sign Data**:
   ```go
   r, s, err := modular.Sign(data, privKey.ToBig())
   ```

3. **Verify Signature**:
   ```go
   valid, err := modular.Verify(data, r, s, pubKey.ToBig())
   ```

4. **Derive Shared Secret**:
   ```go
   sharedKey := modular.SharedKey(privKey)
   ```

---

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Polarys Foundation**: For the `pm256` package used for checksum generation.
- **Go Crypto Libraries**: For providing the foundation for secure cryptographic operations.

---

## Disclaimer

This library is provided as-is, without any warranties. Use it at your own risk. Always consult a security expert before using cryptographic libraries in production environments.

---

By using **PEC256**, you agree to the terms outlined in the [LICENSE](LICENSE) file.