# becc – Basic Elliptic Curve Cryptography

`becc` is a from-scratch implementation of core elliptic curve cryptography primitives written in Go. The project was created to deeply understand how elliptic curves work in practice: from field arithmetic and point operations, through scalar multiplication, to real cryptographic protocols.

It is **not** intended as production code (use established libraries like `crypto/ecdsa` or `btcsuite/btcd/btcec` for that). It is a clean, well-tested, educational codebase that implements the most important ECC algorithms people actually use in 2025.

## Features

- Multiple Weierstrass curves:
  - secp256k1 (Bitcoin/Ethereum)
  - secp256r1 (NIST P-256)
  - secp384r1 (NIST P-384)
  - secp521r1 (NIST P-521)
- Constant-time-ish scalar multiplication (double-and-add)
- ECDSA signing & verification (with low-s normalization)
- Deterministic ECDSA (RFC 6979)
- ECDH key agreement (compressed shared secret)
- Hybrid encryption/decryption (ephemeral ECDH + HKDF + AES-256-GCM)
- CLI tool with subcommands for key generation, signing, verification, ECDH, and hybrid file encrypt/decrypt

All arithmetic is done with `*big.Int` and a custom `FieldElement` type to ensure correctness before performance.

## Why this project exists

Elliptic curve cryptography powers most of modern security (TLS, Bitcoin, Signal, SSH, etc.), yet the actual math and implementation details are often hidden behind libraries. This project is an attempt to build everything from first principles — field operations, point addition/doubling, scalar multiplication, signature schemes, key agreement, and hybrid encryption — while keeping the code readable and well-tested.

The goal was understanding: how the group law works and why it is definied in that way, what parameters are valid for a Weierstrass curve, why deterministic nonces matter, how forward secrecy is achieved, how AES-GCM provides both confidentiality and integrity, among other things.

## What the CLI can do

### Key generation

```bash
# Generate a new secp256k1 key pair (default curve)
becc key gen

# Use secp384r1
becc key gen --curve secp384r1
```

Output example:
```
private key: 2f8bde4d1a07209355b4a7250a5c5128e88b84bff619d7d0d...
public key:  04a4d0c3f... (uncompressed)
```

### Get public key from private key

```bash
becc key public --private-key 2f8bde4d1a07209355b4a7250a5c5128e88b84bff619d7d0...
```

### ECDSA sign & verify

```bash
# Sign message from stdin (deterministic by default)
echo -n "hello" | becc ecdsa sign --private-key <priv>

# Verify
echo -n "hello" | becc ecdsa verify <r-in-hex><s-in-hex> --public-key <pub>
```

### ECDH shared secret

```bash
becc ecdh <remote-public-key-hex> --private-key <my-priv>
```

Returns 33-byte compressed shared point (02/03 + x).

### Hybrid file encryption/decryption

```bash
# Encrypt file for a recipient
becc hybrid encrypt <recipient-pub-hex> < file.txt > file.enc

# Decrypt with your private key
becc hybrid decrypt < file.enc > file.txt.dec
```

The encrypted file format is:

```
33 bytes  (compressed ephemeral public key)
12 bytes  (AES-GCM nonce)
N bytes   (ciphertext)
16 bytes  (authentication tag)
```

## Installation

Clone and build:

```bash
git clone https://github.com/artilugio0/becc
cd becc
go build -o becc ./cmd/becc
```

## Security warning

This is an **educational** implementation. It has **not** been audited and should **not** be used to protect real data or assets. Use battle-tested libraries for production.

## License

MIT

Feel free to open issues or PRs — contributions to documentation, tests, or additional curves are very welcome!
