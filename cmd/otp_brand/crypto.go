package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	blst "github.com/supranational/blst/bindings/go"
)

// BLS min-sig variant: signatures are compressed G1 (48 bytes), public keys are
// compressed G2 (96 bytes).
//
// IMPORTANT — the DST is the first 29 bytes only. The original tool passed a
// hardcoded length of 29 to blst, truncating this string to
// "BLS_SIG_BLS12381G1_XMD:SHA-25". That truncated DST is what every existing key
// and signature was produced with, so it MUST be reproduced byte-for-byte here
// for compatibility (changing it would invalidate all branded boards). Likely an
// upstream bug, but it is now load-bearing.
var blsDST = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")[:29]

type blsSignature = blst.P1Affine // signature in G1
type blsPublicKey = blst.P2Affine // public key in G2

// signBlock produces a 48-byte BLS12-381 compressed G1 signature over dataBlock[0:14].
func signBlock(dataBlock, keyBytes []byte) ([]byte, error) {
	if len(dataBlock) != 32 || len(keyBytes) != 32 {
		return nil, fmt.Errorf("dataBlock must be 32 bytes, keyBytes must be 32 bytes")
	}

	sk := new(blst.SecretKey).FromBEndian(keyBytes)
	if sk == nil {
		return nil, fmt.Errorf("invalid private key (not a valid scalar)")
	}

	sig := new(blsSignature).Sign(sk, dataBlock[0:14], blsDST)
	if sig == nil {
		return nil, fmt.Errorf("signing failed")
	}
	sigCompressed := sig.Compress()
	if len(sigCompressed) != 48 {
		return nil, fmt.Errorf("unexpected signature length %d", len(sigCompressed))
	}

	// Self-check: verify the signature we just produced.
	if valid, err := verifySignatureWithSk(keyBytes, dataBlock, sigCompressed); err != nil || !valid {
		if err != nil {
			return nil, fmt.Errorf("BUG: freshly produced signature fails self-verification: %w", err)
		}
		return nil, fmt.Errorf("BUG: freshly produced signature fails self-verification")
	}

	return sigCompressed, nil
}

// verifySignatureFromFile verifies the BLS signature stored in a 64-byte otp_blocks.bin
// using a 32-byte private key. Returns (valid, jsonPayload, error).
func verifySignatureFromFile(binPath, privKeyPath string) (bool, string, error) {
	binData, err := os.ReadFile(binPath)
	if err != nil {
		return false, "", fmt.Errorf("reading %s: %w", binPath, err)
	}
	if len(binData) != 64 {
		return false, "", fmt.Errorf("%s must be exactly 64 bytes, got %d", binPath, len(binData))
	}

	keyBytes, err := loadPrivateKey(privKeyPath)
	if err != nil {
		return false, "", fmt.Errorf("loading private key: %w", err)
	}

	// Reconstruct signature from blocks:
	//   Block 0 bytes 16..31 = sig[0:16]
	//   Block 1 bytes  0..31 = sig[16:48]
	var sig [48]byte
	copy(sig[0:16], binData[16:32])
	copy(sig[16:48], binData[32:64])

	// Data block for hashing: bytes 0..13 (data fields) plus padding 14..31
	var dataBlock [32]byte
	copy(dataBlock[:], binData[0:16])
	for i := 16; i < 32; i++ {
		dataBlock[i] = 0xFF
	}

	valid, err := verifySignatureWithSk(keyBytes, dataBlock[:], sig[:])
	if err != nil {
		return false, "", fmt.Errorf("verification error: %w", err)
	}

	info := formatOTPInfo(dataBlock[:])
	return valid, info, nil
}

// verifySignatureWithSk verifies (msg[0:14], sig) against the public key derived from sk.
func verifySignatureWithSk(skBytes, msg, sig []byte) (bool, error) {
	if len(skBytes) != 32 {
		return false, fmt.Errorf("private key must be 32 bytes")
	}
	if len(sig) != 48 {
		return false, fmt.Errorf("signature must be 48 bytes (compressed G1)")
	}
	if len(msg) < 14 {
		return false, fmt.Errorf("message must be at least 14 bytes")
	}

	// Derive public key in G2 from private key.
	sk := new(blst.SecretKey).FromBEndian(skBytes)
	if sk == nil {
		return false, fmt.Errorf("invalid private key (not a valid scalar)")
	}
	pk := new(blsPublicKey).From(sk)
	if pk == nil {
		return false, fmt.Errorf("public key derivation failed")
	}

	// Uncompress signature from compressed G1.
	sigAff := new(blsSignature).Uncompress(sig)
	if sigAff == nil {
		return false, fmt.Errorf("signature decompression failed")
	}

	// Core verify: e(sig, g2) == e(H(m), pk), hashing the 14 data bytes.
	return sigAff.Verify(true, pk, true, msg[0:14], blsDST), nil
}

// verifySignatureFromPubFile verifies using a 96-byte compressed G2 public key file.
func verifySignatureFromPubFile(binPath, pubKeyPath string) (bool, string, error) {
	binData, err := os.ReadFile(binPath)
	if err != nil {
		return false, "", fmt.Errorf("reading %s: %w", binPath, err)
	}
	if len(binData) != 64 {
		return false, "", fmt.Errorf("%s must be exactly 64 bytes, got %d", binPath, len(binData))
	}

	pubKeyHex, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return false, "", fmt.Errorf("reading public key %s: %w", pubKeyPath, err)
	}
	pubKeyHex = []byte(strings.TrimSpace(string(pubKeyHex)))
	pubBytes, err := hex.DecodeString(string(pubKeyHex))
	if err != nil {
		return false, "", fmt.Errorf("public key is not valid hex: %w", err)
	}
	if len(pubBytes) != 96 {
		return false, "", fmt.Errorf("public key must be 96 bytes (compressed G2), got %d", len(pubBytes))
	}

	// Reconstruct signature from blocks
	var sig [48]byte
	copy(sig[0:16], binData[16:32])
	copy(sig[16:48], binData[32:64])

	var dataBlock [32]byte
	copy(dataBlock[:], binData[0:16])
	for i := 16; i < 32; i++ {
		dataBlock[i] = 0xFF
	}

	valid, err := verifySignatureWithPub(pubBytes, dataBlock[:], sig[:])
	if err != nil {
		return false, "", fmt.Errorf("verification error: %w", err)
	}

	info := formatOTPInfo(dataBlock[:])
	return valid, info, nil
}

// verifySignatureWithPub verifies (msg[0:14], sig) against a 96-byte compressed G2 public key.
func verifySignatureWithPub(pkCompressed, msg, sig []byte) (bool, error) {
	if len(pkCompressed) != 96 {
		return false, fmt.Errorf("public key must be 96 bytes (compressed G2)")
	}
	if len(sig) != 48 {
		return false, fmt.Errorf("signature must be 48 bytes (compressed G1)")
	}
	if len(msg) < 14 {
		return false, fmt.Errorf("message must be at least 14 bytes")
	}

	// Uncompress public key from G2.
	pk := new(blsPublicKey).Uncompress(pkCompressed)
	if pk == nil {
		return false, fmt.Errorf("public key decompression failed")
	}

	// Uncompress signature from compressed G1.
	sigAff := new(blsSignature).Uncompress(sig)
	if sigAff == nil {
		return false, fmt.Errorf("signature decompression failed")
	}

	return sigAff.Verify(true, pk, true, msg[0:14], blsDST), nil
}

// generateKey creates a new BLS12-381 key pair and saves both private and public keys.
func generateKey(path string) error {
	var ikm [32]byte
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Read(ikm[:]); err != nil {
		return err
	}

	sk := blst.KeyGen(ikm[:])
	if sk == nil {
		return fmt.Errorf("key generation failed")
	}
	keyBytes := sk.ToBEndian()

	// Compute public key in G2 (min-sig variant: sig in G1, pk in G2).
	pk := new(blsPublicKey).From(sk)
	pubBytes := pk.Compress()

	if err := os.WriteFile(path, keyBytes, 0600); err != nil {
		return err
	}

	pubPath := path + ".pub"
	os.WriteFile(pubPath, []byte(hex.EncodeToString(pubBytes)+"\n"), 0644)

	fmt.Printf("Private key saved to: %s (%d bytes)\n", path, len(keyBytes))
	fmt.Printf("Key hex:    %s\n", hex.EncodeToString(keyBytes))
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubBytes))
	fmt.Printf("Public key saved to: %s\n", pubPath)
	fmt.Println()
	fmt.Println("Store this key securely! Recommended: ~/.config/xesc/keys/builder*.key")
	fmt.Println("Permissions set to 600 (owner read/write only).")
	return nil
}

// dumpPubKey prints the public key for a private key file.
func dumpPubKey(path string) error {
	keyBytes, err := loadPrivateKey(path)
	if err != nil {
		return err
	}

	sk := new(blst.SecretKey).FromBEndian(keyBytes)
	if sk == nil {
		return fmt.Errorf("invalid private key (not a valid scalar)")
	}
	pk := new(blsPublicKey).From(sk)
	pubBytes := pk.Compress()

	fmt.Printf("Private key: %s\n", path)
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubBytes))
	return nil
}

// loadPrivateKey reads a 32-byte private key from a file (raw binary or hex).
func loadPrivateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	if len(data) == 64 {
		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("key file is 64 chars but not valid hex: %w", err)
		}
		data = decoded
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(data))
	}
	return data, nil
}
