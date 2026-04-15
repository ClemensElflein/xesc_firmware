package main

/*
#cgo CFLAGS: -I../../hwconf/xtech/xesc2_mini -I/tmp/blst/bindings -I/tmp/blst/build -I/tmp/blst/src -D__BLST_CGO__ -fno-builtin-memcpy -fno-builtin-memset
#cgo amd64 CFLAGS: -D__ADX__ -mno-avx
#cgo LDFLAGS: -L/tmp/blst -lblst

#include "xesc2_otp.h"
#include "blst.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// signBlock produces a 48-byte BLS12-381 compressed G1 signature over dataBlock[0:14].
func signBlock(dataBlock, keyBytes []byte) ([]byte, error) {
	if len(dataBlock) != 32 || len(keyBytes) != 32 {
		return nil, fmt.Errorf("dataBlock must be 32 bytes, keyBytes must be 32 bytes")
	}

	// Load scalar from key bytes (big-endian)
	var sk C.blst_scalar
	C.blst_scalar_from_bendian(&sk, (*C.uchar)(unsafe.Pointer(&keyBytes[0])))

	// Hash message (bytes 0..13) to G1
	var hashP1 C.blst_p1
	dst := C.CString("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
	defer C.free(unsafe.Pointer(dst))
	msg := dataBlock[0:14]
	C.blst_hash_to_g1(&hashP1, (*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(dst)), C.size_t(29), nil, 0)

	// Sign: G1 hash × scalar → G1 point (min-sig-size, signature in G1)
	var sig C.blst_p1
	C.blst_sign_pk_in_g2(&sig, &hashP1, &sk)

	// Convert to affine and compress (48 bytes)
	var sigAff C.blst_p1_affine
	C.blst_p1_to_affine(&sigAff, &sig)

	var sigCompressed [48]byte
	C.blst_p1_affine_compress((*C.uchar)(unsafe.Pointer(&sigCompressed[0])), &sigAff)

	// Self-check: verify the signature we just produced
	if valid, err := verifySignatureWithSk(keyBytes, dataBlock, sigCompressed[:]); err != nil || !valid {
		if err != nil {
			return nil, fmt.Errorf("BUG: freshly produced signature fails self-verification: %w", err)
		}
		return nil, fmt.Errorf("BUG: freshly produced signature fails self-verification")
	}

	return sigCompressed[:], nil
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

	// Derive public key in G2 from private key
	var sk C.blst_scalar
	C.blst_scalar_from_bendian(&sk, (*C.uchar)(unsafe.Pointer(&skBytes[0])))
	var pk C.blst_p2
	C.blst_sk_to_pk_in_g2(&pk, &sk)
	var pkAff C.blst_p2_affine
	C.blst_p2_to_affine(&pkAff, &pk)

	// Uncompress signature from compressed G1
	var sigAff C.blst_p1_affine
	if C.blst_p1_uncompress(&sigAff, (*C.uchar)(unsafe.Pointer(&sig[0]))) != C.BLST_SUCCESS {
		return false, fmt.Errorf("signature decompression failed")
	}

	// Core verify: e(sig, g2) == e(H(m), pk)
	// hash_or_encode=true: blst hashes msg internally
	dst := C.CString("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
	defer C.free(unsafe.Pointer(dst))
	res := C.blst_core_verify_pk_in_g2(&pkAff, &sigAff, true,
		(*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(14),
		(*C.uchar)(unsafe.Pointer(dst)), C.size_t(29),
		nil, 0)
	return res == C.BLST_SUCCESS, nil
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

	// Uncompress public key from G2
	var pkAff C.blst_p2_affine
	if C.blst_p2_uncompress(&pkAff, (*C.uchar)(unsafe.Pointer(&pkCompressed[0]))) != C.BLST_SUCCESS {
		return false, fmt.Errorf("public key decompression failed")
	}

	// Uncompress signature from compressed G1
	var sigAff C.blst_p1_affine
	if C.blst_p1_uncompress(&sigAff, (*C.uchar)(unsafe.Pointer(&sig[0]))) != C.BLST_SUCCESS {
		return false, fmt.Errorf("signature decompression failed")
	}

	// Core verify: e(sig, g2) == e(H(m), pk)
	dst := C.CString("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
	defer C.free(unsafe.Pointer(dst))
	res := C.blst_core_verify_pk_in_g2(&pkAff, &sigAff, true,
		(*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(14),
		(*C.uchar)(unsafe.Pointer(dst)), C.size_t(29),
		nil, 0)
	return res == C.BLST_SUCCESS, nil
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

	var sk C.blst_scalar
	C.blst_keygen(&sk, (*C.uchar)(unsafe.Pointer(&ikm[0])), C.size_t(len(ikm)), nil, 0)

	var keyBytes [32]byte
	C.blst_bendian_from_scalar((*C.uchar)(unsafe.Pointer(&keyBytes[0])), &sk)

	// Compute public key in G2 (min-sig-size: sig in G1, pk in G2)
	var pk C.blst_p2
	C.blst_sk_to_pk_in_g2(&pk, &sk)
	var pkAff C.blst_p2_affine
	C.blst_p2_to_affine(&pkAff, &pk)
	var pubBytes [96]byte
	C.blst_p2_affine_compress((*C.uchar)(unsafe.Pointer(&pubBytes[0])), &pkAff)

	if err := os.WriteFile(path, keyBytes[:], 0600); err != nil {
		return err
	}

	pubPath := path + ".pub"
	os.WriteFile(pubPath, []byte(hex.EncodeToString(pubBytes[:96])+"\n"), 0644)

	fmt.Printf("Private key saved to: %s (%d bytes)\n", path, len(keyBytes))
	fmt.Printf("Key hex:    %s\n", hex.EncodeToString(keyBytes[:]))
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubBytes[:96]))
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

	var sk C.blst_scalar
	C.blst_scalar_from_bendian(&sk, (*C.uchar)(unsafe.Pointer(&keyBytes[0])))

	var pk C.blst_p2
	C.blst_sk_to_pk_in_g2(&pk, &sk)
	var pkAff C.blst_p2_affine
	C.blst_p2_to_affine(&pkAff, &pk)
	var pubBytes [96]byte
	C.blst_p2_affine_compress((*C.uchar)(unsafe.Pointer(&pubBytes[0])), &pkAff)

	fmt.Printf("Private key: %s\n", path)
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubBytes[:96]))
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
