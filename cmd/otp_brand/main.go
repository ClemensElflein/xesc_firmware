package main

/*
#cgo CFLAGS: -I../../hwconf/xtech/xesc2-mini -I/tmp/blst/bindings -I/tmp/blst/build -I/tmp/blst/src -D__BLST_CGO__ -fno-builtin-memcpy -fno-builtin-memset
#cgo amd64 CFLAGS: -D__ADX__ -mno-avx
#cgo LDFLAGS: -L/tmp/blst -lblst

#include "xesc2_otp.h"
#include "blst.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"
)

func crc16CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for j := 0; j < 8; j++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

type MajorMinorPatch struct{ Major, Minor, Patch uint8 }

var typeMap = map[string]uint8{
	"mini": uint8(C.XESC2_TYPE_MINI),
	"lite": uint8(C.XESC2_TYPE_LITE),
}
var variantMap = map[string]uint8{
	"v1_std":   uint8(C.XESC2_VARIANT_V1_STD),
	"v2_power": uint8(C.XESC2_VARIANT_V2_POWER),
}

func buildDataBlock(boardType, variant string, hw MajorMinorPatch, serial uint16, ts uint32) ([]byte, error) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xFF
	}

	b[int(C.XESC2_OTP_OFFS_MAGIC)] = uint8(C.XESC2_OTP_MAGIC)
	b[int(C.XESC2_OTP_OFFS_VERSION)] = uint8(C.XESC2_OTP_VERSION)

	tid, ok := typeMap[boardType]
	if !ok {
		return nil, fmt.Errorf("unknown type: %s", boardType)
	}
	b[int(C.XESC2_OTP_OFFS_TYPE_ID)] = tid

	vid, ok := variantMap[variant]
	if !ok {
		return nil, fmt.Errorf("unknown variant: %s", variant)
	}
	b[int(C.XESC2_OTP_OFFS_VARIANT)] = vid

	b[int(C.XESC2_OTP_OFFS_HW_MAJOR)] = hw.Major
	b[int(C.XESC2_OTP_OFFS_HW_MINOR)] = hw.Minor
	b[int(C.XESC2_OTP_OFFS_HW_PATCH)] = hw.Patch
	binary.LittleEndian.PutUint16(b[int(C.XESC2_OTP_OFFS_SERIAL):], serial)
	binary.LittleEndian.PutUint32(b[int(C.XESC2_OTP_OFFS_TIMESTAMP):], ts)

	crc := crc16CCITT(b[0:14])
	binary.LittleEndian.PutUint16(b[int(C.XESC2_OTP_OFFS_CRC):], crc)
	return b, nil
}

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

	return sigCompressed[:], nil
}

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

	// KeyGen from IKM
	var sk C.blst_scalar
	C.blst_keygen(&sk, (*C.uchar)(unsafe.Pointer(&ikm[0])), C.size_t(len(ikm)), nil, 0)

	// Serialize private key (big-endian)
	var keyBytes [32]byte
	C.blst_bendian_from_scalar((*C.uchar)(unsafe.Pointer(&keyBytes[0])), &sk)

	// Compute public key in G2 (since sig is in G1 = min-sig-size)
	var pk C.blst_p2
	C.blst_sk_to_pk_in_g2(&pk, &sk)
	var pkAff C.blst_p2_affine
	C.blst_p2_to_affine(&pkAff, &pk)
	var pubBytes [96]byte
	C.blst_p2_affine_compress((*C.uchar)(unsafe.Pointer(&pubBytes[0])), &pkAff)

	if err := os.WriteFile(path, keyBytes[:], 0600); err != nil {
		return err
	}

	// Save public key alongside private key
	pubPath := path + ".pub"
	os.WriteFile(pubPath, []byte(hex.EncodeToString(pubBytes[:48])+"\n"), 0644)

	fmt.Printf("Private key saved to: %s (%d bytes)\n", path, len(keyBytes))
	fmt.Printf("Key hex:    %s\n", hex.EncodeToString(keyBytes[:]))
	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubBytes[:48]))
	fmt.Printf("Public key saved to: %s\n", pubPath)
	fmt.Println()
	fmt.Println("Store this key securely! Recommended: ~/.config/xesc/keys/builder*.key")
	fmt.Println("Permissions set to 600 (owner read/write only).")
	return nil
}

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
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubBytes[:48]))
	return nil
}

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

func pairBaseAddr(pair int) uint32 {
	return uint32(C.XESC2_OTP_BASE_ADDR) + uint32(pair)*2*uint32(C.XESC2_OTP_BLOCK_SIZE)
}

func readOTPMagic(pair int) (byte, error) {
	addr := pairBaseAddr(pair)
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("otp_check_%d.bin", pair))
	cmd := exec.Command("st-flash", "read", tmpFile, fmt.Sprintf("0x%X", addr), "1")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("cannot read OTP via st-flash: %w", err)
	}
	defer os.Remove(tmpFile)
	data, err := os.ReadFile(tmpFile)
	if err != nil || len(data) < 1 {
		return 0, fmt.Errorf("cannot read OTP check file")
	}
	return data[0], nil
}

func flashOTP(binPath string, pair int) error {
	addr := pairBaseAddr(pair)
	cmd := exec.Command("st-flash", "write", binPath, fmt.Sprintf("0x%X", addr))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Flashing OTP pair %d to 0x%X...\n", pair, addr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("st-flash failed: %w", err)
	}
	fmt.Println("Done! Remove power and reconnect for OTP to take effect.")
	return nil
}

func serialCounterPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".otp_serial_counter" // fallback
	}
	return filepath.Join(home, ".config", "xesc", ".otp_serial_counter")
}
func readSerialCounter() uint16 {
	data, _ := os.ReadFile(serialCounterPath())
	var n uint16
	fmt.Sscanf(string(data), "%d", &n)
	return n
}
func readNextSerial() uint16 {
	n := readSerialCounter() + 1
	if n < 1 {
		n = 1
	}
	return n
}
func writeSerialCounter(n uint16) {
	os.MkdirAll(filepath.Dir(serialCounterPath()), 0755)
	os.WriteFile(serialCounterPath(), []byte(fmt.Sprintf("%d\n", n)), 0644)
}

func main() {
	var (
		genKey    = flag.String("generate-key", "", "Generate new private key and save to PATH")
		dumpPub   = flag.String("dump-pubkey", "", "Print the public key for a private key file")
		boardType = flag.String("type", "", "Board type (mini, lite)")
		variant   = flag.String("variant", "", "Variation (v1_std, v2_power)")
		hw        = flag.String("hw", "", "HW version (e.g. 2.0.1)")
		keyFile   = flag.String("key", "", "Private key file for signing (32 bytes)")
		output    = flag.String("output", "otp_blocks.bin", "Output binary file")
		serial    = flag.Int("serial", 0, "Serial number (default: auto-increment)")
		pair      = flag.Int("pair", 0, "OTP block pair to write (0-7, default 0)")
		force     = flag.Bool("force", false, "Skip OTP occupation check")
		flash     = flag.Bool("flash", false, "Flash OTP blocks after generation")
		dryRun    = flag.Bool("dry-run", false, "Show what would be done without writing")
		dumpC     = flag.Bool("dump-c", false, "Output both blocks as C array for firmware test mode")
	)
	flag.Parse()

	if *genKey != "" {
		if err := generateKey(*genKey); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *dumpPub != "" {
		if err := dumpPubKey(*dumpPub); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *boardType == "" || *variant == "" || *hw == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --type, --variant, --hw, and --key are required")
		flag.Usage()
		os.Exit(1)
	}

	var hwParts MajorMinorPatch
	if _, err := fmt.Sscanf(*hw, "%d.%d.%d", &hwParts.Major, &hwParts.Minor, &hwParts.Patch); err != nil {
		if _, err := fmt.Sscanf(*hw, "%d.%d", &hwParts.Major, &hwParts.Minor); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid HW version: %s (expected e.g. 2.0.1)\n", *hw)
			os.Exit(1)
		}
	}

	serialNum := uint16(*serial)
	if serialNum == 0 {
		serialNum = readNextSerial()
	}

	ts := uint32(time.Now().Unix())
	block, err := buildDataBlock(*boardType, *variant, hwParts, serialNum, ts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	keyBytes, err := loadPrivateKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: loading key: %v\n", err)
		os.Exit(1)
	}

	sig, err := signBlock(block, keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// Assemble: Block 0 (data+CRC + sig[0:16]) + Block 1 (sig[16:48] + 0xFF pad)
	out := make([]byte, 64)
	for i := range out {
		out[i] = 0xFF
	}
	copy(out[0:16], block[0:16])
	copy(out[16:32], sig[0:16])
	copy(out[32:64], sig[16:48])

	crcVal := binary.LittleEndian.Uint16(block[int(C.XESC2_OTP_OFFS_CRC):])
	fmt.Printf("Board:      %s\n", *boardType)
	fmt.Printf("Variation:  %s\n", *variant)
	fmt.Printf("HW:         %s\n", *hw)
	fmt.Printf("Serial:     %d\n", serialNum)
	fmt.Printf("Timestamp:  %d\n", ts)
	fmt.Printf("CRC16:      0x%04X\n", crcVal)
	fmt.Printf("Signature:  %s... (%d bytes BLS12-381)\n", hex.EncodeToString(sig[:8]), len(sig))
	fmt.Println()

	if *dumpC {
		fmt.Println("// Copy into xesc2_variant_config.c test_otp_block[]:")
		fmt.Println("static const uint8_t test_otp_block[XESC2_OTP_BLOCK_SIZE] = {")
		for i := 0; i < 32; i++ {
			if i%8 == 0 {
				fmt.Print("    ")
			}
			fmt.Printf("0x%02X, ", out[i])
			if i%8 == 7 {
				fmt.Println()
			}
		}
		fmt.Println("};")
		fmt.Println()
		fmt.Println("// Block 1 (signature part 2):")
		fmt.Println("static const uint8_t test_otp_sig_block2[XESC2_OTP_BLOCK_SIZE] = {")
		for i := 32; i < 64; i++ {
			if i%8 == 0 {
				fmt.Print("    ")
			}
			fmt.Printf("0x%02X, ", out[i])
			if (i-32)%8 == 7 {
				fmt.Println()
			}
		}
		fmt.Println("};")
		fmt.Println()
		fmt.Println("// Verify CRC16 with:")
		fmt.Printf("//   python3 -c \"import binascii,struct; d=bytes.fromhex('%s'); print(hex(binascii.crc_hqx(d[:14], 0xFFFF)))\"\n",
			hex.EncodeToString(out[:14]))
	} else if *dryRun {
		fmt.Printf("DRY RUN — would write %d bytes to %s\n", len(out), *output)
		fmt.Printf("Serial counter would be: %d\n", serialNum)
	} else {
		if err := os.WriteFile(*output, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %d bytes to %s\n", len(out), *output)
		if *flash {
			if *pair < 0 || *pair >= 8 {
				fmt.Fprintf(os.Stderr, "ERROR: --pair must be 0-7\n")
				os.Exit(1)
			}

			if !*force {
				magic, err := readOTPMagic(*pair)
				if err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: cannot check OTP occupation: %v\n", err)
					fmt.Fprintf(os.Stderr, "  Is the ST-Link connected and the ESC powered?\n")
					os.Exit(1)
				}
				if magic == byte(C.XESC2_OTP_MAGIC) {
					fmt.Fprintf(os.Stderr, "ERROR: OTP pair %d is already branded (magic=0x%02X)\n", *pair, magic)
					fmt.Fprintf(os.Stderr, "  Use --pair %d for the next free pair, or --force to overwrite.\n", *pair+1)
					os.Exit(1)
				}
				if magic != 0xFF {
					fmt.Fprintf(os.Stderr, "WARNING: OTP pair %d contains non-FF data (0x%02X)\n", *pair, magic)
				}
			}

			if err := flashOTP(*output, *pair); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
				os.Exit(1)
			}
			writeSerialCounter(serialNum)
			fmt.Printf("Serial counter advanced to: %d\n", serialNum)
		}
	}
	fmt.Println()
}
