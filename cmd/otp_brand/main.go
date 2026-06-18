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
	"time"
)

func main() {
	var (
		genKey    = flag.String("generate-key", "", "Generate new private key and save to PATH")
		dumpPub   = flag.String("dump-pubkey", "", "Print the public key for a private key file")
		verify    = flag.String("verify", "", "Verify BLS signature in OTP_BLOCKS.BIN using private key KEY")
		verifyPub = flag.String("verify-pub", "", "Verify BLS signature in OTP_BLOCKS.BIN using public key PUBKEY")
		read      = flag.Int("read", -1, "Read OTP pair N from device and display decoded info")
		boardType = flag.String("type", "", "Board type (mini, lite)")
		variant   = flag.String("variant", "", "Variation (v1_std, v2_std, v2_pwr)")
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

	if *verifyPub != "" {
		binPath := *verifyPub
		pubKeyPath := *keyFile
		if pubKeyPath == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --verify-pub requires --key PUBKEY_PATH")
			os.Exit(1)
		}
		valid, info, err := verifySignatureFromPubFile(binPath, pubKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signature verification: %s\n", map[bool]string{true: "VALID", false: "INVALID"}[valid])
		if valid {
			fmt.Printf("OTP data: %s\n", info)
		}
		return
	}

	if *verify != "" {
		valid, info, err := verifySignatureFromFile(*verify, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signature verification: %s\n", map[bool]string{true: "VALID", false: "INVALID"}[valid])
		if valid {
			fmt.Printf("OTP data: %s\n", info)
		}
		return
	}

	if *read >= 0 {
		if err := displayOTPPair(*read); err != nil {
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
