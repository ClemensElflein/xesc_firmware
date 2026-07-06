package main

/*
#cgo CFLAGS: -I../../hwconf/xtech/xesc_all_variants

#include "xesc2_otp.h"
*/
import "C"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// STM32F4 Unique Device ID base address (96-bit, 12 bytes)
// See RM0090 Rev 19 Section 39.1 "Unique device ID register"
const stm32UIDAddr = 0x1FFF7A10
const stm32UIDSize = 12

// ----- STM32CubeProgrammer discovery -----

// findProgrammerCLI locates the STM32_Programmer_CLI binary.
// Search order: 1) $ST_PROGRAMMER_PATH  2) standard install dirs  3) $PATH
func findProgrammerCLI() (string, error) {
	// 1. Explicit env var
	if p := os.Getenv("ST_PROGRAMMER_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 2. Standard install locations
	candidates := []string{
		"/usr/local/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI",
		"/opt/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI",
		filepath.Join(os.Getenv("HOME"), "STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	// 3. $PATH
	if p, err := exec.LookPath("STM32_Programmer_CLI"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("STM32_Programmer_CLI not found — install STM32CubeProgrammer or set $ST_PROGRAMMER_PATH")
}

// ----- Generic st-flash reader -----

// stflashRead reads size bytes from the given device address using st-flash.
// Returns the raw bytes and ensures the expected size was read.
func stflashRead(addr uint32, size int, desc string) ([]byte, error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("otp_read_%X_%d.bin", addr, size))
	cmd := exec.Command("st-flash", "read", tmpFile, fmt.Sprintf("0x%X", addr), fmt.Sprintf("%d", size))
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cannot read %s via st-flash: %w", desc, err)
	}
	defer os.Remove(tmpFile)

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s temp file: %w", desc, err)
	}
	if len(data) != size {
		return nil, fmt.Errorf("expected %d bytes for %s, got %d", size, desc, len(data))
	}
	return data, nil
}

// ----- STM32 UID -----

// readSTM32UID reads the 12-byte STM32 unique device ID via st-flash from
// the fixed system memory address 0x1FFF7A10. Returns the normalized hex string
// and raw bytes, suitable for direct use in signing/verification.
func readSTM32UID() (string, []byte, error) {
	uid, err := stflashRead(stm32UIDAddr, stm32UIDSize, "STM32 UID")
	if err != nil {
		return "", nil, err
	}

	// Normalize via the canonical normalizer (handles whitespace, casing, length validation)
	normalized, uidBytes, err := normalizeSTM32UID(fmt.Sprintf("%x", uid))
	if err != nil {
		return "", nil, fmt.Errorf("read UID normalization failed: %w", err)
	}
	_ = uidBytes

	return normalized, uid, nil
}

// ----- OTP hardware access -----

func pairBaseAddr(pair int) uint32 {
	return uint32(C.XESC2_OTP_BASE_ADDR) + uint32(pair)*2*uint32(C.XESC2_OTP_BLOCK_SIZE)
}

// readOTPMagic reads the first byte of an OTP pair via st-flash (absolute address read).
// st-flash enforces 4-byte alignment on reads, so we read 4 bytes and take the first.
func readOTPMagic(pair int) (byte, error) {
	addr := pairBaseAddr(pair)
	data, err := stflashRead(addr, 4, "OTP magic")
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

// readOTPPair reads a full 64-byte OTP pair from the device via st-flash.
func readOTPPair(pair int) ([]byte, error) {
	addr := pairBaseAddr(pair)
	data, err := stflashRead(addr, 64, fmt.Sprintf("OTP pair %d", pair))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// flashOTP writes a 64-byte block file to OTP using STM32CubeProgrammer CLI.
func flashOTP(binPath string, pair int) error {
	cli, err := findProgrammerCLI()
	if err != nil {
		return err
	}

	addr := pairBaseAddr(pair)
	fmt.Printf("Flashing OTP pair %d at 0x%X via STM32CubeProgrammer...\n", pair, addr)
	cmd := exec.Command(cli,
		"-c", "port=SWD",
		"-w", binPath,
		fmt.Sprintf("0x%X", addr),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("STM32_Programmer_CLI failed: %w", err)
	}
	fmt.Println("Done! Remove power and reconnect for OTP to take effect.")
	return nil
}
