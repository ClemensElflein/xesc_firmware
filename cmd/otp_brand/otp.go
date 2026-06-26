package main

/*
#cgo CFLAGS: -I../../hwconf/xtech/xesc_all_variants

#include "xesc2_otp.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// crc16CCITT computes CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF).
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

// MajorMinorPatch holds a semantic version triple.
type MajorMinorPatch struct{ Major, Minor, Patch uint8 }

var typeMap = map[string]uint8{
	"mini": uint8(C.XESC2_TYPE_MINI),
	"lite": uint8(C.XESC2_TYPE_LITE),
}
var variantMap = map[string]uint8{
	"v1_std": uint8(C.XESC2_VARIANT_V1_STD),
	"v2_std": uint8(C.XESC2_VARIANT_V2_STD),
	"v2_pwr": uint8(C.XESC2_VARIANT_V2_PWR),
}

// buildDataBlock constructs a 32-byte OTP data block (magic .. CRC16).
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

// formatOTPInfo returns a JSON-like string with the decoded OTP header fields.
func formatOTPInfo(dataBlock []byte) string {
	return fmt.Sprintf(
		`{"type":%d,"variant":%d,"hw":"%d.%d.%d","serial":%d,"timestamp":%d,"crc16":"0x%04X"}`,
		dataBlock[int(C.XESC2_OTP_OFFS_TYPE_ID)],
		dataBlock[int(C.XESC2_OTP_OFFS_VARIANT)],
		dataBlock[int(C.XESC2_OTP_OFFS_HW_MAJOR)],
		dataBlock[int(C.XESC2_OTP_OFFS_HW_MINOR)],
		dataBlock[int(C.XESC2_OTP_OFFS_HW_PATCH)],
		binary.LittleEndian.Uint16(dataBlock[int(C.XESC2_OTP_OFFS_SERIAL):]),
		binary.LittleEndian.Uint32(dataBlock[int(C.XESC2_OTP_OFFS_TIMESTAMP):]),
		binary.LittleEndian.Uint16(dataBlock[int(C.XESC2_OTP_OFFS_CRC):]),
	)
}

// ----- Serial counter -----

func serialCounterPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".otp_serial_counter"
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

// displayOTPPair reads an OTP pair from the device and prints a human-readable summary.
func displayOTPPair(pair int) error {
	data, err := readOTPPair(pair)
	if err != nil {
		return err
	}

	// Block 0: bytes 0..31 (data + CRC16 + sig[0:16])
	// Block 1: bytes 32..63 (sig[16:48])
	magic := data[int(C.XESC2_OTP_OFFS_MAGIC)]
	version := data[int(C.XESC2_OTP_OFFS_VERSION)]
	typeID := data[int(C.XESC2_OTP_OFFS_TYPE_ID)]
	variantID := data[int(C.XESC2_OTP_OFFS_VARIANT)]
	hwMaj := data[int(C.XESC2_OTP_OFFS_HW_MAJOR)]
	hwMin := data[int(C.XESC2_OTP_OFFS_HW_MINOR)]
	hwPatch := data[int(C.XESC2_OTP_OFFS_HW_PATCH)]
	serial := binary.LittleEndian.Uint16(data[int(C.XESC2_OTP_OFFS_SERIAL):])
	ts := binary.LittleEndian.Uint32(data[int(C.XESC2_OTP_OFFS_TIMESTAMP):])
	expectedCRC := binary.LittleEndian.Uint16(data[int(C.XESC2_OTP_OFFS_CRC):])
	actualCRC := crc16CCITT(data[0:14])

	typeName := "unknown"
	for k, v := range typeMap {
		if v == typeID {
			typeName = k
		}
	}
	variantName := "unknown"
	for k, v := range variantMap {
		if v == variantID {
			variantName = k
		}
	}

	validStr := "INVALID"
	notes := ""
	if magic == uint8(C.XESC2_OTP_MAGIC) && version == uint8(C.XESC2_OTP_VERSION) && expectedCRC == actualCRC {
		validStr = "VALID"
	} else {
		if magic != uint8(C.XESC2_OTP_MAGIC) {
			notes += fmt.Sprintf(" (bad magic: 0x%02X, expected 0x%02X)", magic, C.XESC2_OTP_MAGIC)
		} else if version != uint8(C.XESC2_OTP_VERSION) {
			notes += fmt.Sprintf(" (bad version: %d, expected %d)", version, C.XESC2_OTP_VERSION)
		} else {
			notes += fmt.Sprintf(" (CRC mismatch: calc=0x%04X stored=0x%04X)", actualCRC, expectedCRC)
		}
	}

	timestampStr := "not set"
	if ts != 0xFFFFFFFF && ts != 0 {
		timestampStr = time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
	}

	fmt.Printf("OTP pair %d (addr 0x%X):\n", pair, pairBaseAddr(pair))
	fmt.Printf("  Magic:       0x%02X\n", magic)
	fmt.Printf("  Version:     %d\n", version)
	fmt.Printf("  Board:       %s (id=%d)\n", typeName, typeID)
	fmt.Printf("  Variant:     %s (id=%d)\n", variantName, variantID)
	fmt.Printf("  HW rev:      %d.%d.%d\n", hwMaj, hwMin, hwPatch)
	fmt.Printf("  Serial:      %d\n", serial)
	fmt.Printf("  Timestamp:   %d (%s)\n", ts, timestampStr)
	fmt.Printf("  CRC16:       0x%04X (calculated: 0x%04X)\n", expectedCRC, actualCRC)
	fmt.Printf("  Status:      %s%s\n", validStr, notes)
	return nil
}
