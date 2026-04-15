/*
    Copyright 2024 - 2026 xESC Project

    This file is part of the VESC firmware.

    The VESC firmware is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    The VESC firmware is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    */

#ifndef XESC2_OTP_H_
#define XESC2_OTP_H_

#include <stdint.h>

/*
 * OTP Memory Layout (STM32F4, 16 blocks à 32 bytes at 0x1FFF7800)
 *
 * Block pairs: even = data+CRC+part1Sig, odd = part2Sig
 *
 * Block 0 (Data+CRC16+SigPart1):
 *   Bytes  0-13: Data fields (magic..timestamp)
 *   Bytes 14-15: CRC-16/CCITT-FALSE over bytes 0..13
 *   Bytes 16-31: BLS12-381 compressed signature part 1 (16 bytes)
 *
 * Block 1 (SigPart2):
 *   Bytes  0-31: BLS12-381 compressed signature part 2 (32 bytes)
 *
 * Total signature: 48 bytes BLS12-381 compressed G1 (RFC 9380)
 *
 * Pair 0: Block 0 (0x1FFF7800) + Block 1 (0x1FFF7820)  — Initial branding
 * Pair 1: Block 2 (0x1FFF7840) + Block 3 (0x1FFF7860)  — 1. Rebranding
 * ...
 * Pair 7: Block 14 + Block 15                          — 7. Rebranding
 *
 * Total: 8 branding attempts (1 initial + 7 rebrandings)
 */

// OTP base address
#define XESC2_OTP_BASE_ADDR 0x1FFF7800
#define XESC2_OTP_BLOCK_SIZE 32
#define XESC2_OTP_NUM_BLOCKS 16
#define XESC2_OTP_NUM_PAIRS (XESC2_OTP_NUM_BLOCKS / 2)

// Block 0 layout
#define XESC2_OTP_OFFS_MAGIC 0     // uint8:  0xEC = valid record
#define XESC2_OTP_OFFS_VERSION 1   // uint8:  structure version
#define XESC2_OTP_OFFS_TYPE_ID 2   // uint8:  board type (Mini, Lite, ...)
#define XESC2_OTP_OFFS_VARIANT 3   // uint8:  variant within type (v1_std, v2_power, ...)
#define XESC2_OTP_OFFS_HW_MAJOR 4  // uint8:  hardware major version
#define XESC2_OTP_OFFS_HW_MINOR 5  // uint8:  hardware minor version
#define XESC2_OTP_OFFS_HW_PATCH 6  // uint8:  hardware patch version
#define XESC2_OTP_OFFS_SERIAL 7    // uint16: serial number (little-endian)
#define XESC2_OTP_OFFS_TIMESTAMP 9 // uint32: build Unix timestamp (little-endian)
// Data fields above occupy bytes 0..12 (13 bytes)
#define XESC2_OTP_DATA_LEN 13
// Pad byte at offset 13 keeps struct aligned
#define XESC2_OTP_OFFS_RESERVED 13  // uint8:  0xFF (reserved for future use)
#define XESC2_OTP_OFFS_CRC 14       // uint16: CRC-16/CCITT-FALSE over bytes 0..13
#define XESC2_OTP_OFFS_SIG_PART1 16 // 16 bytes: BLS12-381 signature part 1

// CRC data span
#define XESC2_OTP_CRC_DATA_OFFS 0
#define XESC2_OTP_CRC_DATA_LEN 14 // bytes 0..13 (magic..pad)

// Magic value, abbreviated from xESC ;-)
#define XESC2_OTP_MAGIC 0xEC

// Structure version
#define XESC2_OTP_VERSION 1

// CRC-16/CCITT-FALSE parameters
// Polynomial: 0x1021, Init: 0xFFFF, No Reflect, No XorOut
#define XESC2_OTP_CRC16_POLY 0x1021
#define XESC2_OTP_CRC16_INIT 0xFFFF

// BLS signature
#define XESC2_OTP_SIG_SIZE 48 // BLS12-381 compressed G1

// Type IDs
#define XESC2_TYPE_MINI 0
#define XESC2_TYPE_LITE 1

// Variant IDs
#define XESC2_VARIANT_V1_STD 0
#define XESC2_VARIANT_V2_STD 1 // v2 Standard (25mΩ shunt, YJG20N06A FETs)
#define XESC2_VARIANT_V2_PWR 2 // v2 Power (3mΩ shunt, BSC0702LS FETs)

#endif /* XESC2_OTP_H_ */