/*
    Copyright 2016 - 2020 Benjamin Vedder	benjamin@vedder.se
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

#include "conf_general.h"

// This file lives in the shared HWSRC list, so it is compiled for every board.
// All of its functionality is xESC2-OTP specific, so guard the entire
// implementation on HAS_OTP (defined only by the xESC2 hardware header). On any
// other board this becomes an empty translation unit.
#ifdef HAS_OTP

#include "ch.h"
#include "hal.h"
#include "xesc2_variant_config.h"
#include "crc.h"
#include "xesc2_otp.h"
#include "commands.h"
#include "terminal.h"
#include "hw_xesc2_mini.h"
#include "flash_helper.h"
#include <time.h>
#include <string.h>

// Global OTP identity, populated at startup
xesc2_otp_identity_t g_xesc2_otp_identity = {0, 0, 0, 0, 0, 0, 0, 0};

// Fatal config error flag: set when OTP is missing on v2 or corrupt.
// main() latches a persistent fault before mc_interface_init() so the motor can
// never be armed (see main.c / mc_interface_set_persistent_fault).
bool g_xesc2_fatal_config_error = false;

// ------------------------------------------------------------------
// CRC-16/CCITT-FALSE verification
// ------------------------------------------------------------------
static uint16_t otp_crc16(const uint8_t *data, uint32_t len)
{
    // CRC-16/CCITT-FALSE: poly=0x1021, init=0xFFFF, no reflect, no xorout
    uint16_t crc = XESC2_OTP_CRC16_INIT;
    for (uint32_t i = 0; i < len; i++)
    {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 0x8000)
            {
                crc = (crc << 1) ^ XESC2_OTP_CRC16_POLY;
            }
            else
            {
                crc <<= 1;
            }
        }
    }
    return crc;
}

// ------------------------------------------------------------------
// OTP scanner: find the last valid block pair (scans from highest
// pair index downward — last pair with valid magic+version+CRC wins)
// ------------------------------------------------------------------
static const uint8_t *otp_read_block(uint8_t pair_index)
{
    return (const uint8_t *)(XESC2_OTP_BASE_ADDR + pair_index * 2 * XESC2_OTP_BLOCK_SIZE);
}

// ------------------------------------------------------------------
// Public: check if any OTP data exists (any pair has magic byte)
// ------------------------------------------------------------------
bool xesc2_has_otp_data(void)
{
    for (int pair = 0; pair < XESC2_OTP_NUM_PAIRS; pair++)
    {
        const uint8_t *block = otp_read_block(pair);
        if (block[XESC2_OTP_OFFS_MAGIC] == XESC2_OTP_MAGIC)
        {
            return true;
        }
    }
    return false;
}

// ------------------------------------------------------------------
// Public: find the last valid OTP identity (scans from highest
// pair index downward — last pair with valid magic+version+CRC wins)
// Returns identity with valid=0 if no valid record found.
// ------------------------------------------------------------------
xesc2_otp_identity_t xesc2_get_otp_identity(void)
{
    xesc2_otp_identity_t id = {0, 0, 0, 0, 0, 0, 0, 0};

    // OTP pairs are at absolute addresses 0x1FFF7800 .. 0x1FFF79E0.
    // Scan from highest (last rebranding) to lowest (initial branding).
    // The first valid block with matching CRC is the active identity.
    for (int pair = XESC2_OTP_NUM_PAIRS - 1; pair >= 0; pair--)
    {
        const uint8_t *block = otp_read_block(pair);

        // Check magic
        if (block[XESC2_OTP_OFFS_MAGIC] != XESC2_OTP_MAGIC)
        {
            continue;
        }

        // Check version
        if (block[XESC2_OTP_OFFS_VERSION] != XESC2_OTP_VERSION)
        {
            continue;
        }

        // Verify CRC16 over bytes 0..13
        uint16_t expected_crc =
            (uint16_t)block[XESC2_OTP_OFFS_CRC] |
            ((uint16_t)block[XESC2_OTP_OFFS_CRC + 1] << 8);

        uint16_t actual_crc = otp_crc16(block + XESC2_OTP_CRC_DATA_OFFS,
                                        XESC2_OTP_CRC_DATA_LEN);

        if (expected_crc == actual_crc)
        {
            id.type_id = block[XESC2_OTP_OFFS_TYPE_ID];
            id.variant_id = block[XESC2_OTP_OFFS_VARIANT];
            id.hw_major = block[XESC2_OTP_OFFS_HW_MAJOR];
            id.hw_minor = block[XESC2_OTP_OFFS_HW_MINOR];
            id.hw_patch = block[XESC2_OTP_OFFS_HW_PATCH];
            id.serial = (uint16_t)block[XESC2_OTP_OFFS_SERIAL] |
                        ((uint16_t)block[XESC2_OTP_OFFS_SERIAL + 1] << 8);
            id.timestamp = (uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP] |
                           ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 1] << 8) |
                           ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 2] << 16) |
                           ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 3] << 24);
            id.valid = 1;
            return id;
        }
    }

    return id;
}

// ----------------------------
// Variant configuration tables
// ----------------------------

// -- Old v1.x mini
static const xesc2_variant_config_t variant_mini_v1_standard = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = XESC2_VARIANT_V1_STD,  // Do not use spaces in hw_name, it becomes part of the UAVCAN node name
    .hw_name = "xESC2-mini_v1",
    .driver_type = XESC2_DRIVER_TMC6200,
    .gate_active_high = 1,
    .has_phase_shunts = 1,
    .current_amp_gain = (5.0f * 0.595f), // 5x gain * voltage divider ratio
    .current_shunt_res = 0.033f,
    .tmc6200_amp_gain = 5,
    .tmc6200_drvstrength = 2,            // medium (default)
    .lim_current_min = -15.0f,
    .lim_current_max = 15.0f,
    .lim_current_in_min = -10.0f,
    .lim_current_in_max = 10.0f,
    .lim_current_abs_max = 15.0f,
    .lim_vin_min = 6.0f,
    .lim_vin_max = 57.0f,
    .lim_temp_fet_max = 90.0f,
    .l_max_abs_current = 15.0f,
    .mcconf_l_current_max = 6.0f,
    .mcconf_l_current_min = -6.0f,
    .mcconf_l_in_current_max = 2.0f,
    .mcconf_l_in_current_min = -2.0f,
    .mcconf_max_current_unbalance = 512.0f,
};

// -- New v2.x mini
static const xesc2_variant_config_t variant_mini_v2_standard = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = XESC2_VARIANT_V2_STD,
    .hw_name = "xESC2-mini_v2",   // Do not use spaces in hw_name, it becomes part of the UAVCAN node name
    .driver_type = XESC2_DRIVER_TMC6200,
    .gate_active_high = 1,
    .has_phase_shunts = 1,
    .current_amp_gain = 5.0f, // 5x gain
    .current_shunt_res = 0.025f,
    .tmc6200_amp_gain = 5,        // 5x (10x would saturate at 13.2A)
    .tmc6200_drvstrength = 2,     // medium
    .lim_current_min = -15.0f,    // FET derated ~14-15A at 90°C
    .lim_current_max = 15.0f,
    .lim_current_in_min = -10.0f,
    .lim_current_in_max = 10.0f,
    .lim_current_abs_max = 20.0f, // 25mΩ handles 33% more than 33mΩ v1
    .lim_vin_min = 6.0f,
    .lim_vin_max = 57.0f,
    .lim_temp_fet_max = 90.0f,
    .l_max_abs_current = 20.0f,
    .mcconf_l_current_max = 6.0f,
    .mcconf_l_current_min = -6.0f,
    .mcconf_l_in_current_max = 2.0f,
    .mcconf_l_in_current_min = -2.0f,
    .mcconf_max_current_unbalance = 512.0f,
};

static const xesc2_variant_config_t variant_mini_v2_power = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = XESC2_VARIANT_V2_PWR,
    .hw_name = "xESC2-power_v2", // Do not use spaces in hw_name, it becomes part of the UAVCAN node name
    .driver_type = XESC2_DRIVER_TMC6200,
    .gate_active_high = 1,
    .has_phase_shunts = 1,
    .current_amp_gain = 10.0f, // 10x gain
    .current_shunt_res = 0.003f,
    .tmc6200_amp_gain = 10,
    .tmc6200_drvstrength = 3,    // strong for BSC0702LS (1300pF Ciss) at VIO=3.3V
    .lim_current_min = -25.0f,
    .lim_current_max = 25.0f,
    .lim_current_in_min = -8.0f,
    .lim_current_in_max = 8.0f,
    .lim_current_abs_max = 50.0f,
    .lim_vin_min = 9.0f,
    .lim_vin_max = 48.0f,
    .lim_temp_fet_max = 85.0f,
    .l_max_abs_current = 50.0f,
    .mcconf_l_current_max = 25.0f,
    .mcconf_l_current_min = -25.0f,
    .mcconf_l_in_current_max = 8.0f,
    .mcconf_l_in_current_min = -8.0f,
    .mcconf_max_current_unbalance = 512.0f,
};

// Error fallback (no runtime state, only used when config/OTP is invalid
static const xesc2_variant_config_t variant_error_fallback = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = 0xFF,           // marker for invalid/missing config
    .hw_name = "xESC2_OTP-ERROR", // Do not use spaces in hw_name, it becomes part of the UAVCAN node name
    .driver_type = XESC2_DRIVER_TMC6200,
    .gate_active_high = 1,
    .has_phase_shunts = 0,         // safe default for invalid/missing config
    .current_amp_gain = 1.0f,
    .current_shunt_res = 0.033f,
    .tmc6200_amp_gain = 1,
    .tmc6200_drvstrength = 2,
    .lim_current_min = 0.0f,
    .lim_current_max = 0.0f,
    .lim_current_in_min = 0.0f,
    .lim_current_in_max = 0.0f,
    .lim_current_abs_max = 0.0f,
    .lim_vin_min = 6.0f,
    .lim_vin_max = 57.0f,
    .lim_temp_fet_max = 90.0f,
    .l_max_abs_current = 0.0f,
    .mcconf_l_current_max = 0.0f,
    .mcconf_l_current_min = 0.0f,
    .mcconf_l_in_current_max = 0.0f,
    .mcconf_l_in_current_min = 0.0f,
    .mcconf_max_current_unbalance = 512.0f,
};

// -- Lite type (XESC2_TYPE_LITE) — DRV8376 gate driver, low-side shunts,
// active-low gate enable. Current sense uses inverted polarity, which the
// unified GET_CURRENT macro expresses as (4095 - adc * scale) with scale = 1.0.
static const xesc2_variant_config_t variant_lite_standard = {
    .type_id = XESC2_TYPE_LITE,
    .variant_id = XESC2_VARIANT_LITE_STD,
    .hw_name = "xESC2-lite", // Do not use spaces in hw_name, it becomes part of the UAVCAN node name
    .driver_type = XESC2_DRIVER_DRV8376,
    .gate_active_high = 0,         // lite enables the gate driver by driving the pad LOW
    .has_phase_shunts = 0,         // low-side shunts only: no V0_V7 sampling
    .current_amp_gain = 0.4f,
    .current_shunt_res = 1.0f,
    .tmc6200_amp_gain = 0,         // unused (DRV8376)
    .tmc6200_drvstrength = 0,      // unused (DRV8376)
    .lim_current_min = -3.0f,
    .lim_current_max = 3.0f,
    .lim_current_in_min = -9.0f,
    .lim_current_in_max = 9.0f,
    .lim_current_abs_max = 15.0f,
    .lim_vin_min = 6.0f,
    .lim_vin_max = 55.0f,
    .lim_temp_fet_max = 90.0f,
    .l_max_abs_current = 4.0f,
    .mcconf_l_current_max = 3.0f,
    .mcconf_l_current_min = -3.0f,
    .mcconf_l_in_current_max = 2.0f,
    .mcconf_l_in_current_min = -2.0f,
    .mcconf_max_current_unbalance = 1024.0f, // lite: noisier low-side sensing, keep old standalone *1024 threshold
};

// Global pointer to the active variant configuration
const xesc2_variant_config_t *g_xesc2_variant = &variant_error_fallback;


// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

const xesc2_variant_config_t *xesc2_get_variant_config(uint8_t type_id, uint8_t variant_id) {
    switch (type_id) {
        case XESC2_TYPE_MINI:
            switch (variant_id) {
                case XESC2_VARIANT_V1_STD:
                    return &variant_mini_v1_standard;
                case XESC2_VARIANT_V2_STD:
                    return &variant_mini_v2_standard;
                case XESC2_VARIANT_V2_PWR:
                    return &variant_mini_v2_power;
            }
            break;
        case XESC2_TYPE_LITE:
            switch (variant_id) {
                case XESC2_VARIANT_LITE_STD:
                    return &variant_lite_standard;
            }
            break;
    }

    // Unknown combination
    g_xesc2_fatal_config_error = true;
    return &variant_error_fallback;
}

void xesc2_detect_and_apply_variant(void) {
    // Configure V2 identification pin: LOW = v2 board (requires OTP),
    // HIGH/open = v1 board (no OTP needed, but allowed)
    palSetPadMode(HW_V2_ID_GPIO, HW_V2_ID_PIN, PAL_MODE_INPUT_PULLUP);
    bool is_v2 = (palReadPad(HW_V2_ID_GPIO, HW_V2_ID_PIN) == 0);

    xesc2_otp_identity_t id = xesc2_get_otp_identity();

    // Store the full identity for later use (hw_status, otp_info, etc.)
    g_xesc2_otp_identity = id;

    if (id.valid) {
        // Valid OTP found, all fine
        g_xesc2_variant = xesc2_get_variant_config(id.type_id, id.variant_id);
        return;
    }
    
    if (!xesc2_has_otp_data() && !is_v2) {
        // v1 board without OTP => v1-mini standard config
        g_xesc2_variant = xesc2_get_variant_config(XESC2_TYPE_MINI, XESC2_VARIANT_V1_STD);
        return;
    }

    // All other cases are errors eg:
    // - v2 board without valid OTP
    // - v1 board with invalid OTP (eg CRC mismatch)
    g_xesc2_variant = &variant_error_fallback;
    g_xesc2_fatal_config_error = true;
}

// ------------------------------------------------------------------
// Terminal: otp_info command
// ------------------------------------------------------------------
void xesc2_terminal_otp_info(int argc, const char **argv) {
    (void)argc;
    (void)argv;

    commands_printf("OTP Memory Scan (0x%08X, %d pairs):",
                    (unsigned int)XESC2_OTP_BASE_ADDR, XESC2_OTP_NUM_PAIRS);
    commands_printf(" ");

    int found = 0;
    int active_pair = -1;
    for (int pair = 0; pair < XESC2_OTP_NUM_PAIRS; pair++) {
        const uint8_t *block = otp_read_block(pair);

        uint8_t magic = block[XESC2_OTP_OFFS_MAGIC];
        if (magic != XESC2_OTP_MAGIC) {
            commands_printf("Pair %d: MAGIC INVALID (0x%02X)", pair, magic);
            continue;
        }

        uint8_t ver = block[XESC2_OTP_OFFS_VERSION];
        if (ver != XESC2_OTP_VERSION) {
            commands_printf("Pair %d: Magic=OK VERSION INVALID (%d)", pair, ver);
            continue;
        }

        uint16_t expected_crc =
            (uint16_t)block[XESC2_OTP_OFFS_CRC] |
            ((uint16_t)block[XESC2_OTP_OFFS_CRC + 1] << 8);
        uint16_t actual_crc = otp_crc16(block + XESC2_OTP_CRC_DATA_OFFS,
                                        XESC2_OTP_CRC_DATA_LEN);
        const char *crc_ok = (expected_crc == actual_crc) ? "OK" : "FAIL";

        uint8_t type_id = block[XESC2_OTP_OFFS_TYPE_ID];
        uint8_t variant_id = block[XESC2_OTP_OFFS_VARIANT];
        uint8_t hw_maj = block[XESC2_OTP_OFFS_HW_MAJOR];
        uint8_t hw_min = block[XESC2_OTP_OFFS_HW_MINOR];
        uint8_t hw_pat = block[XESC2_OTP_OFFS_HW_PATCH];
        uint16_t serial = (uint16_t)block[XESC2_OTP_OFFS_SERIAL] |
                          ((uint16_t)block[XESC2_OTP_OFFS_SERIAL + 1] << 8);
        uint32_t ts = (uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP] |
                      ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 1] << 8) |
                      ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 2] << 16) |
                      ((uint32_t)block[XESC2_OTP_OFFS_TIMESTAMP + 3] << 24);

        commands_printf("Pair %d: Magic=0x%02X Ver=%d Type=%d Var=%d "
                        "HW=%d.%d.%d Serial=%u Timestamp=%u CRC=%s",
                        pair, magic, ver, type_id, variant_id,
                        hw_maj, hw_min, hw_pat, serial, (unsigned int)ts, crc_ok);

        if (expected_crc == actual_crc) {
            found++;
            active_pair = pair; // highest valid pair wins (xesc2_get_otp_identity semantics)
        }
    }

    commands_printf(" ");
    if (found > 0) {
        commands_printf("Active identity: Type=%d Variant=%d HW=%d.%d.%d Serial=%u",
                        g_xesc2_otp_identity.type_id, g_xesc2_otp_identity.variant_id,
                        g_xesc2_otp_identity.hw_major, g_xesc2_otp_identity.hw_minor,
                        g_xesc2_otp_identity.hw_patch, g_xesc2_otp_identity.serial);

        const uint8_t *block = otp_read_block(active_pair);
        char hexbuf[129];
        for (int i = 0; i < 64; i++) {
            static const char hx[] = "0123456789abcdef";
            hexbuf[i * 2]     = hx[block[i] >> 4];
            hexbuf[i * 2 + 1] = hx[block[i] & 0x0F];
        }
        hexbuf[128] = '\0';
        commands_printf("ACTIVE_RAW: %s", hexbuf);
    } else {
        commands_printf("No valid OTP identity found, using defaults.");
    }
    commands_printf(" ");
}

// ------------------------------------------------------------------
// Terminal: otp_brand command
//   Usage: otp_brand <pair> <128 hex chars>
// Programs a host-prepared, signed 64-byte block pair (block0[0..31] +
// block1[0..31] = data + CRC16 + BLS signature, produced by the otp_brand host
// tool) into the STM32 OTP region. The block's magic/version/CRC are validated
// first, and the target pair must still be erased (OTP can only clear bits).
// Lock bytes are never touched, so the 8-slot rebrand scheme stays intact.
// ------------------------------------------------------------------
static int otp_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void xesc2_terminal_otp_brand(int argc, const char **argv) {
    if (argc != 2) {
        commands_printf("Usage: otp_brand <128 hex chars>");
        return;
    }

    // Auto-detect the next free pair (first pair with all 0xFF bytes).
    int pair = -1;
    for (int i = 0; i < XESC2_OTP_NUM_PAIRS; i++) {
        const uint8_t *cur = otp_read_block(i);
        bool empty = true;
        for (int j = 0; j < 64; j++) {
            if (cur[j] != 0xFF) { empty = false; break; }
        }
        if (empty) { pair = i; break; }
    }
    if (pair < 0) {
        commands_printf("otp_brand: no free pair available (all %d pairs used)",
                        XESC2_OTP_NUM_PAIRS);
        return;
    }

    // Parse 64 bytes from 128 hex chars.
    const char *hexstr = argv[1];
    if (strlen(hexstr) != 64 * 2) {
        commands_printf("otp_brand: expected 128 hex chars, got %d",
                        (int)strlen(hexstr));
        return;
    }
    uint8_t blk[64];
    for (int i = 0; i < 64; i++) {
        int hi = otp_hexval(hexstr[i * 2]);
        int lo = otp_hexval(hexstr[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            commands_printf("otp_brand: bad hex char at byte %d", i);
            return;
        }
        blk[i] = (uint8_t)((hi << 4) | lo);
    }

    // Validate header + CRC before burning OTP.
    if (blk[XESC2_OTP_OFFS_MAGIC] != XESC2_OTP_MAGIC) {
        commands_printf("otp_brand: bad magic 0x%02X (want 0x%02X)",
                        blk[XESC2_OTP_OFFS_MAGIC], XESC2_OTP_MAGIC);
        return;
    }
    if (blk[XESC2_OTP_OFFS_VERSION] != XESC2_OTP_VERSION) {
        commands_printf("otp_brand: bad version %d (want %d)",
                        blk[XESC2_OTP_OFFS_VERSION], XESC2_OTP_VERSION);
        return;
    }
    uint16_t want_crc = (uint16_t)blk[XESC2_OTP_OFFS_CRC] |
                        ((uint16_t)blk[XESC2_OTP_OFFS_CRC + 1] << 8);
    uint16_t got_crc = otp_crc16(blk + XESC2_OTP_CRC_DATA_OFFS,
                                 XESC2_OTP_CRC_DATA_LEN);
    if (want_crc != got_crc) {
        commands_printf("otp_brand: CRC mismatch (calc 0x%04X, block 0x%04X)",
                        got_crc, want_crc);
        return;
    }

    // OTP can only clear bits (1 -> 0): require the target pair to be erased.
    uint32_t addr = XESC2_OTP_BASE_ADDR +
                    (uint32_t)pair * 2 * XESC2_OTP_BLOCK_SIZE;
    const uint8_t *cur = (const uint8_t *)addr;
    for (int i = 0; i < 64; i++) {
        if (cur[i] != 0xFF) {
            commands_printf("otp_brand: pair %d not empty (byte %d = 0x%02X), "
                            "pick a free pair", pair, i, cur[i]);
            return;
        }
    }

    // Program via the shared flash helper (motor release, kernel lock, watchdog).
    uint16_t res = flash_helper_write_otp(addr, blk, 64);
    if (res != 0) {
        commands_printf("otp_brand: flash write failed (code %u)", res);
        return;
    }

    // Verify readback.
    for (int i = 0; i < 64; i++) {
        if (cur[i] != blk[i]) {
            commands_printf("otp_brand: verify failed at byte %d "
                            "(got 0x%02X, want 0x%02X)", i, cur[i], blk[i]);
            return;
        }
    }

    commands_printf("otp_brand: pair %d programmed OK at 0x%08X. "
                    "Power-cycle to apply.", pair, (unsigned int)addr);
}

// ------------------------------------------------------------------
// Helper: print OTP identity info (used by hw_status)
// ------------------------------------------------------------------
void xesc2_print_hw_status_otp_info(void) {
    if (!xesc2_has_otp_data()) {
        commands_printf("OTP detected: No");
    } else if (!g_xesc2_otp_identity.valid) {
        commands_printf("Invalid OTP detected (CRC mismatch)");
    } else {
        // Type name
        const char *type_name = "Unknown";
        if (g_xesc2_otp_identity.type_id == XESC2_TYPE_MINI) {
            type_name = "xESC2 Mini";
        } else if (g_xesc2_otp_identity.type_id == XESC2_TYPE_LITE) {
            type_name = "xESC2 Lite";
        }
        commands_printf("OTP Board Type: %s (ID %d)", type_name, g_xesc2_otp_identity.type_id);

        // Variant name
        const char *variant_name = "Unknown";
        if (g_xesc2_otp_identity.variant_id == XESC2_VARIANT_V1_STD) {
            variant_name = "V1 Standard";
        } else if (g_xesc2_otp_identity.variant_id == XESC2_VARIANT_V2_STD) {
            variant_name = "V2 Standard";
        } else if (g_xesc2_otp_identity.variant_id == XESC2_VARIANT_V2_PWR) {
            variant_name = "V2 Power";
        }
        commands_printf("OTP Variant: %s (ID %d)", variant_name, g_xesc2_otp_identity.variant_id);

        commands_printf("OTP HW Version: %d.%d.%d",
                        g_xesc2_otp_identity.hw_major,
                        g_xesc2_otp_identity.hw_minor,
                        g_xesc2_otp_identity.hw_patch);

        commands_printf("OTP Serial: %u", g_xesc2_otp_identity.serial);

        if (g_xesc2_otp_identity.timestamp > 0) {
            // Convert Unix timestamp to YYYY-MM-DD HH:MM:SS (UTC)
            // Simple algorithm without <time.h> dependency
            uint32_t ts = g_xesc2_otp_identity.timestamp;
            uint32_t days = ts / 86400;
            uint32_t secs = ts % 86400;
            uint32_t h = secs / 3600;
            uint32_t m = (secs % 3600) / 60;
            uint32_t s = secs % 60;

            // Day calculation starting from 1970-01-01
            uint32_t y = 1970;
            while (1) {
                uint32_t days_in_year = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 366 : 365;
                if (days < days_in_year) break;
                days -= days_in_year;
                y++;
            }

            // Days per month (non-leap year)
            static const uint8_t month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
            uint8_t leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 1 : 0;
            uint32_t mo = 0;
            while (mo < 12) {
                uint32_t md = month_days[mo];
                if (mo == 1) md += leap;
                if (days < md) break;
                days -= md;
                mo++;
            }
            uint32_t d = days + 1;
            mo += 1;

            commands_printf("OTP Timestamp: %u (%04u-%02u-%02u %02u:%02u:%02u UTC)",
                           (unsigned int)ts, y, mo, d, h, m, s);
        } else {
            commands_printf("OTP Timestamp: N/A");
        }
    }

    // Additional HW info from variant config
    if (g_xesc2_variant) {
        commands_printf("Current Amp Gain: %.3f", (double)g_xesc2_variant->current_amp_gain);
        commands_printf("Current Shunt Res: %.4f mOhm",
                        (double)(g_xesc2_variant->current_shunt_res * 1000.0));
    }
}

#endif // HAS_OTP
