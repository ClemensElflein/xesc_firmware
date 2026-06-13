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

#include "xesc2_variant_config.h"
#include "crc.h"
#include "xesc2_otp.h"

// Global pointer to the active variant configuration
const xesc2_variant_config_t *g_xesc2_variant = 0;

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

static xesc2_otp_identity_t otp_scan(void)
{
    xesc2_otp_identity_t id = {0, 0, 0};

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
            id.valid = 1;
            return id;
        }
    }

    return id;
}

// ------------------------------------------------------------------
// Variant configuration tables (indexed by type_id, variant_id)
// ------------------------------------------------------------------

// -- Mini type (XESC2_TYPE_MINI) --
static const xesc2_variant_config_t variant_mini_v1_standard = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = XESC2_VARIANT_V1_STD,
    // Do not use spaces in hw_name — it becomes part of the UAVCAN node name
    .hw_name = "xESC2-mini_v1",
    .current_amp_gain = (5.0f * 0.595f), // 5x gain * voltage divider ratio
    .current_shunt_res = 0.033f,
    .get_current_scale = 1.11f,
    .tmc6200_amp_gain = 5,
    .tmc6200_drvstrength = 2, // medium (default)
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
};

static const xesc2_variant_config_t variant_mini_v2_power = {
    .type_id = XESC2_TYPE_MINI,
    .variant_id = XESC2_VARIANT_V2_POWER,
    // Do not use spaces in hw_name — it becomes part of the UAVCAN node name
    .hw_name = "xESC2-power_v2",
    .current_amp_gain = 10.0f,
    .current_shunt_res = 0.003f,
    .get_current_scale = 0.935f,
    .tmc6200_amp_gain = 10,
    .tmc6200_drvstrength = 3, // strong for BSC0702LS (1300pF Ciss) at VIO=3.3V
    .lim_current_min = -11.5f,
    .lim_current_max = 11.5f,
    .lim_current_in_min = -11.0f,
    .lim_current_in_max = 11.0f,
    .lim_current_abs_max = 25.0f,
    .lim_vin_min = 9.0f,
    .lim_vin_max = 48.0f,
    .lim_temp_fet_max = 85.0f,
    .l_max_abs_current = 25.0f,
    .mcconf_l_current_max = 11.5f,
    .mcconf_l_current_min = -11.5f,
    .mcconf_l_in_current_max = 11.0f,
    .mcconf_l_in_current_min = -11.0f,
};

// -- Lite type (XESC2_TYPE_LITE) —
// TODO: Add lite variants if usefull to integrated here

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

const xesc2_variant_config_t *xesc2_get_variant_config(uint8_t type_id, uint8_t variant_id) {
    if (type_id == XESC2_TYPE_MINI) {
        if (variant_id == XESC2_VARIANT_V1_STD) {
            return &variant_mini_v1_standard;
        }
        if (variant_id == XESC2_VARIANT_V2_POWER) {
            return &variant_mini_v2_power;
        }
    }

    // Unknown combination — fall back to Mini Standard as safe default
    return &variant_mini_v1_standard;
}

void xesc2_detect_and_apply_variant(void) {
    xesc2_otp_identity_t id = otp_scan();

    if (id.valid) {
        g_xesc2_variant = xesc2_get_variant_config(id.type_id, id.variant_id);
    } else {
        // No valid OTP found — fall back to Mini Standard
        g_xesc2_variant = xesc2_get_variant_config(XESC2_TYPE_MINI, XESC2_VARIANT_V1_STD);
    }
}
