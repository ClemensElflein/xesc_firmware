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

#ifndef XESC2_VARIANT_CONFIG_H_
#define XESC2_VARIANT_CONFIG_H_

#include <stdint.h>
#include <stdbool.h>

// Note: Type and variant IDs are defined in xesc2_otp.h

// Gate driver IC used by a variant. Selects which driver implementation is
// initialized and dispatched to at runtime (single firmware for all variants).
#define XESC2_DRIVER_TMC6200 0 // xESC2 mini/power
#define XESC2_DRIVER_DRV8376 1 // xESC2 lite

// Structure returned by OTP scanner
typedef struct {
    uint8_t type_id;    // Board type from OTP (XESC2_TYPE_*)
    uint8_t variant_id; // Variant from OTP (XESC2_VARIANT_*)
    uint8_t valid;      // 1 if valid OTP record found
    uint8_t hw_major;   // Hardware version major
    uint8_t hw_minor;   // Hardware version minor
    uint8_t hw_patch;   // Hardware version patch
    uint16_t serial;    // Serial number
    uint32_t timestamp; // Build Unix timestamp
} xesc2_otp_identity_t;

typedef struct {
    uint8_t type_id;    // Board type this config belongs to
    uint8_t variant_id; // Variant this config belongs to
    const char *hw_name;
    uint8_t driver_type;     // Gate driver IC (XESC2_DRIVER_*)
    uint8_t gate_active_high; // 1: ENABLE_GATE drives pad high; 0: drives low
    float current_amp_gain;
    float current_shunt_res;
    float get_current_scale;     // ADC scaling for GET_CURRENT* macros
    uint8_t tmc6200_amp_gain;    // TMC6200 x5, x10, x20
    uint8_t tmc6200_drvstrength; // 0=weak, 1=weak+TC, 2=medium, 3=strong
    float lim_current_min;
    float lim_current_max;
    float lim_current_in_min;
    float lim_current_in_max;
    float lim_current_abs_max;
    float lim_vin_min;
    float lim_vin_max;
    float lim_temp_fet_max;
    float l_max_abs_current;
    float mcconf_l_current_max;
    float mcconf_l_current_min;
    float mcconf_l_in_current_max;
    float mcconf_l_in_current_min;
} xesc2_variant_config_t;

// Global pointer to the active variant config, initialized at startup
extern const xesc2_variant_config_t *g_xesc2_variant;

// Global OTP identity, populated at startup
extern xesc2_otp_identity_t g_xesc2_otp_identity;

// Fatal config error flag: set when OTP is missing on v2 or corrupt.
// Causes tmc_error() to report permanent fault, blocking motor start.
extern bool g_xesc2_fatal_config_error;

bool xesc2_has_otp_data(void);
xesc2_otp_identity_t xesc2_get_otp_identity(void);

const xesc2_variant_config_t *xesc2_get_variant_config(uint8_t type_id, uint8_t variant_id);
void xesc2_detect_and_apply_variant(void);

void xesc2_terminal_otp_info(int argc, const char **argv);
void xesc2_print_hw_status_otp_info(void);

#endif /* XESC2_VARIANT_CONFIG_H_ */
