//
// Created by clemens on 4/14/26.
//
#include "conf_general.h"

#ifdef HW_HAS_DRV8376
#include "drv8376.h"
#include "ch.h"
#include "commands.h"
#include "hal.h"
#include "stdio.h"
#include "stm32f4xx_conf.h"
#include "string.h"
#include "utils_math.h"
#include "terminal.h"

// Private functions
static uint32_t spi_exchange_24(uint32_t x);
static void spi_transfer(uint8_t *in_buf, const uint8_t *out_buf, int length);
static void spi_begin(void);
static void spi_end(void);
static void spi_delay(void);
uint16_t drv8376_read_reg(uint16_t reg);
void drv8376_write_reg(uint16_t reg, uint16_t data);

static void terminal_read_reg(int argc, const char **argv);
static void terminal_write_reg(int argc, const char **argv);

static void terminal_print_faults(int argc, const char **argv);
static void terminal_clear_faults(int argc, const char **argv);

void drv8376_read_faults(unsigned int*,unsigned int*,unsigned int*,unsigned int*);
char* drv8376_faults_to_string(unsigned int dev_status,unsigned int overtemperature_status, unsigned int supply_status, unsigned int driver_status);


unsigned int latch_dev_status = 0;
unsigned int latch_overtemperature_status = 0;
unsigned int latch_supply_status = 0;
unsigned int latch_driver_status = 0;

// Private variables
static char m_fault_print_buffer[255];
static mutex_t m_spi_mutex;

bool config_fault = false;


void drv8376_init(void) {
	chMtxObjectInit(&m_spi_mutex);

	latch_dev_status = 0;
	latch_overtemperature_status = 0;
	latch_supply_status = 0;
	latch_driver_status = 0;

	// DRV8376 SPI
	palSetPadMode(DRV8376_MISO_GPIO, DRV8376_MISO_PIN, PAL_MODE_INPUT);
	palSetPadMode(DRV8376_SCK_GPIO, DRV8376_SCK_PIN, PAL_MODE_OUTPUT_PUSHPULL | PAL_STM32_OSPEED_HIGHEST);
	palSetPadMode(DRV8376_CS_GPIO, DRV8376_CS_PIN, PAL_MODE_OUTPUT_PUSHPULL | PAL_STM32_OSPEED_HIGHEST);
	palSetPadMode(DRV8376_MOSI_GPIO, DRV8376_MOSI_PIN, PAL_MODE_OUTPUT_PUSHPULL | PAL_STM32_OSPEED_HIGHEST);
	palSetPad(DRV8376_MOSI_GPIO, DRV8376_MOSI_PIN);
	palSetPadMode(DRV8376_nSLEEP_GPIO, DRV8376_nSLEEP_PIN, PAL_MODE_OUTPUT_PUSHPULL | PAL_STM32_OSPEED_HIGHEST);
	palSetPadMode(DRV8376_ILIMIT_GPIO, DRV8376_ILIMIT_PIN, PAL_MODE_OUTPUT_PUSHPULL | PAL_STM32_OSPEED_HIGHEST);

	// Reset the DRV
	palClearPad(DRV8376_nSLEEP_GPIO, DRV8376_nSLEEP_PIN);
	chThdSleepMilliseconds(100);
	palSetPad(DRV8376_nSLEEP_GPIO, DRV8376_nSLEEP_PIN);

	// TODO: use DAC if we want to limit the current, I think we skip it for now
	// set max ILIMIT
	palSetPad(DRV8376_ILIMIT_GPIO, DRV8376_ILIMIT_PIN);

	chThdSleepMilliseconds(100);

	drv8376_set_current_amp_gain(CURRENT_AMP_GAIN);

	terminal_register_command_callback(
			"drv8376_read_reg",
			"Read a register from the DRV8376 and print it.",
			"[reg]",
			terminal_read_reg);

	terminal_register_command_callback(
			"drv8376_write_reg",
			"Write to a DRV8376 register.",
			"[reg] [hexvalue]",
			terminal_write_reg);

	terminal_register_command_callback(
			"drv8376_print_faults",
			"Print all current DRV8376 faults.",
			0,
			terminal_print_faults);
	terminal_register_command_callback(
			"drv8376_reset_faults",
			"Reset all current and historic faults.",
			0,
			terminal_clear_faults);

}

void drv8376_reset_faults(void) {
	unsigned int dev_status, overtemperature_status, supply_status, driver_status;
	drv8376_read_faults(&dev_status, &overtemperature_status, &supply_status, &driver_status);
	// Write FLT_CLR bit
	drv8376_write_reg(0x17, 1);
}

void drv8376_set_current_amp_gain(float gain) {
	if (gain == 0.4f) {
		drv8376_write_reg(0x23, 0);
	} else if (gain == 1.0f) {
		drv8376_write_reg(0x23, 1);
	} else if (gain == 2.5f) {
		drv8376_write_reg(0x23, 2);
	} else  if (gain == 5.0f) {
		drv8376_write_reg(0x23, 3);
	} else {
		config_fault = 1;
		chDbgAssert(false, "Invalid gain value");
	}
}

bool drv8376_config_error(void) {
	return config_fault;
}

uint16_t drv8376_read_reg(uint16_t reg) {
	uint32_t out = 0;
	// Read bit
	out |= (1 << 16);
	// Address
	out |= (reg & 0x3F) << 17;

	chMtxLock(&m_spi_mutex);

	uint32_t res = spi_exchange_24(out);

	chMtxUnlock(&m_spi_mutex);

	return res & 0xFFFF;
}

void drv8376_write_reg(uint16_t reg, uint16_t data) {
	uint32_t out = 0;
	// Address
	out |= (reg & 0x3F) << 17;
	// data
	out |= data & 0x7FFF;

	chMtxLock(&m_spi_mutex);

	spi_exchange_24(out);

	chMtxUnlock(&m_spi_mutex);
}


static void terminal_read_reg(int argc, const char **argv) {
	if (argc == 2) {
		int reg = -1;
		sscanf(argv[1], "%d", &reg);

		if (reg >= 0) {
			unsigned int res = drv8376_read_reg(reg);
			char bl[9];
			char bh[9];

			utils_byte_to_binary((res >> 8) & 0xFF, bh);
			utils_byte_to_binary(res & 0xFF, bl);

			commands_printf("Reg 0x%02x: %s %s (0x%04x)\n", reg, bh, bl, res);
		} else {
			commands_printf("Invalid argument(s).\n");
		}
	} else {
		commands_printf("This command requires one argument.\n");
	}
}

void drv8376_set_oc_adj(int val) {
	if (val >= 0 && val < 32) {
		unsigned int reg = drv8376_read_reg(5);
		reg &= ~(0x1F << 6);
		reg |= (val & 0x1F) << 6;
		drv8376_write_reg(5, reg);
	}
}

void drv8376_read_faults(unsigned int* dev_status, unsigned int* overtemperature_status, unsigned int* supply_status, unsigned int* driver_status) {
	*dev_status = drv8376_read_reg(0x00);
	*overtemperature_status = drv8376_read_reg(0x04);
	*supply_status = drv8376_read_reg(0x05);
	*driver_status = drv8376_read_reg(0x06);

	// latch_dev_status |= *dev_status;
	// latch_overtemperature_status |= *overtemperature_status;
	// latch_supply_status |= *supply_status;
	// latch_driver_status |= *driver_status;
}

char* drv8376_faults_to_string(unsigned int dev_status, unsigned int overtemperature_status, unsigned int supply_status, unsigned int driver_status) {
	if ((dev_status & DRV8376_DEVICE_FAULT_MASK) == 0 && (overtemperature_status & DRV8376_TEMPERATURE_MASK) == 0 && (supply_status & DRV8376_SUPPLY_STAT_MASK) == 0 && (driver_status & DRV8376_DRIVER_STAT_MASK) == 0) {
		strcpy(m_fault_print_buffer, "No DRV8376 faults");
	} else {
		strcpy(m_fault_print_buffer, "|");

		if (dev_status & DRV8376_DEVICE_FAULT_FAULT) {
			strcat(m_fault_print_buffer, " FAULT |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_OTF) {
			strcat(m_fault_print_buffer, " OTF |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_UVP) {
			strcat(m_fault_print_buffer, " UVP |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_OVP) {
			strcat(m_fault_print_buffer, " OVP |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_OCP) {
			strcat(m_fault_print_buffer, " OCP |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_SPIFLT) {
			strcat(m_fault_print_buffer, " SPIFLT |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_RESET) {
			strcat(m_fault_print_buffer, " RESET |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_SYSFLT) {
			strcat(m_fault_print_buffer, " SYSFLT |");
		}

		if (dev_status & DRV8376_DEVICE_FAULT_DNRDY_STS) {
			strcat(m_fault_print_buffer, " DNRDY |");
		}

		if (overtemperature_status & DRV8376_TEMPERATURE_OTSD) {
			strcat(m_fault_print_buffer, " OTSD |");
		}

		if (overtemperature_status & DRV8376_TEMPERATURE_OTW) {
			strcat(m_fault_print_buffer, " OTW |");
		}

		if (supply_status & DRV8376_SUPPLY_STAT_VM_OV) {
			strcat(m_fault_print_buffer, " VM_OV |");
		}

		if (supply_status & (DRV8376_SUPPLY_STAT_CP_UV << 24)) {
			strcat(m_fault_print_buffer, " CP_UV |");
		}

		if (driver_status & DRV8376_DRIVER_STAT_OCPC_HS) {
			strcat(m_fault_print_buffer, " OCPC_HS |");
		}
		if (driver_status & DRV8376_DRIVER_STAT_OCPB_HS) {
			strcat(m_fault_print_buffer, " OCPB_HS |");
		}
		if (driver_status & DRV8376_DRIVER_STAT_OCPA_HS) {
			strcat(m_fault_print_buffer, " OCPA_HS |");
		}
		if (driver_status & DRV8376_DRIVER_STAT_OCPC_LS) {
			strcat(m_fault_print_buffer, " OCPC_LS |");
		}
		if (driver_status & DRV8376_DRIVER_STAT_OCPB_LS) {
			strcat(m_fault_print_buffer, " OCPB_LS |");
		}
		if (driver_status & DRV8376_DRIVER_STAT_OCPA_LS) {
			strcat(m_fault_print_buffer, " OCPA_LS |");
		}
		if (config_fault) {
			strcat(m_fault_print_buffer, " CONFIG_FAULT |");
		}
	}

	return m_fault_print_buffer;
}

static void terminal_write_reg(int argc, const char **argv) {
	if (argc == 3) {
		int reg = -1;
		int val = -1;
		sscanf(argv[1], "%d", &reg);
		sscanf(argv[2], "%x", &val);

		if (reg >= 0 && val >= 0) {
			drv8376_write_reg(reg, val);
			unsigned int res = drv8376_read_reg(reg);
			char bl[9];
			char bh[9];

			utils_byte_to_binary((res >> 8) & 0xFF, bh);
			utils_byte_to_binary(res & 0xFF, bl);

			commands_printf("New reg value 0x%02x: %s %s (0x%04x)\n", reg, bh, bl, res);
		} else {
			commands_printf("Invalid argument(s).\n");
		}
	} else {
		commands_printf("This command requires two arguments.\n");
	}
}

static void terminal_print_faults(int argc, const char **argv) {
	(void)argc;
	(void)argv;
	unsigned int dev_status, overtemperature_status, supply_status, driver_status;
	drv8376_read_faults(&dev_status, &overtemperature_status, &supply_status, &driver_status);
	commands_printf("Current faults:");
	commands_printf(drv8376_faults_to_string(dev_status, overtemperature_status, supply_status, driver_status));
	commands_printf("Historic faults:");
	commands_printf(drv8376_faults_to_string(latch_dev_status, latch_overtemperature_status, latch_supply_status, latch_driver_status));
}

static void terminal_clear_faults(int argc, const char **argv) {
	(void)argc;
	(void)argv;
	drv8376_reset_faults();
	latch_dev_status = 0;
	latch_overtemperature_status = 0;
	latch_supply_status = 0;
	latch_driver_status = 0;
	unsigned int dev_status, overtemperature_status, supply_status, driver_status;
	// read once again, this will also update the latch
	drv8376_read_faults(&dev_status, &overtemperature_status, &supply_status, &driver_status);
	commands_printf("All faults cleared, new faults:");
	commands_printf(drv8376_faults_to_string(latch_dev_status, latch_overtemperature_status, latch_supply_status, latch_driver_status));
}

// Software SPI
static uint32_t spi_exchange_24(uint32_t x) {
	uint8_t out_buf[3];
	uint8_t in_buf[3];

	out_buf[0] = (x >> 16) & 0xFF;
	out_buf[1] = (x >> 8) & 0xFF;
	out_buf[2] = x & 0xFF;

	spi_transfer(in_buf, out_buf, 3);

	return ((uint32_t)in_buf[0] << 16) | ((uint32_t)in_buf[1] << 8) | (uint32_t)in_buf[2];
}

static void spi_transfer(uint8_t *in_buf, const uint8_t *out_buf, int length) {
	spi_begin();
	spi_delay();
	for (int i = 0;i < length;i++) {
		uint8_t send = out_buf ? out_buf[i] : 0xFF;
		uint8_t receive = 0;

		for (int bit = 0;bit < 8;bit++) {
			palWritePad(DRV8376_MOSI_GPIO, DRV8376_MOSI_PIN, (send >> 7) & 1);
			send <<= 1;

			spi_delay();
			palSetPad(DRV8376_SCK_GPIO, DRV8376_SCK_PIN);
			spi_delay();
			palClearPad(DRV8376_SCK_GPIO, DRV8376_SCK_PIN);

			int r1, r2, r3;
			r1 = palReadPad(DRV8376_MISO_GPIO, DRV8376_MISO_PIN);
			__NOP();
			r2 = palReadPad(DRV8376_MISO_GPIO, DRV8376_MISO_PIN);
			__NOP();
			r3 = palReadPad(DRV8376_MISO_GPIO, DRV8376_MISO_PIN);

			receive <<= 1;
			if (utils_middle_of_3_int(r1, r2, r3)) {
				receive |= 1;
			}
		}

		if (in_buf) {
			in_buf[i] = receive;
		}
	}
	spi_delay();
	spi_end();
}

static void spi_begin(void) {
	palClearPad(DRV8376_SCK_GPIO, DRV8376_SCK_PIN);
	spi_delay();
	palClearPad(DRV8376_CS_GPIO, DRV8376_CS_PIN);
}

static void spi_end(void) {
	palSetPad(DRV8376_CS_GPIO, DRV8376_CS_PIN);
}

static void spi_delay(void) {
	for (volatile int i = 0;i < 10;i++) {
		__NOP();
	}
}


#endif

