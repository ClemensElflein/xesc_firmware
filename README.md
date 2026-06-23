# xESC Firmware (VESC based)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This is the firmware for the xESC2 family of motor controllers, based on the open-source [VESC firmware](https://github.com/vedderb/bldc) by Benjamin Vedder.

## xESC-specific features

### Hardware variant auto-detection

All xESC2 boards use the **same firmware binary** (`xesc_all_variants`). The firmware reads an OTP (One-Time Programmable) identity record from flash at boot and configures itself for the detected hardware — gate driver, current sensing mode, pin assignments, and motor parameters are all selected at runtime.

| Hardware | How it's detected | Gate driver | Current sensing |
|---|---|---|---|
| xESC2 mini v1.x | No OTP + no v2 pin strap | TMC6200 | Phase shunts |
| xESC2 mini v2.x | OTP identity record | TMC6200 | Phase shunts |
| xESC2 power v2.x | OTP identity record | TMC6200 | Phase shunts |
| xESC2 lite | OTP identity record | DRV8376 | Low-side shunts |

**v1.x boards** have no OTP and no pin strap. The firmware detects this combination and loads the v1 hardware configuration automatically — no OTP branding required.

**v2.x boards** carry a pin strap that tells the firmware OTP is required. If OTP is missing or invalid, the firmware will **not** enable the motor and shows a static red LED.

### OTP Branding (xESC2 v2.x series)

v2.x boards ship with a factory-written OTP identity record containing the board type, hardware variant, revision, and the STM32's unique chip ID. The record is cryptographically signed to prevent misconfiguration.

#### Builder Keys

Builder keys are BLS12-381 private keys — generated once per builder and stored securely (e.g. `~/.config/xesc/keys/builder1.key`). Only needed during branding, not for normal operation.

#### Building the Branding Tool

```bash
cd cmd/otp_brand
go build -o otp_brand .
```

Or use Docker for a fully static binary:

```bash
docker build -f cmd/otp_brand/Dockerfile -o out .
# binary lands in out/otp_brand
```

#### Usage

```bash
# 1. Generate a builder key (once per builder)
./otp_brand --generate-key ~/.config/xesc/keys/builder1.key
# -> ~/.config/xesc/keys/builder1.key      (private key, 32 bytes)
# -> ~/.config/xesc/keys/builder1.key.pub  (public key, 96 bytes hex)

# 2. Sign an OTP identity block
./otp_brand --type mini --variant v2_pwr --hw 2.0.1 \
    --key ~/.config/xesc/keys/builder1.key --output otp_blocks.bin

# 3. Verify the signature before flashing
./otp_brand --verify otp_blocks.bin --key ~/.config/xesc/keys/builder1.key
# or with public key only:
./otp_brand --verify-pub otp_blocks.bin --key ~/.config/xesc/keys/builder1.key.pub

# 4a. Flash OTP via STM32CubeProgrammer (ST-Link required)
./otp_brand --type mini --variant v2_pwr --hw 2.0.1 \
    --key ~/.config/xesc/keys/builder1.key --flash

# 4b. Flash OTP over USB/CAN comm link (no ST-Link needed)
./otp_brand --type mini --variant v2_pwr --hw 2.0.1 \
    --key ~/.config/xesc/keys/builder1.key --emit-hex \
    | vesc-tool-or-terminal otp_brand 0 <hex>
```

STM32CubeProgrammer discovery order: `$ST_PROGRAMMER_PATH` → `/usr/local/STMicroelectronics/...` → `/opt/STMicroelectronics/...` → `$PATH`.

| Flag             | Values / Description                                          |
| ---------------- | ------------------------------------------------------------- |
| `--type`         | `mini`, `lite`                                                |
| `--variant`      | `v1_std`, `v2_std`, `v2_pwr`                                  |
| `--hw`           | `"2.0.1"` (`MAJOR.MINOR.PATCH`)                               |
| `--key`          | Private key path (32 bytes), or public key for `--verify-pub` |
| `--output`       | Output `.bin` path (default: `otp_blocks.bin`)                |
| `--verify`       | Verify signature in a `.bin` using private key `--key`        |
| `--verify-pub`   | Verify signature in a `.bin` using public key `--key`         |
| `--generate-key` | Create new key pair at PATH                                   |
| `--dump-pubkey`  | Print public key for a private key file                       |
| `--emit-hex`     | Print signed block as hex for on-device programming           |
| `--dry-run`      | Show what would be done without writing                       |
| `--dump-c`       | Output C arrays for firmware `test_otp_block[]`               |
| `--serial`       | Override auto-increment serial number                         |
| `--force`        | Skip OTP occupation check                                     |

#### On-device terminal commands

Once firmware is running, two terminal commands are available:

- `otp_info` — dump all OTP pairs with CRC validation and show the active block
- `otp_brand <pair> <128-hex-chars>` — program a signed block directly (use `--emit-hex` output from the host tool)

---

## VESC Firmware (upstream)

The sections below are from the upstream VESC firmware README. Build instructions, IDE setup, and flashing methods apply to xESC targets as well — use `xesc_all_variants` as the target name instead of the VESC examples shown.

---

[![Travis CI Status](https://travis-ci.com/vedderb/bldc.svg?branch=master)](https://travis-ci.com/vedderb/bldc)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/75e90ffbd46841a3a7be2a9f7a94c242)](https://www.codacy.com/app/vedderb/bldc?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=vedderb/bldc&amp;utm_campaign=Badge_Grade)
[![Contributors](https://img.shields.io/github/contributors/vedderb/bldc.svg)](https://github.com/vedderb/bldc/graphs/contributors)
[![Watchers](https://img.shields.io/github/watchers/vedderb/bldc.svg)](https://github.com/vedderb/bldc/watchers)
[![Stars](https://img.shields.io/github/stars/vedderb/bldc.svg)](https://github.com/vedderb/bldc/stargazers)
[![Forks](https://img.shields.io/github/forks/vedderb/bldc.svg)](https://github.com/vedderb/bldc/network/members)

An open source motor controller firmware.

This is the source code for the VESC DC/BLDC/FOC controller. Read more at
[https://vesc-project.com/](https://vesc-project.com/)

## Supported boards

All of them!

Check the supported boards by typing `make`

```
[Firmware]
     fw   - Build firmware for default target
                            supported boards are: 100_250 100_250_no_limits 100_500...
```

There are also many other options that can be changed in [conf_general.h](conf_general.h).

## Prerequisites

### On Ubuntu (Linux)/macOS
- Tools: `git`, `wget`, and `make`
- Additional Linux requirements: `libgl-dev` and `libxcb-xinerama0`
- Helpful Ubuntu commands:
```bash
sudo apt install git build-essential libgl-dev libxcb-xinerama0 wget git-gui
```
- Helpful macOS tools: 

```bash
brew install stlink
brew install openocd
```

### On Windows
- Chocolately: https://chocolatey.org/install
- Git: https://git-scm.com/download/win. Make sure to click any boxes to add Git to your Environment (aka PATH)

## Install Dev environment and build

### On Ubuntu (Linux)/MacOS
Open up a terminal
1.  `git clone http://github.com/vedderb/bldc.git`
2.  `cd bldc`
3.  Continue with [On all platforms](#on-all-platforms)

### On Windows

1.  Open up a Windows Powershell terminal (Resist the urge to run Powershell as administrator, that will break things)
2.  Type `choco install make`
3.  `git clone http://github.com/vedderb/bldc`
4.  `cd bldc`
5.  Continue with [On all platforms](#on-all-platforms)

### On all platforms

1.  `git checkout origin/master`
2.  `make arm_sdk_install`
3.  `make` <-- Pick out the name of your target device from the supported boards list. For instance, I have a Trampa **VESC 100/250**, so my target is `100_250`
4.   `make 100_250` <-- This will build the **VESC 100/250** firmware and place it into the `bldc/builds/100_250/` directory

## Other tools

**Linux Optional - Add udev rules to use the stlink v2 programmer without being root**
```bash
wget vedder.se/Temp/49-stlinkv2.rules
sudo mv 49-stlinkv2.rules /etc/udev/rules.d/
sudo udevadm trigger
```

## IDE
### Prerequisites
#### On macOS/Linux

- `python3`, and `pip`

#### On Windows
- Python 3: https://www.python.org/downloads/. Make sure to click the box to add Python3 to your Environment.

### All platforms

1.  `pip install aqtinstall`
2.  `make qt_install`
3.  Open Qt Creator IDE installed in `tools/Qt/Tools/QtCreator/bin/qtcreator`
4.  With Qt Creator, open the vesc firmware Qt Creator project, named vesc.pro. You will find it in `Project/Qt Creator/vesc.pro`
5.  The IDE is configured by default to build 100_250 firmware, this can be changed in the bottom of the left panel, there you will find all hardware variants supported by VESC

## Upload to VESC
### Method 1 - Flash it using an STLink SWD debugger

1.  Build and flash the [bootloader](https://github.com/vedderb/bldc-bootloader) first
2.  Then `_flash` to the target of your choice. So for instance, for the VESC 100/250: 
```bash
make 100_250_flash
```

### Method 2 - Upload Firmware via VESC tool through USB

1.  Clone and build the firmware in **.bin** format as in the above Build instructions

In VESC tool

2.  Connect to the VESC
3.  Navigate to the Firmware tab on the left side menu 
4.  Click on Custom file tab
5.  Click on the folder icon to select the built firmware in .bin format (e.g. `build/100_250/100_250.bin`)

##### [ Reminder : It is normal to see VESC disconnects during the firmware upload process ]  
#####  **[ Warning : DO NOT DISCONNECT POWER/USB to VESC during the upload process, or you will risk bricking your VESC ]**  
#####  **[ Warning : ONLY DISCONNECT your VESC 10s after the upload loading bar completed and "FW Upload DONE" ]**

6.  Press the upload firmware button (downward arrow) on the bottom right to start upload the selected firmware.
7.  Wait for **10s** after the loading bar completed (Warning: unplug sooner will risk bricking your VESC)
8.  The VESC will disconnect itself after new firmware is uploaded.

## In case you bricked your VESC
you will need to upload a new working firmware to the VESC.  
However, to upload a firmware to a bricked VESC, you have to use a SWD Debugger.

## Contribute

Head to the [forums](https://vesc-project.com/forum) to get involved and improve this project.
Join the [Discord](https://discord.gg/JgvV5NwYts) for real-time support and chat

## Tags

Every firmware release has a tag. They are created as follows:

```bash
git tag -a [version] [commit] -m "VESC Firmware Version [version]"
git push --tags
```

## License

The software is released under the GNU General Public License version 3.0
