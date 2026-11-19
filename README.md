# AMD RAS MANAGER

The **amd-ras-manager** service is intended to discover, configure, and exercise
Out-Of-Band (OOB) Reliability, Availability, and Serviceability (RAS)
capabilities supported by AMD processors. The service harvests RAS telemetry,
creates CPER crash records, exposes D-Bus interfaces, and uses a flexible
multi‑platform configuration model.

**Branch Requirement:** Integrate this project using the **`integ_sp8`** branch. All platform layers and build systems should reference this branch when pulling sources.

```sh
git clone https://github.com/AMDESE/amd-bmc-ras.git
cd amd-bmc-ras
git checkout integ_sp8
```

For Yocto/OpenBMC recipes:
```bitbake
SRCBRANCH = "integ_sp8"
SRCREV    = "${AUTOREV}"
```

---

## Overview

`amd-ras-manager` communicates with AMD processors through APML to:
- Monitor APML alert assertions.
- Read SBRMI/SBRM registers to determine error conditions.
- Harvest MCA/MSR dumps and generate CPER files.
- Expose generated CPER files via Redfish.
- Manage RAS policy including system recovery actions.

If CPER record creation exceeds the limit of **10 entries**, older records are
rotated.

System recovery actions can be configured as:
- Cold reset
- Warm reset
- No reset

---

# Multi-Platform Configuration Architecture

`amd-ras-manager` supports multiple platforms. Each platform ships its own RAS
configuration file (`platform.json`) via its **platform-specific Yocto/meta
layer**. During boot, an init script selects the appropriate configuration and
places it at a shared runtime path:

```
/var/lib/platform-config/platform.json
```

If this file is **absent**, the service falls back to **default internal
configuration**.

---

# Multi‑Platform Architecture Diagram

```
                   +-----------------------------------------------+
                   |        Multiple Platform Meta-Layers          |
                   |-----------------------------------------------|
                   |                                               |
                   |  meta-MI300C/                                 |
                   |    └── platform.json ---------------------+   |
                   |                                           |   |
                   |  meta-turin/                              |   |
                   |    └── platform.json ------------------+  |   |
                   |                                        |  |   |
                   |  meta-sp7/                             |  |   |
                   |    └── platform.json ---------------+  |  |   |
                   |                                     |  |  |   |
                   +-------------------------------------|--|--|---+
                                                         |  |  |
                                      (installed to)     |  |  |
                                                         v  v  v
                             /usr/share/amd-ras/platforms/<platform>/
                             └── platform.json        (platform-specific)


                         +---------------------------------------------+
                         |  Init script (amd-ras-init.service)         |
                         |---------------------------------------------|
                         | Detect platform (FRU, board-id, etc.)       |
                         | Select correct platform.json                |
                         | Copy/symlink to:                            |
                         |     /var/lib/platform-config/platform.json  |
                         +---------------------------------------------+
                                           |
                                           v
                            /var/lib/platform-config/platform.json
                          (active configuration for runtime)


                         +----------------------------------------------+
                         |          amd-ras-manager daemon              |
                         |----------------------------------------------|
                         | Reads /var/lib/platform-config/platform.json |
                         | If missing → uses built-in defaults          |
                         | Exposes D-Bus interfaces                     |
                         | Handles crashdump creation                   |
                         +----------------------------------------------+
```

---

## Example Platform Layout

```
meta-amd-sp5/
 └── recipes-amd/amd-ras/files/platform.json   # SP5 config

meta-amd-sp7/
 └── recipes-amd/amd-ras/files/platform.json   # SP7 config
```

Both install to:
```
/usr/share/amd-ras/platforms/sp5/platform.json
/usr/share/amd-ras/platforms/sp7/platform.json
```

Init script sets:
```
/var/lib/platform-config/platform.json
```

---

## Example Init Script

```sh
#!/bin/sh
BOARD=$(cat /etc/board-id)

case "$BOARD" in
    SP5)
        ln -sf /usr/share/amd-ras/platforms/sp5/platform.json /var/lib/platform-config/platform.json
        ;;
    SP7)
        ln -sf /usr/share/amd-ras/platforms/sp7/platform.json /var/lib/platform-config/platform.json
        ;;
    *)
        echo "Unknown board, using defaults"
        ;;
 esac
```

---

## Example `platform.json` (MI300C)

Below is an example of a **platform-specific RAS configuration file** for the `meta-mi300c` layer:

```json
{
  "CpuCount": 4,
  "Model": "0x80",
  "FamilyID": "0x19",
  "DebugLogID": [
    1,
    2,
    3,
    23,
    24,
    25,
    33,
    36,
    37,
    38,
    40
  ]
}
```

This file should be placed in:
```
meta-mi300c/recipes-amd/amd-ras/files/platform.json
```
It will be installed to:
```
/usr/share/amd-ras/platforms/mi300c/platform.json
```
and selected by the init script at runtime:
```
/var/lib/platform-config/platform.json
```

---

# Features

- Monitors APML alert pins.
- Detects fatal/non-fatal conditions.
- Harvests MCA/MSR dumps.
- Generates CPER records.
- Supports rotation of up to 10 CPER entries.
- Triggers configurable system recovery.
- Reads configuration from `platform.json` (platform-specific or default).

---

# Configuration

Configuration options follow Meson’s build-system model.
See:
https://mesonbuild.com/Build-options.html

Available options are declared in `meson_options.txt`.

---

# Building

This project uses **Meson (>=1.1.1)**.

To build natively:

```sh
meson setup build
ninja -C build
```

---

