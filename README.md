# AMD RAS MANAGER

The amd-ras-manager service is intended to discover, configure and exercise Out
Of Band (OOB) Reliability Availability and Serviceability (RAS) capabilities
supported by the processors. The service creates error records from RAS
telemetry extracted from the processor over Advanced Platform Management Link
(APML).

## Features

The amd-ras-manager service reads SBRMI registers over the APML upon the APML_L
assertion by the System Management Unit (SMU). If the SBRMI register indicates
if the assertion is due to the fatal error, BMC harvests MCA and MSR dump via
APML and generates the CPER record. On user demand, these CPER files will be
available for download via redfish. The CPER records will be rotated after
reaching maximum limit of 10 CPER records in the BMC.

Once the CPER record is created, BMC triggers system recovery either by cold
reset or warm reset or no reset depending on user configuration.

## Configuration

The amd-ras-manager is configured per the
[meson build files](https://mesonbuild.com/Build-options.html). Available
options are documented in `meson_options.txt`

## Building

This project uses Meson (>=1.1.1). To build for native architecture, run:

```sh
meson setup build
ninja -C build
```
