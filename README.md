# AMD BMC RAS

The amd - bmc - ras service is intended to discover, configure and exercise OOB
RAS capabilities supported by the processors .The application creates error
records from RAS telemetry extracted from the processor over APML.

## Features

The application waits on the APML_L gpio pin to check if any events are
detected. When a fatal error is detected in the system , SMU responds to
ErrEvent by signaling ALERT_L on APML. BMC then checks for the SB-RMI RasStatus
register via APML to confirm an MCA error has caused the ALERT_L assertion. The
application collects the MCA / MSR dump via APML and creates CPER record. System
recovery is handled as per the user's preference from the config file.

## Configuration

amd-ras is configured per the
[meson build files](https://mesonbuild.com/Build-options.html). Available
options are documented in `meson_options.txt`
