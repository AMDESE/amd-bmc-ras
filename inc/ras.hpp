#pragma once

#include "edk/Cper.h"
#include "generator/cper-generate.h"

#include <sys/stat.h>

#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <gpiod.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <regex>

extern "C"
{
#include "apml.h"
#include "apml_common.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

#define EFI_CPER_CREATOR_PSTORE                                                \
    {                                                                          \
        0x61fa3fac, 0xcb80, 0x4292,                                            \
        {                                                                      \
            0x8b, 0xfb, 0xd6, 0x43, 0xb1, 0xde, 0x17, 0xf4                     \
        }                                                                      \
    }

#define EFI_CPER_NOTIFY_MCE                                                    \
    {                                                                          \
        0xE8F56FFE, 0x919C, 0x4cc5,                                            \
        {                                                                      \
            0xBA, 0x88, 0x65, 0xAB, 0xE1, 0x49, 0x13, 0xBB                     \
        }                                                                      \
    }

static const int RESERVED = 0;
static const int BASE_16 = 16;
static const int TWO_SOCKET = 2;
static const int INDEX_0 = 0;
static const int INDEX_1 = 1;
static const int INDEX_2 = 2;
static const int INDEX_3 = 3;
static const int INDEX_4 = 4;
static const int INDEX_5 = 5;
static const int INDEX_6 = 6;
static const int INDEX_7 = 7;
static const int INDEX_8 = 8;
static const int INDEX_12 = 12;
static const int INDEX_16 = 16;
static const int INDEX_19 = 19;
static const int INDEX_20 = 20;
static const int BLOCK_ID_1 = 1;
static const int BLOCK_ID_2 = 2;
static const int BLOCK_ID_3 = 3;
static const int BLOCK_ID_23 = 23;
static const int BLOCK_ID_24 = 24;
static const int BLOCK_ID_33 = 33;
static const int BLOCK_ID_36 = 36;
static const int BLOCK_ID_37 = 37;
static const int BLOCK_ID_38 = 38;
static const int BLOCK_ID_39 = 39;
static const int BLOCK_ID_40 = 40;
static const int MI300A_MODEL_NUMBER = 0x90;
static const int MI300C_MODEL_NUMBER = 0x80;
static const int TURIN_FAMILY_ID = 0x1A;
static const int GENOA_FAMILY_ID = 0x19;
static const int EPYC_PROG_SEG_ID = 0x01;
static const int MI_PROG_SEG_ID = 0x02;
static const int MAX_ERROR_FILE = 10;
static const std::string RAS_DIR = "/var/lib/amd-ras/";
static const std::string INDEX_FILE = "/var/lib/amd-ras/current_index";
static const std::string CONFIG_FILE = "/var/lib/amd-ras/ras-config.json";
static const std::string SRC_CONFIG_FILE =
    "/usr/share/ras-config/ras-config.json";
static const std::string INVENTORY_SERVICE =
    "xyz.openbmc_project.Inventory.Manager";
static const std::string CPU_INVENTORY_INTERFACE =
    "xyz.openbmc_project.Inventory.Item.Cpu";
static const std::string EVENT_SUBSCRIPTION_FILE =
    "/var/lib/bmcweb/eventservice_config.json";
static const int RAS_STATUS_REGISTER = 0x4C;
static const std::string COMMAND_NUM_OF_CPU =
    "/sbin/fw_printenv -n bootdelay"; // num_of_cpu
static const std::string COMMAND_BOARD_ID = "/sbin/fw_printenv -n board_id";
static const int COMMAND_LEN = 3;
static const int SBRMI_CONTROL_REGISTER = 0x1;
static const int SYS_MGMT_CTRL_ERR = 0x04;
static const int RESET_HANG_ERR = 0x02;
static const int INT_255 = 0xFF;
static const int SOCKET_0 = 0;
static const int SOCKET_1 = 1;
static const int FATAL_ERROR = 1;
static const int MAX_MCA_BANKS = 32;
static const int CPER_RECORD_REV = 0x0100;
static const int CPER_SEV_FATAL = 1;
static const int CPER_VALID_PLATFORM_ID = 0x0001;
static const int CPER_VALID_TIMESTAMP = 0x0002;
static const int CPER_VALID_PARTITION_ID = 0x0004;
static const int CPER_MINOR_REV = 0x1;
static const std::string DBUS_SERVICE_NAME = "com.amd.RAS";
static const int ADDC_GEN_NUMBER_1 = 0x01;
static const int ADDC_GEN_NUMBER_2 = 0x02;
static const int ADDC_GEN_NUMBER_3 = 0x03;
static const int CTX_OOB_CRASH = 0x01;
static const int CPU_ID_VALID = 0x02;
static const int LOCAL_APIC_ID_VALID = 0x01;
static const int CPER_PRIMARY = 1;
static const int SHIFT_23 = 23;
static const int SHIFT_24 = 24;
static const int SHIFT_25 = 25;
static const int SHIFT_4 = 4;
static const int BYTE_4 = 4;
static const int BYTE_2 = 2;
static const int BAD_DATA = 0xBAADDA7A;
static const int FAILURE_SIGNATURE_ID = 0x04;
static const int PROC_CONTEXT_STRUCT_VALID = 0x100;

struct CpuId
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};
