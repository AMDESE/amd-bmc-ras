#pragma once

#include <sys/stat.h>

#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gpiod.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#define GENOA_MCA_BANKS (32)
#define CCM_COUNT (8)
#define MCA_BANK_MAX_OFFSET (128)
#define LAST_TRANS_ADDR_OFFSET (4)
#define DEUB_LOG_DUMP_REGION (12124)
#define CPER_SIG_SIZE (4)
#define INDEX_0 (0)
#define INDEX_1 (1)
#define INDEX_2 (2)
#define INDEX_3 (3)
#define INDEX_4 (4)
#define INDEX_5 (5)
#define INDEX_6 (6)
#define INDEX_7 (7)
#define INDEX_8 (8)
#define INDEX_12 (12)
#define INDEX_16 (16)
#define INDEX_20 (20)
#define INDEX_24 (24)
#define INDEX_60 (60)
#define RESERVE_96 (96)

#define RAS_DIR ("/var/lib/amd-ras/")
#define INDEX_FILE ("/var/lib/amd-ras/current_index")
#define CONFIG_FILE ("/var/lib/amd-ras/config_file")
#define MAX_RETRIES (10)
#define NO_RESET ("NO_RESET")
#define COLD_RESET ("COLD_RESET")
#define WARM_RESET ("WARM_RESET")
#define COMMAND_NUM_OF_CPU ("/sbin/fw_printenv -n num_of_cpu")
#define COMMAND_BOARD_ID ("/sbin/fw_printenv -n board_id")
#define INVENTORY_SERVICE ("xyz.openbmc_project.Inventory.Manager")
#define CPU_INVENTORY_INTERFACE ("xyz.openbmc_project.Inventory.Item.Cpu")
#define COMMAND_LEN (3)
#define TWO_SOCKET (2)
#define MI300A_MODEL_NUMBER (0x90)
#define MI300C_MODEL_NUMBER (0x80)
#define EPYC_PROG_SEG_ID (0x01)
#define MI_PROG_SEG_ID (0x02)
#define NAVI_PROG_SEG_ID (0x03)
#define MCA_POLLING_PERIOD (3)
#define DRAM_CECC_POLLING_PERIOD (5)
#define PCIE_AER_POLLING_PERIOD (7)
#define SYS_RESET ("SYS_RST")
#define RSMRST ("RSMRST")
#define ERROR_THRESHOLD_VAL (1)
#define READ_REGISTER ("Read")
#define WRITE_REGISTER ("Write")

#define PCIE_ERROR_THRESHOLD (32)
#define DRAM_CECC_ERROR_THRESHOLD (16)
#define MCA_ERROR_THRESHOLD (8)
#define FATAL_ERROR (1)
#define MCA_ERR_OVERFLOW (8)
#define DRAM_CECC_ERR_OVERFLOW (16)
#define PCIE_ERR_OVERFLOW (32)
#define SYS_MGMT_CTRL_ERR (0x04)
#define RESET_HANG_ERR (0x02)
#define INT_15 (0xFF)
#define BASE_16 (16)
#define RAS_STATUS_REGISTER (0x4C)

#define GENOA_FAMILY_ID (0x19)
#define TURIN_FAMILY_ID (0x1A)
#define APML_INIT_DONE_FILE ("/tmp/apml_init_complete")
#define SBRMI_CONTROL_REGISTER (0x1)
#define CPER_SIG_SIZE (4)
#define CPER_SIG_RECORD ("CPER")
#define CPER_RECORD_REV (0x0100)
#define FATAL_SECTION_COUNT (2)
#define CPER_SIG_END (0xffffffff)
#define CPER_SEV_FATAL (1)
#define CPER_VALID_PLATFORM_ID (0x0001)
#define CPER_VALID_TIMESTAMP (0x0002)
#define CPER_VALID_PARTITION_ID (0x0004)
#define RUNTIME_MCA_ERR ("RUNTIME_MCA_ERROR")
#define RUNTIME_PCIE_ERR ("RUNTIME_PCIE_ERROR")
#define RUNTIME_DRAM_ERR ("RUNTIME_DRAM_ERROR")
#define RUNTIME_MCA_BANK_MAX_OFFSET (32)
#define FATAL_ERR ("FATAL")
#define SEV_NON_FATAL_UNCORRECTED (0)
#define SEV_NON_FATAL_CORRECTED (2)
#define CPER_SEV_FATAL (1)
#define CPER_MINOR_REV (0x0006)
#define FRU_ID_VALID (0x01)
#define FRU_TEXT_VALID (0x02)
#define CPER_PRIMARY (1)
#define ADDC_GEN_NUMBER_1 (0x01)
#define ADDC_GEN_NUMBER_2 (0x02)
#define ADDC_GEN_NUMBER_3 (0x03)
#define SHIFT_4 (4)
#define SOCKET_0 (0)
#define SOCKET_1 (1)

#define BLOCK_ID_1 (1)
#define BLOCK_ID_2 (2)
#define BLOCK_ID_3 (3)
#define BLOCK_ID_24 (24)
#define BLOCK_ID_33 (33)
#define BLOCK_ID_36 (36)
#define BLOCK_ID_37 (37)
#define BLOCK_ID_38 (38)
#define BLOCK_ID_39 (39)
#define BLOCK_ID_40 (40)

enum ErrorType
{
    ERROR_TYPE_FATAL,
    ERROR_TYPE_NON_FATAL
};
