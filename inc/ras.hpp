#ifndef RAS_H
#define RAS_H

#include <array>
#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <filesystem>
#include <fstream>
#include <future>
#include <gpiod.hpp>
#include <iostream>
#include <mutex>  // std::mutex
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <shared_mutex>
#include <string_view>
#include <utility>
#include <regex>
#include <ctype.h>
#include <nlohmann/json.hpp>
#include <experimental/filesystem>

extern "C" {
#include <sys/stat.h>
#include "linux/i2c-dev.h"
#include "i2c/smbus.h"
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
#include "esmi_mailbox_nda.h"
}

#define GENOA_FAMILY_ID               (0x19)
#define TURIN_FAMILY_ID               (0x1A)
#define MCA_POLLING_PERIOD            (3)
#define DRAM_CECC_POLLING_PERIOD      (5)
#define PCIE_AER_POLLING_PERIOD       (7)

#define MCA_ERR                       (0)
#define DRAM_CECC_ERR                 (1)
#define PCIE_ERR                      (2)
#define ERROR_THRESHOLD_VAL           (1)

#define PCIE_ERROR_THRESHOLD          (32)
#define DRAM_CECC_ERROR_THRESHOLD     (16)
#define MCA_ERROR_THRESHOLD           (8)
#define FATAL_ERROR                   (1)
#define APML_INIT_DONE_FILE           ("/tmp/apml_init_complete")
#define SBRMI_CONTROL_REGISTER        (0x1)

#define COMMAND_NUM_OF_CPU  ("/sbin/fw_printenv -n num_of_cpu")
#define COMMAND_LEN         (3)
#define MAX_MCA_BANKS       (32)
#define TWO_SOCKET          (2)
#define SHIFT_24            (24)
#define SHIFT_32            (32)
#define CMD_BUFF_LEN        (256)
#define BASE_16             (16)
#define MAX_RETRIES         (10)
#define RAS_STATUS_REGISTER (0x4C)
#define index_file          ("/var/lib/amd-ras/current_index")
#define config_file         ("/var/lib/amd-ras/config_file")
#define COMMAND_BOARD_ID    ("/sbin/fw_printenv -n board_id")
#define BAD_DATA            (0xBAADDA7A)
#define PCIE_VENDOR_ID      (0x1022)
#define RUNTIME_MCA_ERR     ("RUNTIME_MCA_ERROR")
#define RUNTIME_PCIE_ERR    ("RUNTIME_PCIE_ERROR")
#define RUNTIME_DRAM_ERR    ("RUNTIME_DRAM_ERROR")
#define FATAL_ERR           ("FATAL")

void RunTimeErrorPolling();
void SetOobConfig();
void write_to_cper_file(std::string);
void ErrorPollingHandler(uint8_t, uint16_t);
extern boost::asio::deadline_timer *McaErrorPollingEvent;
extern boost::asio::deadline_timer *DramCeccErrorPollingEvent;
extern boost::asio::deadline_timer *PcieAerErrorPollingEvent;

extern uint8_t p0_info;
extern uint8_t p1_info;
extern int num_of_proc;
extern bool TurinPlatform;
extern bool GenoaPlatform;

extern unsigned int board_id;
extern uint64_t RecordId;
extern uint16_t apmlRetryCount;
extern bool McaPollingEn;
extern bool PcieAerPollingEn;
extern bool DramCeccPollingEn;

extern uint16_t McaPollingPeriod;
extern uint16_t DramCeccPollingPeriod;
extern uint16_t PcieAerPollingPeriod;

extern uint32_t p0_ucode;
extern uint32_t p1_ucode;
extern uint64_t p0_ppin;
extern uint64_t p1_ppin;

extern uint32_t p0_eax , p0_ebx , p0_ecx , p0_edx;
extern uint32_t p1_eax , p1_ebx , p1_ecx , p1_edx;
extern uint32_t err_count;

constexpr std::string_view kRasDir = "/var/lib/amd-ras/";
#endif
