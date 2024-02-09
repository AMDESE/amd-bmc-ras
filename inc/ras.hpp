#ifndef RAS_H
#define RAS_H

#include "cper.hpp"

#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <filesystem>
#include <fstream>
#include <gpiod.hpp>
#include <mutex>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

extern "C" {
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_mailbox_nda.h"
#include "esmi_rmi.h"
}

#define GENOA_FAMILY_ID (0x19)
#define TURIN_FAMILY_ID (0x1A)
#define MCA_POLLING_PERIOD (3)
#define DRAM_CECC_POLLING_PERIOD (5)
#define PCIE_AER_POLLING_PERIOD (7)

#define MCA_ERR (0)
#define DRAM_CECC_ERR (1)
#define PCIE_ERR (2)
#define POLLING_MODE (0)
#define INTERRUPT_MODE (1)
#define ERROR_THRESHOLD_VAL (1)

#define PCIE_ERROR_THRESHOLD (32)
#define DRAM_CECC_ERROR_THRESHOLD (16)
#define MCA_ERROR_THRESHOLD (8)
#define FATAL_ERROR (1)
#define MCA_ERR_OVERFLOW (8)
#define DRAM_CECC_ERR_OVERFLOW (16)
#define PCIE_ERR_OVERFLOW (32)

#define APML_INIT_DONE_FILE ("/tmp/apml_init_complete")
#define SBRMI_CONTROL_REGISTER (0x1)

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

#define COMMAND_NUM_OF_CPU ("/sbin/fw_printenv -n num_of_cpu")
#define COMMAND_LEN (3)
#define MAX_MCA_BANKS (32)
#define TWO_SOCKET (2)
#define SHIFT_24 (24)
#define SHIFT_32 (32)
#define CMD_BUFF_LEN (256)
#define BASE_16 (16)
#define MAX_RETRIES (10)
#define RAS_STATUS_REGISTER (0x4C)
#define index_file ("/var/lib/amd-ras/current_index")
#define config_file ("/var/lib/amd-ras/config_file")
#define COMMAND_BOARD_ID ("/sbin/fw_printenv -n board_id")
#define BAD_DATA (0xBAADDA7A)
#define PCIE_VENDOR_ID (0x1022)
#define RUNTIME_MCA_ERR ("RUNTIME_MCA_ERROR")
#define RUNTIME_PCIE_ERR ("RUNTIME_PCIE_ERROR")
#define RUNTIME_DRAM_ERR ("RUNTIME_DRAM_ERROR")
#define FATAL_ERR ("FATAL")

#define RETRY_45 (45)
#define SLEEP_20 (20)
#define WARM_RESET (0)
#define COLD_RESET (1)
#define NO_RESET (2)

#define MI300A_MODEL_NUMBER (0x90)
#define MI300C_MODEL_NUMBER (0x80)
#define TURIN_UMC_HW_ID (0x96)
#define MASK_11_TO_0 (0xFFF)
#define MASK_0X0F (0x0F)

#define SYS_RESET ("SYS_RST")
#define RSMRST ("RSMRST")

void RunTimeErrorPolling();
oob_status_t SetOobConfig();
oob_status_t SetErrThreshold();
void RunTimeErrorInfoCheck(uint8_t, uint8_t);
void write_to_cper_file(std::string);
void ErrorPollingHandler(uint8_t, uint16_t);
void CreateDbusInterface();

bool requestGPIOEvents(const std::string&, const std::function<void()>&,
                       gpiod::line&, boost::asio::posix::stream_descriptor&);
bool harvest_ras_errors(uint8_t, std::string);

void P0AlertEventHandler();
void P1AlertEventHandler();
void P0PmicAfEventHandler();
void P0PmicGlEventHandler();
void P1PmicAfEventHandler();
void P1PmicGlEventHandler();
void HPMFPGALockoutEventHandler();

template <typename T>
void calculate_time_stamp(const std::shared_ptr<T>&);
template <typename T>
void write_to_cper_file(const std::shared_ptr<T>&, std::string, uint16_t);
template <typename T>
void dump_cper_header_section(const std::shared_ptr<T>&, uint16_t, uint32_t,
                              std::string);
template <typename T>
void dump_error_descriptor_section(const std::shared_ptr<T>&, uint16_t,
                                   std::string, uint32_t*);
template <typename T>
void dump_proc_error_section(const std::shared_ptr<T>&, uint8_t,
                             struct ras_rt_valid_err_inst, uint8_t, uint16_t,
                             uint32_t*, uint64_t*);
template <typename T>
void dump_pcie_error_info_section(const std::shared_ptr<T>&, uint16_t,
                                  uint16_t);
template <typename T>
void dump_proc_error_info_section(const std::shared_ptr<T>&, uint8_t, uint16_t,
                                  uint64_t*, uint32_t);
void exportCrashdumpToDBus(int, const ERROR_TIME_STAMP&);
void write_register(uint8_t, uint32_t, uint32_t);

extern boost::asio::io_service io;
extern std::vector<uint8_t> BlockId;

extern gpiod::line P0_apmlAlertLine;
extern gpiod::line P1_apmlAlertLine;
extern gpiod::line P0_pmicAfAlertLine;
extern gpiod::line P0_pmicGlAlertLine;
extern gpiod::line P1_pmicAfAlertLine;
extern gpiod::line P1_pmicGlAlertLine;
extern gpiod::line HPMFPGALockoutAlertLine;

extern boost::asio::posix::stream_descriptor P0_apmlAlertEvent;
extern boost::asio::posix::stream_descriptor P1_apmlAlertEvent;
extern boost::asio::posix::stream_descriptor P0_pmicAfAlertEvent;
extern boost::asio::posix::stream_descriptor P0_pmicGlAlertEvent;
extern boost::asio::posix::stream_descriptor P1_pmicAfAlertEvent;
extern boost::asio::posix::stream_descriptor P1_pmicGlAlertEvent;
extern boost::asio::posix::stream_descriptor HPMFPGALockoutAlertEvent;

extern boost::asio::deadline_timer* McaErrorPollingEvent;
extern boost::asio::deadline_timer* DramCeccErrorPollingEvent;
extern boost::asio::deadline_timer* PcieAerErrorPollingEvent;

extern uint8_t p0_info;
extern uint8_t p1_info;
extern int num_of_proc;

extern unsigned int board_id;
extern uint64_t RecordId;

extern uint32_t p0_ucode;
extern uint32_t p1_ucode;
extern uint64_t p0_ppin;
extern uint64_t p1_ppin;

extern uint32_t p0_eax, p0_ebx, p0_ecx, p0_edx;
extern uint32_t p1_eax, p1_ebx, p1_ecx, p1_edx;
extern uint32_t err_count;
extern uint8_t ProgId;
extern uint32_t FamilyId;
extern bool apmlInitialized;
constexpr std::string_view kRasDir = "/var/lib/amd-ras/";
#endif
