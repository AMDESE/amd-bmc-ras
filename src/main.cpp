// amd-bmc-ras main.cpp file
// NOTE: Socket = processor in this script. Terms will be used interchangeably

#include <array>
#include "boost/asio.hpp"
#include "boost/asio/error.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/posix/stream_descriptor.hpp"
#include "boost/asio/spawn.hpp"
#include "boost/asio/steady_timer.hpp"
#include "boost/container/flat_map.hpp"
#include "boost/container/flat_set.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "cper.hpp"
#include <ctype.h>
#include <experimental/filesystem>
#include <filesystem>
#include <fstream>
#include <future>
#include "gpiod.hpp"
#include <inttypes.h>
#include <iostream>
#include <mutex>  // std::mutex
#include "nlohmann/json.hpp"
#include <regex>
#include <shared_mutex>
#include <string_view>
#include <syslog.h>
#include <stdarg.h>
#include <utility>

extern "C" {
#include <sys/stat.h>
#include "linux/i2c-dev.h"
#include "i2c/smbus.h"
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_mailbox_nda.h"
#include "esmi_rmi.h"
}
}

#define COMMAND_NUM_OF_CPU  ("/sbin/fw_printenv -n num_of_cpu")
#define COMMAND_LEN         (3)
#define MAX_MCA_BANKS       (32)
#define TWO_SOCKET          (2)
#define FOUR_SOCKET         (4)
#define SHIFT_24            (24)
#define SHIFT_32            (32)
#define CMD_BUFF_LEN        (256)
#define BASE_16             (16)

#define WARM_RESET          (0)
#define COLD_RESET          (1)
#define NO_RESET            (2)

#define MAX_RETRIES 10
#define RAS_STATUS_REGISTER (0x4C)
#define index_file  ("/rwfs/amd-ras-files/current_index")
#define config_file ("/rwfs/amd-ras-files/config_file")
#define BAD_DATA    (0xBAADDA7A)

static boost::asio::io_service io;

constexpr std::string_view kRasDir = "/rwfs/amd-ras-files/";
constexpr int kCrashdumpTimeInSec = 300;

static std::string BoardName;
static uint32_t err_count = 0;

static gpiod::line P0_apmlAlertLine;
static boost::asio::posix::stream_descriptor P0_apmlAlertEvent(io);

static gpiod::line P1_apmlAlertLine;
static boost::asio::posix::stream_descriptor P1_apmlAlertEvent(io);

static gpiod::line P2_apmlAlertLine;
static boost::asio::posix::stream_descriptor P2_apmlAlertEvent(io);

static gpiod::line P3_apmlAlertLine;
static boost::asio::posix::stream_descriptor P3_apmlAlertEvent(io);

static gpiod::line HPMFPGALockoutAlertLine;
static boost::asio::posix::stream_descriptor HPMFPGALockoutAlertEvent(io);

// Declare and init socket ID variables
uint8_t p0_info = 0;
uint8_t p1_info = 1;
uint8_t p2_info = 2;
uint8_t p3_info = 3;

// Declare and init number of sockets on CPU
// Value will be updated later
static int num_of_proc = 0;

const static constexpr int resetPulseTimeMs = 100;

std::mutex harvest_in_progress_mtx;           // mutex for critical section

// Declare and init flag for processing socket alert
static bool P0_AlertProcessed = false;
static bool P1_AlertProcessed = false;
static bool P2_AlertProcessed = false;
static bool P3_AlertProcessed = false;

static uint64_t RecordId = 1;
unsigned int board_id = 0;

// Declare CPUID variables for each socket
static uint32_t p0_eax , p0_ebx , p0_ecx , p0_edx;
static uint32_t p1_eax , p1_ebx , p1_ecx , p1_edx;
static uint32_t p2_eax , p2_ebx , p2_ecx , p2_edx;
static uint32_t p3_eax , p3_ebx , p3_ecx , p3_edx;

// Declare and init microcode variables for each socket
// Value will be updated later
uint32_t p0_ucode = 0;
uint32_t p1_ucode = 0;
uint32_t p2_ucode = 0;
uint32_t p3_ucode = 0;

// Declare and init fuse/ppin variables for each socket
// Value will be updated later
uint64_t p0_ppin = 0;
uint64_t p1_ppin = 0;
uint64_t p2_ppin = 0;
uint64_t p3_ppin = 0;

std::shared_ptr<CPER_RECORD> rcd;

// Declare and init last transaction address variable for each socket
// Value will be updated later
uint64_t p0_last_transact_addr = 0;
uint64_t p1_last_transact_addr = 0;
uint64_t p2_last_transact_addr = 0;
uint64_t p3_last_transact_addr = 0;

// Declare harvest_ras_errors function
bool harvest_ras_errors(uint8_t info,std::string alert_name);

// Declare init_apml_mce_event function
void init_apml_mce_event(apml_mce_event* event_ptr, uint32_t mca_synd_lo, uint32_t mca_synd_hi, 
							uint32_t mca_ipid_lo, uint32_t mca_ipid_hi, uint32_t mca_status_lo, 
							uint32_t mca_status_hi, uint32_t mca_addr_lo, uint32_t mca_addr_hi, 
							uint32_t mca_misc_lo, uint32_t mca_misc_hi, uint8_t socketid_data);
							
uint16_t apmlRetryCount;
uint16_t systemRecovery;
bool harvestuCodeVersionFlag = false;
bool harvestPpinFlag = false;

// Declare MCA register value variables
uint32_t mca_status_lo = 0;
uint32_t mca_status_hi = 0;
uint32_t mca_ipid_lo = 0;
uint32_t mca_ipid_hi = 0;
uint32_t mca_synd_lo = 0;
uint32_t mca_synd_hi = 0;
uint32_t mca_addr_lo = 0;
uint32_t mca_addr_hi = 0;
uint32_t mca_misc_lo = 0;
uint32_t mca_misc_hi = 0;

// Declare MCA register offset variables
int synd_lo_offset = 0;
int synd_hi_offset = 0;
int ipid_lo_offset = 0;
int ipid_hi_offset = 0;
int status_lo_offset = 0;
int status_hi_offset = 0;
int addr_lo_offset = 0;
int addr_hi_offset = 0;
int misc_lo_offset = 0;
int misc_hi_offset = 0;

// Declare and init flag for valid RAS error
bool ValidSignatureID = false;

// Array containing offsets of MCA registers
// Index[0] = synd_low
// Index[1] = synd_high
// Index[2] = ipid_low
// Index[3] = ipid_high
// Index[4] = status_low
// Index[5] = status_high
// Index[8] = addr_low
// Index[9] = addr_high
// Index[10] = misc_low
// Index[11] = misc_high
std::vector<std::string> sigIDOffset = {"0x30","0x34","0x28","0x2c","0x08","0x0c","null","null","0x10","0x14","0x18","0x1c"};

// Opens connection to the system logger
void initialize_syslog(const char *program_name) {
    openlog(program_name, LOG_PID | LOG_CONS, LOG_USER);
}

// Info logging function
void log_info(const char *format, ...) {
    va_list arg;
    va_start(arg, format);
    vsyslog(LOG_INFO, format, arg);
    va_end(arg);
}

// Warning logging function
void log_warning(const char *format, ...) {
    va_list arg;
    va_start(arg, format);
    vsyslog(LOG_WARNING, format, arg);
    va_end(arg);
}

// Error logging function
void log_error(const char *format, ...) {
    va_list arg;
    va_start(arg, format);
    vsyslog(LOG_ERR, format, arg);
    va_end(arg);
}

// Closes connection to the system logger
void close_syslog() {
    closelog();
}

// Gets number of CPUs
bool getNumberOfCpu()
{
    num_of_proc = 4;
    log_warning("Number of Cpus: %d\n", num_of_proc);
    return true;
}

// Get CPUID using APML library
// Output = Assigns CPUID value to static variables p#_eax, p#_ebx, p#_ecx, p#_edx
// p#_eax, p#_ebx, p#_ecx, p#_edx variables declared at start of script
void getCpuID()
{
    uint32_t core_id = 0;
    oob_status_t ret;
    p0_eax = 1;
    p0_ebx = 0;
    p0_ecx = 0;
    p0_edx = 0;

	// Get CPUID for socket 0
    log_info("Checking P0");
    ret = esmi_oob_cpuid(p0_info, core_id,
                 &p0_eax, &p0_ebx, &p0_ecx, &p0_edx);

	// Check if error getting CPUID for socket 0
    if(ret)
    {
        log_error("Failed to get the CPUID for socket 0");
    }

	// Check if 2 socket CPU
    if(num_of_proc == TWO_SOCKET)
    {
        log_info("Checking P1");
        p1_eax = 1;
        p1_ebx = 0;
        p1_ecx = 0;
        p1_edx = 0;

		// Get CPUID for socket 1
        ret = esmi_oob_cpuid(p1_info, core_id,
                 &p1_eax, &p1_ebx, &p1_ecx, &p1_edx);

		// Check if error getting CPUID for socket 1
        if(ret)
        {
            log_error("Failed to get the CPUID for socket 1");
        }
	
	// Check if 4 socket CPU
    } else if(num_of_proc == FOUR_SOCKET)
    {
        p1_eax = 1;
        p1_ebx = 0;
        p1_ecx = 0;
        p1_edx = 0;

		// Get CPUID for socket 1
        log_info("Checking P1");
        ret = esmi_oob_cpuid(p1_info, core_id,
                 &p1_eax, &p1_ebx, &p1_ecx, &p1_edx);

		// Check if error getting CPUID for socket 1
        if(ret)
        {
            log_error("Failed to get the CPUID for socket 1");
        }

        p2_eax = 1;
        p2_ebx = 0;
        p2_ecx = 0;
        p2_edx = 0;

		// Get CPUID for socket 2
        log_info("Checking P2");
        ret = esmi_oob_cpuid(p2_info, core_id,
                 &p2_eax, &p2_ebx, &p2_ecx, &p2_edx);

		// Check if error getting CPUID for socket 2
        if(ret)
        {
            log_error("Failed to get the CPUID for socket 2");
        }

        p3_eax = 1;
        p3_ebx = 0;
        p3_ecx = 0;
        p3_edx = 0;

		// Get CPUID for socket 3
        log_info("Checking P3");
        ret = esmi_oob_cpuid(p3_info, core_id,
                 &p3_eax, &p3_ebx, &p3_ecx, &p3_edx);

		// Check if error getting CPUID for socket 3
        if(ret)
        {
            log_error("Failed to get the CPUID for socket 3");
        }

    }

}

template <typename T> void updateConfigFile(std::string jsonField, T updateData)
{
    std::ifstream jsonRead(config_file);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    data[jsonField] = updateData;

    std::ofstream jsonWrite(config_file);
    jsonWrite << data;

    jsonRead.close();
    jsonWrite.close();
}

// Update microcode revision for each socket
void getMicrocodeRev(){
    oob_status_t ret;
    ret = read_ucode_revision(0,&p0_ucode);
    if(ret!=0){
        log_error("Failed to read ucode revision for Processor P0");
    }
    else{
        log_warning("ucode revision for Processor P0: %" PRIu32, p0_ucode);
    }
    if(num_of_proc == TWO_SOCKET){
        ret = read_ucode_revision(1,&p1_ucode);
        if(ret!=0){
            log_error("Failed to read ucode revision for Processor P1");
        }
        else{
            log_warning("ucode revision for Processor P1: %" PRIu32, p1_ucode);
        }
    }
    else if(num_of_proc == FOUR_SOCKET){
        ret = read_ucode_revision(1,&p1_ucode);
        if(ret!=0){
            log_error("Failed to read ucode revision for Processor P1");
        }
        else{
            log_warning("ucode revision for Processor P1: %" PRIu32, p1_ucode);
        }
        ret = read_ucode_revision(2,&p2_ucode);
        if(ret!=0){
            log_error("Failed to read ucode revision for Processor P2");
        }
        else{
            log_warning("ucode revision for Processor P2: %" PRIu32, p2_ucode);
        }
        ret = read_ucode_revision(3,&p3_ucode);
        if(ret!=0){
            log_error("Failed to read ucode revision for Processor P3");
        }
        else{
            log_warning("ucode revision for Processor P3: %" PRIu32, p3_ucode);
        }
    }
}

// Get fuse/ppin for each socket
void getPpinFuse(){
    oob_status_t ret;
    ret = read_ppin_fuse(0,&p0_ppin);
    if(ret!=0){
        log_error("Failed to read PPIN for Processor P0");
    }
    else{
        log_warning("PPIN for Processor P0: %" PRIu64, p0_ppin);
    }
    if(num_of_proc == TWO_SOCKET){
        ret = read_ppin_fuse(1,&p1_ppin);
        if(ret!=0){
            log_error("Failed to read PPIN for Processor P1");
        }
        else{
            log_warning("PPIN for Processor P1: %" PRIu64, p1_ppin);
        }
    }
    else if(num_of_proc == FOUR_SOCKET){
        ret = read_ppin_fuse(1,&p1_ppin);
        if(ret!=0){
            log_error("Failed to read PPIN for Processor P1");
        }
        else{
            log_warning("PPIN for Processor P1: %" PRIu64, p1_ppin);
        }
        ret = read_ppin_fuse(2,&p2_ppin);
        if(ret!=0){
            log_error("Failed to read PPIN for Processor P2");
        }
        else{
            log_warning("PPIN for Processor P2: %" PRIu64, p2_ppin);
        }
        ret = read_ppin_fuse(3,&p3_ppin);
        if(ret!=0){
            log_error("Failed to read PPIN for Processor P3");
        }
        else{
            log_warning("PPIN for Processor P3: %" PRIu64, p3_ppin);
        }
    }
}

void getLastTransAddr(uint8_t info)
{
    oob_status_t ret;
    uint8_t blk_id = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    ret = read_ras_df_err_validity_check(info, blk_id, &err_chk);

    if (ret)
    {
        log_error("Failed to read RAS DF validity check");
    }
    else
    {
        if(err_chk.df_block_instances != 0)
        {
            maxOffset32 = ((err_chk.err_log_len % BYTE_4) ? INDEX_1 : INDEX_0) + (err_chk.err_log_len >> BYTE_2);
            while(n < err_chk.df_block_instances)
            {
                for (int offset = 0; offset < maxOffset32; offset++)
                {
                    memset(&data, 0, sizeof(data));
                    /* Offset */
                    df_err.input[INDEX_0] = offset * BYTE_4;
                    /* DF block ID */
                    df_err.input[INDEX_1] = blk_id;
                    /* DF block ID instance */
                    df_err.input[INDEX_2] = n;

                    ret = read_ras_df_err_dump(info, df_err, &data);

                    if(info == p0_info) {
                        rcd->P0_ErrorRecord.ContextInfo.DfDumpData.LastTransAddr[n].WdtData[offset] = data;
                    } else if(info == p1_info) {
                        rcd->P1_ErrorRecord.ContextInfo.DfDumpData.LastTransAddr[n].WdtData[offset] = data;
                    } else if(info == p2_info) {
                        rcd->P2_ErrorRecord.ContextInfo.DfDumpData.LastTransAddr[n].WdtData[offset] = data;
                    } else if(info == p3_info) {
                        rcd->P3_ErrorRecord.ContextInfo.DfDumpData.LastTransAddr[n].WdtData[offset] = data;
                    }
                }
                n++;
            }
        }
    }
}

void harvestPcieDump(uint8_t info)
{
    oob_status_t ret;
    uint8_t blk_id = BLOCK_ID_33;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    log_info("Harvesting PCIE dump");

    ret = read_ras_df_err_validity_check(info, blk_id, &err_chk);

    if (ret)
    {
        log_error("Failed to read Pcie dump validity check P%d", info);

        /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE dump region*/
        if(info == p0_info)
        {
            rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.BlockID = (BAD_DATA & INT_255);
            rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance = (BAD_DATA >> INDEX_8) & INT_255;
            rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = (BAD_DATA >> INDEX_16) & TWO_BYTE_MASK;
            rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_0] = BAD_DATA;
            rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_1] = BAD_DATA;
        }
        else if(info == p1_info)
        {
            rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.BlockID = (BAD_DATA & INT_255);
            rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance = (BAD_DATA >> INDEX_8) & INT_255;
            rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = (BAD_DATA >> INDEX_16) & TWO_BYTE_MASK;
            rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_0] = BAD_DATA;
            rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_1] = BAD_DATA;
        }else if(info == p2_info)
        {
            rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.BlockID = (BAD_DATA & INT_255);
            rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance = (BAD_DATA >> INDEX_8) & INT_255;
            rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = (BAD_DATA >> INDEX_16) & TWO_BYTE_MASK;
            rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_0] = BAD_DATA;
            rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_1] = BAD_DATA;
        }else if(info == p3_info)
        {
            rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.BlockID = (BAD_DATA & INT_255);
            rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance = (BAD_DATA >> INDEX_8) & INT_255;
            rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = (BAD_DATA >> INDEX_16) & TWO_BYTE_MASK;
            rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_0] = BAD_DATA;
            rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[INDEX_0].PcieData[INDEX_1] = BAD_DATA;
        }
    }
    else
    {
        if(err_chk.df_block_instances != 0)
        {
            if(info == p0_info)
            {
                rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.BlockID = blk_id;
                rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance =
                                                         err_chk.df_block_instances;
                rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = err_chk.err_log_len;
            }
            else if(info == p1_info)
            {
                rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.BlockID = blk_id;
                rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance =
                                                             err_chk.df_block_instances;
                rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = err_chk.err_log_len;
            }
            else if(info == p2_info)
            {
                rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.BlockID = blk_id;
                rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance =
                                                             err_chk.df_block_instances;
                rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = err_chk.err_log_len;
            }
            else if(info == p3_info)
            {
                rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.BlockID = blk_id;
                rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.ValidLogInstance =
                                                             err_chk.df_block_instances;
                rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.LogInstanceSize = err_chk.err_log_len;
            }

            maxOffset32 = ((err_chk.err_log_len % BYTE_4) ? INDEX_1 : INDEX_0) + (err_chk.err_log_len >> BYTE_2);

            while(n < err_chk.df_block_instances)
            {
                for (int offset = 0; offset < maxOffset32; offset++)
                {
                    memset(&data, 0, sizeof(data));
                    /* Offset */
                    df_err.input[INDEX_0] = offset * BYTE_4;
                    /* DF block ID */
                    df_err.input[INDEX_1] = blk_id;
                    /* DF block ID instance */
                    df_err.input[INDEX_2] = n;

                    ret = read_ras_df_err_dump(info, df_err, &data);

                    if (ret != OOB_SUCCESS)
                    {
                        log_error("Failed to read Pcie dump data");
                        data = BAD_DATA;
                    }

                    if(info == p0_info) {
                        rcd->P0_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[n].PcieData[offset] = data;
                    } else if(info == p1_info) {
                        rcd->P1_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[n].PcieData[offset] = data;
                    } else if(info == p2_info) {
                        rcd->P2_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[n].PcieData[offset] = data;
                    } else if(info == p3_info) {
                        rcd->P3_ErrorRecord.ContextInfo.PcieDumpData.PcieDump[n].PcieData[offset] = data;
                    }
                }
                n++;
            }
        }
    }
}

void triggerColdReset(){
    log_info("Need to be implemented using YAAPD/GPIO. Manual reboot of the OS is needed.");
}

inline std::string getCperFilename(int num) {
    return "ras-error" + std::to_string(num) + ".cper";
}

static bool requestGPIOEvents(
    const std::string& name, const std::function<void()>& handler,
    gpiod::line& gpioLine,
    boost::asio::posix::stream_descriptor& gpioEventDescriptor)
{
    // Find the GPIO line
    gpioLine = gpiod::find_line(name);
    if (!gpioLine)
    {
        log_error("Failed to find gpio line %s", name.c_str());
        return false;
    }

    try
    {
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES});
    }
    catch (std::exception& exc)
    {
        log_error("Failed to request events for gpio line %s, exception: %s", name.c_str(), exc.what());
        return false;
    }

    int gpioLineFd = gpioLine.event_get_fd();
    if (gpioLineFd < 0)
    {
        log_error("Failed to get gpio line %s fd", name.c_str());
        return false;
    }

    gpioEventDescriptor.assign(gpioLineFd);

    gpioEventDescriptor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [&name, handler](const boost::system::error_code ec) {
            if (ec)
            {
                log_error("fd handler error: %s", ec.message().c_str());
                // TODO: throw here to force power-control to restart?
                return;
            }
            handler();
        });

    return true;
}

static bool setGPIOOutput(const std::string& name, const int value,
                          gpiod::line& gpioLine)
{
    // Find the GPIO line
    gpioLine = gpiod::find_line(name);
    if (!gpioLine)
    {
        log_error("Failed to find gpio line %s", name.c_str());
        return false;
    }

    try
    {
        gpioLine.request({__FUNCTION__, gpiod::line_request::DIRECTION_OUTPUT});
    }
    catch (std::system_error& exc)
    {
        log_error("Error setting gpio as Output: %s, exception: %s", name.c_str(), exc.what());
    }

    try
    {
        // Request GPIO output to specified value
        gpioLine.set_value(value);
    }
    catch (std::exception& exc)
    {
        log_error("Failed to set value for %s, exception: %s", name.c_str(), exc.what());
        return false;
    }

    log_warning("%s set to %d", name.c_str(), value);

    return true;
}

static int setGPIOValue(const std::string& name, const int value,
                              const int durationMs)
{
    // No mask set, so request and set the GPIO normally
    gpiod::line gpioLine;
    if (!setGPIOOutput(name, value, gpioLine))
    {
        return -1;
    }
    usleep(durationMs * 1000);
    gpioLine.set_value(!value);
    return 0;
}


/* Schedule a wait event */
static void P0AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        log_warning("Falling Edge: P0 APML Alert received");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p0_info, "P0_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        log_warning("Rising Edge: P0 APML Alert cancelled");
    }

    P0_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            log_error("P0 APML alert handler error: %s", ec.message().c_str());
            return;
        }
        P0AlertEventHandler();
    });
}

static void P1AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        log_warning("Falling Edge: P1 APML Alert received");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p1_info, "P1_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        log_warning("Rising Edge: P1 APML Alert cancelled");
    }
    P1_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            log_error("P1 APML alert handler error: %s", ec.message().c_str());
            return;
        }
        P1AlertEventHandler();
    });
}

static void P2AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P2_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        log_warning("Falling Edge: P2 APML Alert received");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p1_info, "P2_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        log_warning("Rising Edge: P2 APML Alert cancelled");
    }
    P2_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            log_error("P2 APML alert handler error: %s", ec.message().c_str());
            return;
        }
        P2AlertEventHandler();
    });
}

static void P3AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P3_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        log_warning("Falling Edge: P3 APML Alert received");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p1_info, "P3_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        log_warning("Rising Edge: P3 APML Alert cancelled");
    }
    P3_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            log_error("P3 APML alert handler error: %s", ec.message().c_str());
            return;
        }
        P3AlertEventHandler();
    });
}

static void HPMFPGALockoutEventHandler()
{
    gpiod::line_event gpioLineEvent = HPMFPGALockoutAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "HPM FPGA detected fatal error."
                                  "FPGA registers dump to /rwfs/amd-ras-files/amd-ras/fpga_dump.txt in openbmc"
                                  "A/C power cycle to recover";
        log_warning("Rising Edge: HPM FPGA lockout Alert received");
        log_error("%s", ras_err_msg.c_str());
        //system("HPM_FPGA_REGDUMP > " HPM_FPGA_REGDUMP_FILE " 2>&1 &");
    }

    HPMFPGALockoutAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            log_error("HPM FPGA lockout alert handler error: %s", ec.message().c_str());
            return;
        }
        HPMFPGALockoutEventHandler();
    });
}

static void write_register(uint8_t info, uint32_t reg, uint32_t value)
{
    oob_status_t ret;

    ret = esmi_oob_write_byte(info, reg, SBRMI, value);
    if (ret != OOB_SUCCESS) {
        log_error("Failed to write register: 0x%x", reg);
        return;
    }
    log_warning("Write to register 0x%x is successful", reg);
}

void calculate_time_stamp()
{
    using namespace std;
    using namespace std::chrono;
    typedef duration<int, ratio_multiply<hours::period, ratio<24> >::type> days;

    system_clock::time_point now = system_clock::now();
    system_clock::duration tp = now.time_since_epoch();

    days d = duration_cast<days>(tp);
    tp -= d;
    hours h = duration_cast<hours>(tp);
    tp -= h;
    minutes m = duration_cast<minutes>(tp);
    tp -= m;
    seconds s = duration_cast<seconds>(tp);
    tp -= s;

    time_t tt = system_clock::to_time_t(now);
    tm utc_tm = *gmtime(&tt);

    rcd->Header.TimeStamp.Seconds = utc_tm.tm_sec;
    rcd->Header.TimeStamp.Minutes = utc_tm.tm_min;
    rcd->Header.TimeStamp.Hours = utc_tm.tm_hour;
    rcd->Header.TimeStamp.Flag = 1;
    rcd->Header.TimeStamp.Day = utc_tm.tm_mday;
    rcd->Header.TimeStamp.Month = utc_tm.tm_mon + 1;
    rcd->Header.TimeStamp.Year = utc_tm.tm_year;
    rcd->Header.TimeStamp.Century = 20 + utc_tm.tm_year/100;
    rcd->Header.TimeStamp.Year = rcd->Header.TimeStamp.Year % 100;
}

void dump_cper_header_section(uint16_t numbanks, uint16_t bytespermca)
{
    memcpy(rcd->Header.Signature, CPER_SIG_RECORD, CPER_SIG_SIZE);
    rcd->Header.Revision = CPER_RECORD_REV;
    rcd->Header.SignatureEnd = CPER_SIG_END;
    rcd->Header.SectionCount = SECTION_COUNT;
    rcd->Header.ErrorSeverity = CPER_SEV_FATAL;

    /*Bit 0 = 1 -> PlatformID field contains valid info
      Bit 1 = 1 -> TimeStamp field contains valid info
      Bit 2 = 1 -> PartitionID field contains valid info*/

    rcd->Header.ValidationBits = (CPER_VALID_PLATFORM_ID | CPER_VALID_TIMESTAMP);

    rcd->Header.RecordLength = sizeof(CPER_RECORD);

    calculate_time_stamp();

    rcd->Header.PlatformId[INDEX_0] = board_id;

    rcd->Header.CreatorId = CPER_CREATOR_PSTORE;
    rcd->Header.NotifyType = CPER_NOTIFY_MCE;

    if(rcd->Header.RecordId != RSVD)
        rcd->Header.RecordId = RecordId++;
}

void dump_error_descriptor_section(uint16_t numbanks, uint16_t bytespermca,uint8_t info)
{

    rcd->SectionDescriptor[INDEX_0].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                              (INDEX_4 * sizeof(ERROR_SECTION_DESCRIPTOR));
    rcd->SectionDescriptor[INDEX_0].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_0].RevisionMinor = CPER_MINOR_REV;
    rcd->SectionDescriptor[INDEX_0].RevisionMajor = ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | MI_PROG_SEG_ID;
    rcd->SectionDescriptor[INDEX_0].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[INDEX_0].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[INDEX_0].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[INDEX_0].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[INDEX_0].FRUText[INDEX_0] = 'P';
    rcd->SectionDescriptor[INDEX_0].FRUText[INDEX_1] = '0';


    rcd->SectionDescriptor[INDEX_1].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                             (INDEX_4 * sizeof(ERROR_SECTION_DESCRIPTOR)) + sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_1].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_1].RevisionMinor = CPER_MINOR_REV;
    rcd->SectionDescriptor[INDEX_1].RevisionMajor = ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | MI_PROG_SEG_ID;
    rcd->SectionDescriptor[INDEX_1].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[INDEX_1].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[INDEX_1].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[INDEX_1].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[INDEX_1].FRUText[INDEX_0] = 'P';
    rcd->SectionDescriptor[INDEX_1].FRUText[INDEX_1] = '1';

    rcd->SectionDescriptor[INDEX_2].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                             (INDEX_4 * sizeof(ERROR_SECTION_DESCRIPTOR)) + sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_2].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_2].RevisionMinor = CPER_MINOR_REV;
    rcd->SectionDescriptor[INDEX_2].RevisionMajor = ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | MI_PROG_SEG_ID;
    rcd->SectionDescriptor[INDEX_2].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[INDEX_2].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[INDEX_2].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[INDEX_2].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[INDEX_2].FRUText[INDEX_0] = 'P';
    rcd->SectionDescriptor[INDEX_2].FRUText[INDEX_1] = '2';

    rcd->SectionDescriptor[INDEX_3].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                             (INDEX_4 * sizeof(ERROR_SECTION_DESCRIPTOR)) + sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_3].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[INDEX_3].RevisionMinor = CPER_MINOR_REV;
    rcd->SectionDescriptor[INDEX_3].RevisionMajor = ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | MI_PROG_SEG_ID;
    rcd->SectionDescriptor[INDEX_3].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[INDEX_3].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[INDEX_3].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[INDEX_3].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[INDEX_3].FRUText[INDEX_0] = 'P';
    rcd->SectionDescriptor[INDEX_3].FRUText[INDEX_1] = '3';
}

void dump_processor_error_section(uint8_t info)
{

    rcd->P0_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_0] = p0_eax;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_1] = p0_ebx;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_2] = p0_ecx;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_3] = p0_edx;
    rcd->P0_ErrorRecord.ProcError.CPUAPICId = ((p0_ebx >> SHIFT_24) & INT_255);

    if(num_of_proc == TWO_SOCKET)
    {
        rcd->P1_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_0] = p1_eax;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_1] = p1_ebx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_2] = p1_ecx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_3] = p1_edx;
        rcd->P1_ErrorRecord.ProcError.CPUAPICId = ((p1_ebx >> SHIFT_24) & INT_255);
    } else if(num_of_proc == FOUR_SOCKET)
    {
        rcd->P1_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_0] = p1_eax;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_1] = p1_ebx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_2] = p1_ecx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_3] = p1_edx;
        rcd->P1_ErrorRecord.ProcError.CPUAPICId = ((p1_ebx >> SHIFT_24) & INT_255);

        rcd->P2_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P2_ErrorRecord.ProcError.CpuId[INDEX_0] = p2_eax;
        rcd->P2_ErrorRecord.ProcError.CpuId[INDEX_1] = p2_ebx;
        rcd->P2_ErrorRecord.ProcError.CpuId[INDEX_2] = p2_ecx;
        rcd->P2_ErrorRecord.ProcError.CpuId[INDEX_3] = p2_edx;
        rcd->P2_ErrorRecord.ProcError.CPUAPICId = ((p2_ebx >> SHIFT_24) & INT_255);

        rcd->P3_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P3_ErrorRecord.ProcError.CpuId[INDEX_0] = p3_eax;
        rcd->P3_ErrorRecord.ProcError.CpuId[INDEX_1] = p3_ebx;
        rcd->P3_ErrorRecord.ProcError.CpuId[INDEX_2] = p3_ecx;
        rcd->P3_ErrorRecord.ProcError.CpuId[INDEX_3] = p3_edx;
        rcd->P3_ErrorRecord.ProcError.CPUAPICId = ((p3_ebx >> SHIFT_24) & INT_255);
    }

   if(info == p0_info)
   {
       rcd->P0_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
   if(info == p1_info)
   {
       rcd->P1_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
   if(info == p2_info)
   {
       rcd->P2_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
   if(info == p3_info)
   {
       rcd->P3_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
}

void dump_context_info(uint16_t numbanks,uint16_t bytespermca,uint8_t info)
{
    getLastTransAddr(p0_info);
    harvestPcieDump(p0_info);

    if(num_of_proc == TWO_SOCKET)
    {
        getLastTransAddr(p1_info);
        harvestPcieDump(p1_info);
    } else if(num_of_proc == FOUR_SOCKET)
    {
        getLastTransAddr(p1_info);
        harvestPcieDump(p1_info);
        getLastTransAddr(p2_info);
        harvestPcieDump(p2_info);
        getLastTransAddr(p3_info);
        harvestPcieDump(p3_info);
    }

    if(info == p0_info)
    {
        rcd->P0_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P0_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
    }
    else if(info == p1_info)
    {
        rcd->P1_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P1_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
    }
    else if(info == p2_info)
    {
        rcd->P2_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P2_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
    }
    else if(info == p3_info)
    {
        rcd->P3_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P3_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
    }

    rcd->P0_ErrorRecord.ContextInfo.MicrocodeVersion = p0_ucode;
    rcd->P0_ErrorRecord.ContextInfo.Ppin = p0_ppin;

    if(num_of_proc == TWO_SOCKET)
    {
        rcd->P1_ErrorRecord.ContextInfo.MicrocodeVersion = p1_ucode;
        rcd->P1_ErrorRecord.ContextInfo.Ppin = p1_ppin;
    } else if(num_of_proc == FOUR_SOCKET)
    {
        rcd->P1_ErrorRecord.ContextInfo.MicrocodeVersion = p1_ucode;
        rcd->P1_ErrorRecord.ContextInfo.Ppin = p1_ppin;

        rcd->P2_ErrorRecord.ContextInfo.MicrocodeVersion = p2_ucode;
        rcd->P2_ErrorRecord.ContextInfo.Ppin = p2_ppin;

        rcd->P3_ErrorRecord.ContextInfo.MicrocodeVersion = p3_ucode;
        rcd->P3_ErrorRecord.ContextInfo.Ppin = p3_ppin;
    }
}

static bool harvest_mca_data_banks(uint8_t info, uint16_t numbanks, uint16_t bytespermca)
{
    FILE *file;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
	int ret_error_summary;

    dump_cper_header_section(numbanks,bytespermca);

    dump_error_descriptor_section(numbanks,bytespermca,info);

    dump_processor_error_section(info);

    dump_context_info(numbanks,bytespermca,info);
	
	// Create struct apml_mce_event object and pointer
	apml_mce_event event;
	apml_mce_event* event_ptr = &event;

	// Initialize MCA register offsets
    synd_lo_offset = std::stoul(sigIDOffset[INDEX_0], nullptr, BASE_16);
    synd_hi_offset = std::stoul(sigIDOffset[INDEX_1], nullptr, BASE_16);
    ipid_lo_offset = std::stoul(sigIDOffset[INDEX_2], nullptr, BASE_16);
    ipid_hi_offset = std::stoul(sigIDOffset[INDEX_3], nullptr, BASE_16);
    status_lo_offset = std::stoul(sigIDOffset[INDEX_4], nullptr, BASE_16);
    status_hi_offset = std::stoul(sigIDOffset[INDEX_5], nullptr, BASE_16);
    addr_lo_offset = std::stoul(sigIDOffset[INDEX_8], nullptr, BASE_16);
    addr_hi_offset = std::stoul(sigIDOffset[INDEX_9], nullptr, BASE_16);
    misc_lo_offset = std::stoul(sigIDOffset[INDEX_10], nullptr, BASE_16);
    misc_hi_offset = std::stoul(sigIDOffset[INDEX_11], nullptr, BASE_16);
    maxOffset32 = ((bytespermca % BYTE_4) ? INDEX_1 : INDEX_0) + (bytespermca >> BYTE_2);
    log_info("Number of Valid MCA bank:%d\n", numbanks);
    log_info("Number of 32 Bit Words:%d\n", maxOffset32);

    while(n < numbanks)
    {
        for (int offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&mca_dump, 0, sizeof(mca_dump));
            mca_dump.index  = n;
            mca_dump.offset = offset * BYTE_4;

            ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

            if (ret != OOB_SUCCESS)
            {
                // retry
                uint16_t retryCount = apmlRetryCount;
                while(retryCount > 0)
                {
                    memset(&buffer, 0, sizeof(buffer));
                    memset(&mca_dump, 0, sizeof(mca_dump));
                    mca_dump.index  = n;
                    mca_dump.offset = offset * BYTE_4;

                    ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    retryCount--;
                    usleep(1000 * 1000);

                }
                if (ret != OOB_SUCCESS)
                {
                    log_error("Socket %d : Failed to get MCA bank data from Bank:%d, Offset:0x%x", info, n, offset);
                    if(info == p0_info) {
                        rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    } else if(info == p1_info) {
                       rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    } else if(info == p2_info) {
                       rcd->P2_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    } else if(info == p3_info) {
                       rcd->P3_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    }
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            if(info == p0_info) {
                rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            } else if(info == p1_info) {
                rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            } else if(info == p2_info) {
                rcd->P2_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            } else if(info == p3_info) {
                rcd->P3_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            }

            if(mca_dump.offset == status_lo_offset)
            {
                mca_status_lo = buffer;
            }
            if(mca_dump.offset == status_hi_offset)
            {
                mca_status_hi = buffer;

                /*Bit 23 and bit 25 of MCA_STATUS_HI
                  should be set for a valid signature ID*/
                if ((mca_status_hi & (INDEX_1 << SHIFT_25)) && (mca_status_hi & (INDEX_1 << SHIFT_23)))
                {
                    ValidSignatureID = true;
                }
            }
            if(mca_dump.offset == ipid_lo_offset)
            {
                mca_ipid_lo = buffer;
            }
            if(mca_dump.offset == ipid_hi_offset)
            {
                mca_ipid_hi = buffer;
            }
            if(mca_dump.offset == synd_lo_offset)
            {
                mca_synd_lo = buffer;
            }
            if(mca_dump.offset == synd_hi_offset)
            {
                mca_synd_hi = buffer;
            }
			if(mca_dump.offset == addr_lo_offset)
            {
                mca_addr_lo = buffer;
            }
            if(mca_dump.offset == addr_hi_offset)
            {
                mca_addr_hi = buffer;
            }
			if(mca_dump.offset == misc_lo_offset)
            {
                mca_misc_lo = buffer;
            }
            if(mca_dump.offset == misc_hi_offset)
            {
                mca_misc_hi = buffer;
            }

        } // for loop

		// Check if valid RAS error is detected
        if(ValidSignatureID == true)
        {
			// Check if RAS error occurred on socket 0
            if(info == p0_info)
            {
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_0] = mca_synd_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_1] = mca_synd_hi;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_2] = mca_ipid_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_3] = mca_ipid_hi;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_4] = mca_status_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_5] = mca_status_hi;

                rcd->P0_ErrorRecord.ProcError.ValidBits = rcd->P0_ErrorRecord.ProcError.ValidBits
                                                          | FAILURE_SIGNATURE_ID;
				
				// Initialize apml_mce_event
				init_apml_mce_event(event_ptr, mca_synd_lo, mca_synd_hi, mca_ipid_lo, mca_ipid_hi, mca_status_lo, mca_status_hi, mca_addr_lo, mca_addr_hi, mca_misc_lo, mca_misc_hi, info);
				
				// Decode apml_mce_event
				mi300a_apml_mce_decoder(event);
				
				// Generate JSON summary
				ret_error_summary = generate_sockets_summary_json();
            }
			// Check if RAS error occurred on socket 1
            if(info == p1_info)
            {
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_0] = mca_synd_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_1] = mca_synd_hi;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_2] = mca_ipid_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_3] = mca_ipid_hi;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_4] = mca_status_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_5] = mca_status_hi;

                rcd->P1_ErrorRecord.ProcError.ValidBits = rcd->P1_ErrorRecord.ProcError.ValidBits
                                                          | FAILURE_SIGNATURE_ID;
				
				// Initialize apml_mce_event
				init_apml_mce_event(event_ptr, mca_synd_lo, mca_synd_hi, mca_ipid_lo, mca_ipid_hi, mca_status_lo, mca_status_hi, mca_addr_lo, mca_addr_hi, mca_misc_lo, mca_misc_hi, info);
				
				// Decode apml_mce_event
				mi300a_apml_mce_decoder(event);
				
				// Generate JSON summary
				ret_error_summary = generate_sockets_summary_json();
            }
			// Check if RAS error occurred on socket 2
            if(info == p2_info)
            {
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_0] = mca_synd_lo;
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_1] = mca_synd_hi;
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_2] = mca_ipid_lo;
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_3] = mca_ipid_hi;
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_4] = mca_status_lo;
                rcd->P2_ErrorRecord.ProcError.SignatureID[INDEX_5] = mca_status_hi;

                rcd->P2_ErrorRecord.ProcError.ValidBits = rcd->P2_ErrorRecord.ProcError.ValidBits
                                                          | FAILURE_SIGNATURE_ID;
				
				// Initialize apml_mce_event
				init_apml_mce_event(event_ptr, mca_synd_lo, mca_synd_hi, mca_ipid_lo, mca_ipid_hi, mca_status_lo, mca_status_hi, mca_addr_lo, mca_addr_hi, mca_misc_lo, mca_misc_hi, info);
				
				// Decode apml_mce_event
				mi300a_apml_mce_decoder(event);
				
				// Generate JSON summary
				ret_error_summary = generate_sockets_summary_json();
            }
			// Check if RAS error occurred on socket 3
            if(info == p3_info)
            {
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_0] = mca_synd_lo;
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_1] = mca_synd_hi;
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_2] = mca_ipid_lo;
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_3] = mca_ipid_hi;
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_4] = mca_status_lo;
                rcd->P3_ErrorRecord.ProcError.SignatureID[INDEX_5] = mca_status_hi;

                rcd->P3_ErrorRecord.ProcError.ValidBits = rcd->P3_ErrorRecord.ProcError.ValidBits
                                                          | FAILURE_SIGNATURE_ID;
				
				// Initialize apml_mce_event
				init_apml_mce_event(event_ptr, mca_synd_lo, mca_synd_hi, mca_ipid_lo, mca_ipid_hi, mca_status_lo, mca_status_hi, mca_addr_lo, mca_addr_hi, mca_misc_lo, mca_misc_hi, info);
				
				// Decode apml_mce_event
				mi300a_apml_mce_decoder(event);
				
				// Generate JSON summary
				ret_error_summary = generate_sockets_summary_json();
            }
			// Reset valid RAS error flag
            ValidSignatureID = false;
        }
        else
        {
			// Reset MCA register values
            mca_synd_lo = 0;
            mca_synd_hi = 0;
            mca_ipid_lo = 0;
            mca_ipid_hi = 0;
            mca_status_lo = 0;
            mca_status_hi = 0;
			mca_addr_lo = 0;
			mca_addr_hi = 0;
			mca_misc_lo = 0;
			mca_misc_hi = 0;
        }
        n++;
    } // while loop

    return true;
}

static bool harvest_mca_validity_check(uint8_t info, uint16_t *numbanks, uint16_t *bytespermca)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    bool mac_validity_check = true;

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_bmc_ras_mca_validity_check(info, bytespermca, numbanks);

        if (retries > apmlRetryCount)
        {
            log_error("Socket %d: Failed to get MCA banks with valid status. Error: %d", info, ret);
            break;
        }

        if ( (*numbanks == 0) ||
             (*numbanks > MAX_MCA_BANKS) )
        {
            log_error("Socket %d: Invalid MCA bank validity status. Retry Count: %d", info, retries);
            ret = OOB_MAILBOX_CMD_UNKNOWN;
            usleep(1000 * 1000);
            continue;
        }
    }


    if ( (*numbanks <= 0)            ||
         (*numbanks > MAX_MCA_BANKS) )
    {
        mac_validity_check = false;

    }

    return mac_validity_check;
}

// Harvest RAS errors
bool harvest_ras_errors(uint8_t info,std::string alert_name)
{
    std::unique_lock lock(harvest_in_progress_mtx);

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;
    bool ControlFabricError = false;
    bool FchHangError = false;

    uint8_t buf;
    bool ResetReady  = false;
    FILE *file;
    oob_status_t ret;
    uint32_t ack_resp = 0;

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {
        // TEMP - Uncomment once GPIO is implemented
        // log_warning("Read RAS status register. Value: 0x%x", buf);
        // END OF TEMP

        // check RAS Status Register
        if (buf & INT_15)
        {
            log_info("The alert signaled is due to a RAS fatal error");

            if (buf & SYS_MGMT_CTRL_ERR)
            {
                /*if RasStatus[reset_ctrl_err] is set in any of the processors,
                  proceed to cold reset, regardless of the status of the other P */
                std::string ras_err_msg = "Fatal error detected in the control fabric. "
                                          "BMC may trigger a reset based on policy set.\n";
                log_error("%s", ras_err_msg.c_str());

                P0_AlertProcessed = true;
                P1_AlertProcessed = true;
                P2_AlertProcessed = true;
                P3_AlertProcessed = true;
                ControlFabricError = true;

            } else if(buf & RESET_HANG_ERR)
            {
                std::string ras_err_msg = "System hang while resetting in syncflood."
                                          "Suggested next step is to do an additional manual immediate reset\n";
                log_error("%s", ras_err_msg.c_str());

                FchHangError = true;
            }
            else
            {
                std::string ras_err_msg = "RAS FATAL Error detected. "
                                          "System may reset after harvesting MCA data based on policy set.\n";
                log_error("%s", ras_err_msg.c_str());

                if(alert_name.compare("P0_ALERT") == 0 )
                {
                    P0_AlertProcessed = true;

                }

                if(alert_name.compare("P1_ALERT") == 0 )
                {
                    P1_AlertProcessed = true;

                }

                if(alert_name.compare("P2_ALERT") == 0 )
                {
                    P2_AlertProcessed = true;

                }

                if(alert_name.compare("P3_ALERT") == 0 )
                {
                    P3_AlertProcessed = true;

                }
            }

            //Do not harvest MCA banks in case of control fabric errors
            if((ControlFabricError == false) && (FchHangError == false))
            {
                // RAS MCA Validity Check
                if ( true == harvest_mca_validity_check(info, &numbanks, &bytespermca) )
                {
                    harvest_mca_data_banks(info, numbanks, bytespermca);

                }
            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in implementation of SMU?
            write_register(info, RAS_STATUS_REGISTER, 1);

            if(FchHangError == true)
            {
                return true;
            }

            if (num_of_proc == TWO_SOCKET)
            {
                if ( (P0_AlertProcessed == true) &&
                     (P1_AlertProcessed == true) )
                {
                    ResetReady = true;
                }
            }
            else if (num_of_proc == FOUR_SOCKET)
            {
                if ( (P0_AlertProcessed == true) &&
                     (P1_AlertProcessed == true) &&
                     (P2_AlertProcessed == true) &&
                     (P3_AlertProcessed == true) )
                {
                    ResetReady = true;
                }
            }
            else
            {
                ResetReady = true;
            }

            if (ResetReady == true)
            {

                if(ControlFabricError == false)
                {
                    std::string cperFilePath =
                        kRasDir.data() + getCperFilename(err_count);
                    err_count++;

                    if(err_count >= MAX_ERROR_FILE)
                    {
                        /*The maximum number of error files supported is 10.
                          The counter will be rotated once it reaches max count*/
                        err_count = (err_count % MAX_ERROR_FILE);
                    }

                    file = fopen(index_file, "w");

                    if(file != NULL)
                    {
                        fprintf(file,"%d",err_count);
                        fclose(file);
                    }

                    file = fopen(cperFilePath.c_str(), "w");
                    if ((rcd != nullptr) && (file != NULL)) {
                        log_warning("Generating CPER file");
                        fwrite(rcd.get(), sizeof(CPER_RECORD), 1, file);
                        fclose(file);
                    }
                }

                rcd = nullptr;

                if(systemRecovery == WARM_RESET)
                {
                    if ((buf & SYS_MGMT_CTRL_ERR))
                    {
                        triggerColdReset();
                        log_info("COLD RESET triggered");

                    } else {
                        /* In a 2P/4P config, it is recommended to only send this command to P0
                           Hence, sending the Signal only to socket 0*/
                        ret = reset_on_sync_flood(p0_info, &ack_resp);
                        if(ret)
                        {
                            log_error("Failed to request reset after sync flood");
                        } else {
                            log_error("WARM RESET triggered");
                        }
                    }
                }
                else if(systemRecovery == COLD_RESET)
                {
                    triggerColdReset();
                    log_info("COLD RESET triggered");

                }
                else if(systemRecovery == NO_RESET)
                {
                    log_info("NO RESET triggered");
                }
                else
                {
                    log_error("CdumpResetPolicy is not valid");
                }

                P0_AlertProcessed = false;
                P1_AlertProcessed = false;
                P2_AlertProcessed = false;
                P3_AlertProcessed = false;
            }

        }
    }
    else
    {
        log_warning("Nothing to Harvest. Not RAS Error");
    }

    return true;
}

// Initialize apml_mce_event struct
// NOTE: getCpuID() must always be called before init_apml_mce_event is called
void init_apml_mce_event(apml_mce_event* event_ptr, uint32_t mca_synd_lo, uint32_t mca_synd_hi, 
							uint32_t mca_ipid_lo, uint32_t mca_ipid_hi, uint32_t mca_status_lo, 
							uint32_t mca_status_hi, uint32_t mca_addr_lo, uint32_t mca_addr_hi, 
							uint32_t mca_misc_lo, uint32_t mca_misc_hi, uint8_t socketid_data){

    using namespace std;
    using namespace std::chrono;

	// Initialize status
	uint64_t uint64_mca_status_lo = mca_status_lo;
    uint64_t uint64_mca_status_hi = static_cast<uint64_t>(mca_status_hi) << 32;
	event_ptr->status = uint64_mca_status_hi+uint64_mca_status_lo;

	// Initialize addr
	uint64_t uint64_mca_addr_lo = mca_addr_lo;
    uint64_t uint64_mca_addr_hi = static_cast<uint64_t>(mca_addr_hi) << 32;
	event_ptr->addr = uint64_mca_addr_hi+uint64_mca_addr_lo;

	// Initialize misc
	uint64_t uint64_mca_misc_lo = mca_misc_lo;
    uint64_t uint64_mca_misc_hi = static_cast<uint64_t>(mca_misc_hi) << 32;
	event_ptr->misc = uint64_mca_misc_hi+uint64_mca_misc_lo;

	// Initialize synd
	uint64_t uint64_mca_synd_lo = mca_synd_lo;
    uint64_t uint64_mca_synd_hi = static_cast<uint64_t>(mca_synd_hi) << 32;
	event_ptr->synd = uint64_mca_synd_hi+uint64_mca_synd_lo;

	// Initialize ipid
	uint64_t uint64_mca_ipid_lo = mca_ipid_lo;
    uint64_t uint64_mca_ipid_hi = static_cast<uint64_t>(mca_ipid_hi) << 32;
	event_ptr->ipid = uint64_mca_ipid_hi+uint64_mca_ipid_lo;

	// Initialize cpuid
	// Convert socketid to string for comparison
	std::string socketid_data_string = std::to_string(static_cast<int>(socketid_data));

	// Check which socket's cpuid must be saved
	if(socketid_data_string == "0"){
		event_ptr->cpuid = p0_eax;
	}
	else if(socketid_data_string == "1"){
		event_ptr->cpuid = p1_eax;
	}
	else if(socketid_data_string == "2"){
		event_ptr->cpuid = p2_eax;
	}
	else if(socketid_data_string == "3"){
		event_ptr->cpuid = p3_eax;
	}
 
	// Initialize socketid
	event_ptr->socketid = socketid_data;

	// Initialize timestamp
	time_t now;
	struct tm *utc_tm;
	time(&now);
	utc_tm = gmtime(&now);
	event_ptr->timestamp = utc_tm;

}


int main() {

    int dir;
    struct stat buffer;
    FILE* file;

    initialize_syslog("amd-bmc-ras");

	// Create amd-ras-files directory if it does not exist
    if (stat(kRasDir.data(), &buffer) != 0) {
        dir = mkdir(kRasDir.data(), 0777);

        if(dir != 0) {
            log_error("ras-error-logging directory not created");
        }
    }
	// Update number of CPU sockets
	if(getNumberOfCpu() == false)
    {
        log_error("Could not find number of CPU's of the platform");
        return false;
    }

	// Update CPU IDs
    getCpuID();
	
    memset(&buffer, 0, sizeof(buffer));
    /*Create index file to store error file count */
    if (stat(index_file, &buffer) != 0)
    {
        file = fopen(index_file, "w");

        if(file != NULL)
        {
            fprintf(file,"0");
            fclose(file);
        }
    } else {
        file = fopen(index_file, "r");

        if(file != NULL)
        {
            fscanf(file,"%d",&err_count);
            fclose(file);
        }
    }
	// Generate and initialize error summary file in json format
	init_tracking_errors();
	
    /*Create Cdump Config file to store the system recovery*/
    if (stat(config_file, &buffer) != 0)
    {
        nlohmann::json jsonConfig = {
            { "apmlRetries" , MAX_RETRIES },
            { "systemRecovery" , NO_RESET },
            { "harvestuCodeVersion" , true },
            { "harvestPpin" , true },
        };

        jsonConfig["sigIDOffset"] = sigIDOffset;

        std::ofstream jsonWrite(config_file);
        jsonWrite << jsonConfig;
        jsonWrite.close();
    }

    std::ifstream jsonRead(config_file);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    apmlRetryCount = data["apmlRetries"];
    systemRecovery = data["systemRecovery"];
    harvestuCodeVersionFlag = data["harvestuCodeVersion"];
    harvestPpinFlag = data["harvestPpin"];
    sigIDOffset = data.at("sigIDOffset").get<std::vector<std::string>>();

    jsonRead.close();

	// Update microcode revision for each socket
    if(harvestuCodeVersionFlag == true)
    {
        getMicrocodeRev();
    }
	
    // Update fuse/ppin value for each socket
    if(harvestPpinFlag == true)
    {
        getPpinFuse();
    }

    rcd = std::make_shared<CPER_RECORD>();

    std::future<void> fut;

    // Check if any crashdump already exists.
    if (std::filesystem::exists(std::filesystem::path(kRasDir.data()))) {
        std::regex pattern("ras-error([[:digit:]]+).cper");
        std::smatch match;
        for (const auto& p : std::filesystem::directory_iterator(
                 std::filesystem::path(kRasDir.data()))) {
            std::string filename = p.path().filename();
            if (!std::regex_match(filename, match, pattern)) {
                continue;
            }
            const int kNum = stoi(match.str(1));
            const std::string cperFilename =
                kRasDir.data() + getCperFilename(kNum);
            // exportCrashdumpToDBus needs the timestamp inside the CPER
            // file. So load it first.
            std::ifstream fin(cperFilename, std::ifstream::binary);
            if (!fin.is_open()) {
                log_warning("Broken crashdump CPER file: %s\n",cperFilename.c_str());
                continue;
            }

            fin.seekg(offsetof(CPER_RECORD, Header) +
                      offsetof(COMMON_ERROR_RECORD_HEADER, TimeStamp));
            fin.read(reinterpret_cast<char*>(&rcd->Header.TimeStamp),
                     sizeof(ERROR_TIME_STAMP));
            fin.close();
        }
    }

    // requestGPIOEvents("nfpga-c0-apml-alert", P0AlertEventHandler, P0_apmlAlertLine, P0_apmlAlertEvent);
    // // requestGPIOEvents("HPM_FPGA_LOCKOUT", HPMFPGALockoutEventHandler, HPMFPGALockoutAlertLine, HPMFPGALockoutAlertEvent);

    // if (num_of_proc == TWO_SOCKET)
    // {
    //     requestGPIOEvents("nfpga-c1-apml-alert", P1AlertEventHandler, P1_apmlAlertLine, P1_apmlAlertEvent);
    // } else if (num_of_proc == FOUR_SOCKET)
    // {
    //     requestGPIOEvents("nfpga-c1-apml-alert", P1AlertEventHandler, P1_apmlAlertLine, P1_apmlAlertEvent);

    //     requestGPIOEvents("nfpga-c2-apml-alert", P2AlertEventHandler, P2_apmlAlertLine, P2_apmlAlertEvent);

    //     requestGPIOEvents("nfpga-c3-apml-alert", P3AlertEventHandler, P3_apmlAlertLine, P3_apmlAlertEvent);
    // }

    // TEMP -- Remove once GPIO is implemented and uncomment above section

	// Check for RAS errors every two seconds
    while(true){
		
		// Check if rcd is uninitialized
        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }
		// Check for P0 RAS errors
        harvest_ras_errors(p0_info, "P0_ALERT");

		// Check if rcd is uninitialized
        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }
		// Check for P1 RAS errors
        harvest_ras_errors(p1_info, "P1_ALERT");

		// Check if rcd is uninitialized
        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }
		// Check for P2 RAS errors
        harvest_ras_errors(p2_info, "P2_ALERT");

		// Check if rcd is uninitialized
        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }
		// Check for P3 RAS errors
        harvest_ras_errors(p3_info, "P3_ALERT");

        sleep(1);
    }
    // END OF TEMP
    
    io.run();

    close_syslog();

    return 0;
}
