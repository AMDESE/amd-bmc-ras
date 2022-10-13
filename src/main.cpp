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
#include "cper.hpp"

extern "C" {
#include <sys/stat.h>
#include "linux/i2c-dev.h"
#include "i2c/smbus.h"
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

#define COMMAND_BOARD_ID    ("/sbin/fw_printenv -n board_id")
#define COMMAND_LEN         3
#define MAX_MCA_BANKS       (32)
#define TWO_SOCKET          (2)
#define SHIFT_24            (24)
#define SHIFT_32            (32)

#define WARM_RESET          ('0')
#define COLD_RESET          ('1')
#define NO_RESET            ('2')

#define MAX_RETRIES 10
#define RAS_STATUS_REGISTER (0x4C)
#define index_file  ("/var/lib/amd-ras/current_index")
#define config_file ("/var/lib/amd-ras/config_file")
#define BAD_DATA    (0xBAADDA7A)

#define HPM_FPGA_REGDUMP         "/usr/sbin/hpm-fpga-dump.sh"
#define HPM_FPGA_REGDUMP_FILE    "/var/lib/amd-ras/fpga_dump.txt"
//#undef LOG_DEBUG
//#define LOG_DEBUG LOG_ERR

static boost::asio::io_service io;
static std::shared_ptr<sdbusplus::asio::connection> conn;
static std::shared_ptr<sdbusplus::asio::object_server> server;
static std::array<
    std::pair<std::string, std::shared_ptr<sdbusplus::asio::dbus_interface>>,
    MAX_ERROR_FILE>
    crashdumpInterfaces;

constexpr std::string_view crashdumpService = "com.amd.crashdump";
constexpr std::string_view crashdumpPath = "/com/amd/crashdump";
constexpr std::string_view crashdumpInterface = "com.amd.crashdump";

constexpr std::string_view deleteAllInterface =
    "xyz.openbmc_project.Collection.DeleteAll";
constexpr std::string_view deleteAllMethod = "DeleteAll";
constexpr std::string_view crashdumpAssertedInterface =
    "com.amd.crashdump.Asserted";
constexpr std::string_view crashdumpAssertedMethod = "GenerateAssertedLog";
// These 2 interfaces will be called by bmcweb, not supported now.
// constexpr std::string_view crashdumpOnDemandInterface =
// "com.amd.crashdump.OnDemand"; constexpr std::string_view
// crashdumpOnDemandMethod = "GenerateOnDemandLog"; constexpr std::string_view
// crashdumpTelemetryInterface = "com.amd.crashdump.Telemetry"; constexpr
// std::string_view crashdumpTelemetryMethod = "GenerateTelemetryLog";

constexpr std::string_view kRasDir = "/var/lib/amd-ras/";
constexpr int kCrashdumpTimeInSec = 300;

static std::string BoardName;
static uint32_t err_count = 0;

static gpiod::line P0_apmlAlertLine;
static boost::asio::posix::stream_descriptor P0_apmlAlertEvent(io);

static gpiod::line P1_apmlAlertLine;
static boost::asio::posix::stream_descriptor P1_apmlAlertEvent(io);

static gpiod::line P0_pmicAfAlertLine;
static boost::asio::posix::stream_descriptor P0_pmicAfAlertEvent(io);

static gpiod::line P0_pmicGlAlertLine;
static boost::asio::posix::stream_descriptor P0_pmicGlAlertEvent(io);

static gpiod::line P1_pmicAfAlertLine;
static boost::asio::posix::stream_descriptor P1_pmicAfAlertEvent(io);

static gpiod::line P1_pmicGlAlertLine;
static boost::asio::posix::stream_descriptor P1_pmicGlAlertEvent(io);

static gpiod::line HPMFPGALockoutAlertLine;
static boost::asio::posix::stream_descriptor HPMFPGALockoutAlertEvent(io);

uint8_t p0_info = 0;
uint8_t p1_info = 1;

static int num_of_proc = 0;

const static constexpr int resetPulseTimeMs = 100;
constexpr auto ONYX_SLT     = 61;   //0x3D
constexpr auto ONYX_1       = 64;   //0x40
constexpr auto ONYX_2       = 65;   //0x41
constexpr auto ONYX_3       = 66;   //0x42
constexpr auto ONYX_FR4     = 82;   //0x52
constexpr auto QUARTZ_DAP   = 62;   //0x3E
constexpr auto QUARTZ_1     = 67;   //0x43
constexpr auto QUARTZ_2     = 68;   //0x44
constexpr auto QUARTZ_3     = 69;   //0x45
constexpr auto QUARTZ_FR4   = 81;   //0x51
constexpr auto RUBY_1       = 70;   //0x46
constexpr auto RUBY_2       = 71;   //0x47
constexpr auto RUBY_3       = 72;   //0x48
constexpr auto TITANITE_1   = 73;   //0x49
constexpr auto TITANITE_2   = 74;   //0x4A
constexpr auto TITANITE_3   = 75;   //0x4B
constexpr auto TITANITE_4   = 76;   //0x4C
constexpr auto TITANITE_5   = 77;   //0x4D
constexpr auto TITANITE_6   = 78;   //0x4E

std::mutex harvest_in_progress_mtx;           // mutex for critical section

static bool P0_AlertProcessed = false;
static bool P1_AlertProcessed = false;

static uint64_t RecordId = 1;
unsigned int board_id = 0;
static uint32_t p0_eax , p0_ebx , p0_ecx , p0_edx;
static uint32_t p1_eax , p1_ebx , p1_ecx , p1_edx;
std::shared_ptr<CPER_RECORD> rcd;

uint64_t p0_last_transact_addr = 0;
uint64_t p1_last_transact_addr = 0;
uint16_t retryCount = MAX_RETRIES;

bool harvest_ras_errors(uint8_t info,std::string alert_name);

bool getPlatformID()
{
    FILE *pf;
    char data[COMMAND_LEN];
    bool PLATID = false;
    std::stringstream ss;

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID,"r");
    // Error handling
    if(pf)
    {
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> board_id;
            PLATID = true;
            sd_journal_print(LOG_DEBUG, "Board ID: 0x%x, Board ID String: %s\n", board_id, data);
        }

        // the data is now in 'data'
        pclose(pf);


        switch (board_id)
        {
        case ONYX_SLT:
        case ONYX_1 ... ONYX_3:
        case ONYX_FR4:
        case RUBY_1 ... RUBY_3:
        num_of_proc = 1;
        break;
        case QUARTZ_DAP:
        case QUARTZ_1 ... QUARTZ_3:
        case QUARTZ_FR4:
        case TITANITE_1 ... TITANITE_6:
        num_of_proc = 2;
        break;
        default:
            num_of_proc = 1;
            break;
        }//switch
    }

    return PLATID;
}

void getCpuID()
{
    uint32_t core_id = 0;
    oob_status_t ret;
    p0_eax = 0;
    p0_ebx = 0;
    p0_ecx = 0;
    p0_edx = 0;

    ret = esmi_oob_cpuid(p0_info, core_id,
                 &p0_eax, &p0_ebx, &p0_ecx, &p0_edx);

    if(ret)
    {
        sd_journal_print(LOG_ERR, "Failed to get the CPUID for socket 0\n");
    }

    if(num_of_proc == TWO_SOCKET)
    {
        p1_eax = 0;
        p1_ebx = 0;
        p1_ecx = 0;
        p1_edx = 0;

        ret = esmi_oob_cpuid(p1_info, core_id,
                 &p1_eax, &p1_ebx, &p1_ecx, &p1_edx);

        if(ret)
        {
            sd_journal_print(LOG_ERR, "Failed to get the CPUID for socket 1\n");
        }

    }

}

void getLastTransAddr()
{
    oob_status_t ret;

    ret = read_ras_last_transaction_address(p0_info, &p0_last_transact_addr);
    if (ret) {
        sd_journal_print(LOG_ERR, "Failed to get the last transaction address for socket 0\n");
    }

    if(num_of_proc == TWO_SOCKET)
    {
        ret = read_ras_last_transaction_address(p1_info, &p1_last_transact_addr);
        if (ret) {
            sd_journal_print(LOG_ERR, "Failed to get the last transaction address for socket 1\n");
        }
    }
    sd_journal_print(LOG_DEBUG, "Last trancation address for P0 = %llu\n",p0_last_transact_addr);
    sd_journal_print(LOG_DEBUG, "Last trancation address for P1 = %llu\n",p1_last_transact_addr);

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
        sd_journal_print(LOG_ERR, "Failed to find gpio line %s \n", name.c_str());
        return false;
    }

    try
    {
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES});
    }
    catch (std::exception& exc)
    {
        sd_journal_print(LOG_ERR, "Failed to request events for gpio line %s, exception: %s \n", name.c_str(), exc.what());
        return false;
    }

    int gpioLineFd = gpioLine.event_get_fd();
    if (gpioLineFd < 0)
    {
        sd_journal_print(LOG_ERR, "Failed to get gpio line %s fd\n", name.c_str());
        return false;
    }

    gpioEventDescriptor.assign(gpioLineFd);

    gpioEventDescriptor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [&name, handler](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error: %s \n", ec.message().c_str());
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
        sd_journal_print(LOG_ERR, "Failed to find gpio line %s \n", name.c_str());
        return false;
    }

    try
    {
        gpioLine.request({__FUNCTION__, gpiod::line_request::DIRECTION_OUTPUT});
    }
    catch (std::system_error& exc)
    {
        sd_journal_print(LOG_ERR, "Error setting gpio as Output: %s, exception: %s \n", name.c_str(), exc.what());
    }

    try
    {
        // Request GPIO output to specified value
        gpioLine.set_value(value);
    }
    catch (std::exception& exc)
    {
        sd_journal_print(LOG_ERR, "Failed to set value for %s, exception: %s \n", name.c_str(), exc.what());
        return false;
    }


    sd_journal_print(LOG_DEBUG, "%s set to %d \n", name.c_str(), value);

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
        sd_journal_print(LOG_DEBUG, "Falling Edge: P0 APML Alert received\n");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p0_info, "P0_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Rising Edge: P0 APML Alert cancelled\n");
    }

    P0_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P0 APML alert handler error: %s\n", ec.message().c_str());
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
        sd_journal_print(LOG_DEBUG, "Falling Edge: P1 APML Alert received\n");

        if (rcd == nullptr) {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p1_info, "P1_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Rising Edge: P1 APML Alert cancelled\n");
    }
    P1_apmlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P1 APML alert handler error: %s\n", ec.message().c_str());
            return;
        }
        P1AlertEventHandler();
    });
}

static void P0PmicAfEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_pmicAfAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "P0 DIMM A-F PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG, "Rising Edge: P0 PMIC DIMM A-F Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P0_pmicAfAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P0 PMIC DIMM A-F alert handler error: %s\n", ec.message().c_str());
            return;
        }
        P0PmicAfEventHandler();
    });
}

static void P0PmicGlEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_pmicGlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "P0 DIMM G-L PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG, "Rising Edge: P0 PMIC DIMM G-L Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P0_pmicGlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P0 PMIC DIMM G-L alert handler error: %s\n", ec.message().c_str());
            return;
        }
        P0PmicGlEventHandler();
    });
}

static void P1PmicAfEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_pmicAfAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "P1 DIMM A-F PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG, "Rising Edge: P1 PMIC DIMM A-F Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P1_pmicAfAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P1 PMIC DIMM A-F alert handler error: %s\n", ec.message().c_str());
            return;
        }
        P1PmicAfEventHandler();
    });
}

static void P1PmicGlEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_pmicGlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "P1 DIMM G-L PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG, "Rising Edge: P1 PMIC DIMM G-L Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P1_pmicGlAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P1 PMIC DIMM G-L alert handler error: %s\n", ec.message().c_str());
            return;
        }
        P1PmicGlEventHandler();
    });
}

static void HPMFPGALockoutEventHandler()
{
    gpiod::line_event gpioLineEvent = HPMFPGALockoutAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg = "HPM FPGA detected fatal error."
                                  "FPGA registers dumped to " HPM_FPGA_REGDUMP_FILE
                                  "A/C power cycle to recover";
        sd_journal_print(LOG_DEBUG, "Rising Edge: HPM FPGA lockout Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
        system("HPM_FPGA_REGDUMP > " HPM_FPGA_REGDUMP_FILE " 2>&1 &");
    }

    HPMFPGALockoutAlertEvent.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [](const boost::system::error_code ec) {
        if (ec)
        {
            sd_journal_print(LOG_ERR, "P1 PMIC DIMM A-F alert handler error: %s\n", ec.message().c_str());
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
        sd_journal_print(LOG_ERR, "Failed to write register: 0x%x\n", reg);
        return;
    }
    sd_journal_print(LOG_DEBUG, "Write to register 0x%x is successful\n", reg);
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

    rcd->Header.PlatformId[0] = board_id;

    rcd->Header.CreatorId = CPER_CREATOR_PSTORE;
    rcd->Header.NotifyType = CPER_NOTIFY_MCE;

    if(rcd->Header.RecordId != RSVD)
        rcd->Header.RecordId = RecordId++;
}

void dump_error_descriptor_section(uint16_t numbanks, uint16_t bytespermca,uint8_t info)
{

    rcd->SectionDescriptor[0].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                              (2 * sizeof(ERROR_SECTION_DESCRIPTOR));
    rcd->SectionDescriptor[0].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[0].Revision = CPER_SEC_REV;
    rcd->SectionDescriptor[0].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[0].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[0].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[0].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[0].FRUText[0] = 'P';
    rcd->SectionDescriptor[0].FRUText[1] = '0';


    rcd->SectionDescriptor[1].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                             (2 * sizeof(ERROR_SECTION_DESCRIPTOR)) + sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[1].SectionLength = sizeof(ERROR_RECORD);
    rcd->SectionDescriptor[1].Revision = CPER_SEC_REV;
    rcd->SectionDescriptor[1].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
    rcd->SectionDescriptor[1].SectionFlags = CPER_PRIMARY;
    rcd->SectionDescriptor[1].SectionType = VENDOR_OOB_CRASHDUMP;
    rcd->SectionDescriptor[1].Severity = CPER_SEV_FATAL;
    rcd->SectionDescriptor[1].FRUText[0] = 'P';
    rcd->SectionDescriptor[1].FRUText[1] = '1';
}

void dump_processor_error_section(uint8_t info)
{

    rcd->P0_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
    rcd->P0_ErrorRecord.ProcError.CpuId[0] = p0_eax;
    rcd->P0_ErrorRecord.ProcError.CpuId[1] = p0_ebx;
    rcd->P0_ErrorRecord.ProcError.CpuId[2] = p0_ecx;
    rcd->P0_ErrorRecord.ProcError.CpuId[3] = p0_edx;
    rcd->P0_ErrorRecord.ProcError.CPUAPICId = ((p0_ebx >> SHIFT_24) & 0xff);

    if(num_of_proc == TWO_SOCKET)
    {
        rcd->P1_ErrorRecord.ProcError.ValidBits = CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P1_ErrorRecord.ProcError.CpuId[0] = p1_eax;
        rcd->P1_ErrorRecord.ProcError.CpuId[1] = p1_ebx;
        rcd->P1_ErrorRecord.ProcError.CpuId[2] = p1_ecx;
        rcd->P1_ErrorRecord.ProcError.CpuId[3] = p1_edx;
        rcd->P1_ErrorRecord.ProcError.CPUAPICId = ((p1_ebx >> SHIFT_24) & 0xff);
    }

   if(info == p0_info)
   {
       rcd->P0_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
   if(info == p1_info)
   {
       rcd->P1_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
   }
}

void dump_context_info(uint16_t numbanks,uint16_t bytespermca,uint8_t info)
{
    getLastTransAddr();
    if(info == p0_info)
    {
        rcd->P0_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P0_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
        rcd->P0_ErrorRecord.ContextInfo.dfdumpdata.dfwdtdump_low = p0_last_transact_addr & FOUR_BYTE_MASK;
        rcd->P0_ErrorRecord.ContextInfo.dfdumpdata.dfwdtdump_high = (p0_last_transact_addr >> SHIFT_32 ) & FOUR_BYTE_MASK;
    }
    else if(info == p1_info)
    {
        rcd->P1_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P1_ErrorRecord.ContextInfo.RegisterArraySize = numbanks * bytespermca;
        rcd->P1_ErrorRecord.ContextInfo.dfdumpdata.dfwdtdump_low = p1_last_transact_addr & FOUR_BYTE_MASK;
        rcd->P1_ErrorRecord.ContextInfo.dfdumpdata.dfwdtdump_high = (p1_last_transact_addr >> SHIFT_32 ) & FOUR_BYTE_MASK;
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

    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    FILE* fp = fopen(config_file, "r");

    while ((read = getline(&line, &len, fp)) != -1)
    {
        if(strstr(line,"APML retries"))
        {
            std::string retry_string =  std::string(line);
            std::string retry = std::regex_replace(
                retry_string,
                std::regex("[^0-9]*([0-9]+).*"),
                std::string("$1")
            );
            retryCount = std::stoi(retry);
            break;
        } else {
            continue;
        }
    }
    sd_journal_print(LOG_DEBUG,"Maximum APML retries  = %d\n",retryCount);

    if(fp != NULL) {
        fclose(fp);
        fp = NULL;
    }

    dump_cper_header_section(numbanks,bytespermca);

    dump_error_descriptor_section(numbanks,bytespermca,info);

    dump_processor_error_section(info);

    dump_context_info(numbanks,bytespermca,info);

    maxOffset32 = ((bytespermca % 4) ? 1 : 0) + (bytespermca >> 2);
    sd_journal_print(LOG_INFO, "Number of Valid MCA bank:%d\n", numbanks);
    sd_journal_print(LOG_INFO, "Number of 32 Bit Words:%d\n", maxOffset32);


    while(n < numbanks)
    {
        for (int offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&mca_dump, 0, sizeof(mca_dump));
            mca_dump.index  = n;
            mca_dump.offset = offset * 4;

            ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

            if (ret != OOB_SUCCESS)
            {
                // retry
                while(retryCount > 0)
                {
                    memset(&buffer, 0, sizeof(buffer));
                    memset(&mca_dump, 0, sizeof(mca_dump));
                    mca_dump.index  = n;
                    mca_dump.offset = offset * 4;

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
                    sd_journal_print(LOG_ERR, "Failed to get MCA bank data from Bank:%d, Offset:0x%x\n", n, offset);
                    if(info == p0_info) {
                        rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    } else if(info == p1_info) {
                       rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = BAD_DATA;
                    }
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            if(info == p0_info) {
                rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            } else if(info == p1_info) {
                rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n].mca_data[offset] = buffer;
            }
        } // for loop

        n++;
    }

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

        if (retries > retryCount)
        {
            sd_journal_print(LOG_ERR, "Failed to get MCA banks with valid status. Error: %d\n", ret);
            break;
        }

        if ( (*numbanks == 0) ||
             (*numbanks > MAX_MCA_BANKS) )
        {
            sd_journal_print(LOG_ERR, "Invalid MCA bank validity status. Retry Count: %d\n", retries);
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

bool harvest_ras_errors(uint8_t info,std::string alert_name)
{
    std::unique_lock lock(harvest_in_progress_mtx);

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;

    uint8_t buf;
    bool ResetReady  = false;
    FILE *file;

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {
        sd_journal_print(LOG_DEBUG, "Read RAS status register. Value: 0x%x\n", buf);

        // check RAS Status Register
        if (buf & 0x0F)
        {
            sd_journal_print(LOG_INFO, "The alert signaled is due to a RAS fatal error\n");

            if (buf & SYS_MGMT_CTRL_ERR)
            {
                /*if RasStatus[reset_ctrl_err] is set in any of the processors,
                  proceed to cold reset, regardless of the status of the other P */
                std::string ras_err_msg = "Fatal error detected in the control fabric. "
                                          "BMC may trigger a reset based on policy set. ";

                sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                    LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                    "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                    ras_err_msg.c_str(), NULL);

                P0_AlertProcessed = true;
                P1_AlertProcessed = true;

            }
            else
            {
                std::string ras_err_msg = "RAS FATAL Error detected. "
                                          "System may reset after harvesting MCA data based on policy set. ";

                sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                    LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                    "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                    ras_err_msg.c_str(), NULL);

                if(alert_name.compare("P0_ALERT") == 0 )
                {
                    P0_AlertProcessed = true;

                }

                if(alert_name.compare("P1_ALERT") == 0 )
                {
                    P1_AlertProcessed = true;

                }
            }
                // RAS MCA Validity Check
            if ( true == harvest_mca_validity_check(info, &numbanks, &bytespermca) )
            {

                harvest_mca_data_banks(info, numbanks, bytespermca);

            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in implementation of SMU?
            write_register(info, RAS_STATUS_REGISTER, 1);

            if (num_of_proc == TWO_SOCKET)
            {
                if ( (P0_AlertProcessed == true) &&
                     (P1_AlertProcessed == true) )
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
                    sd_journal_print(LOG_DEBUG, "Generating CPER file\n");
                    fwrite(rcd.get(), sizeof(CPER_RECORD), 1, file);
                    fclose(file);
                }

                rcd = nullptr;

                FILE* fp = fopen(config_file, "r");

                char * line = NULL;
                size_t len = 0;
                ssize_t read;

                while ((read = getline(&line, &len, fp)) != -1)
                {
                    if(*line == '#')
                        continue;
                    else
                    {
                        if(*line == WARM_RESET)
                        {
                            if ((buf & SYS_MGMT_CTRL_ERR))
                            {
                                setGPIOValue("ASSERT_RST_BTN_L", 0, resetPulseTimeMs);
                                sd_journal_print(LOG_INFO, "COLD RESET triggered\n");

                            } else {

                                setGPIOValue("ASSERT_WARM_RST_BTN_L", 0, resetPulseTimeMs);
                                sd_journal_print(LOG_INFO, "WARM RESET triggered\n");

                            }
                        }
                        else if(*line == COLD_RESET)
                        {

                            setGPIOValue("ASSERT_RST_BTN_L", 0, resetPulseTimeMs);
                            sd_journal_print(LOG_INFO, "COLD RESET triggered\n");

                        }
                        else if(*line == NO_RESET)
                        {
                            sd_journal_print(LOG_INFO, "NO RESET triggered\n");
                        }
                        else
                        {
                            sd_journal_print(LOG_ERR, "CdumpResetPolicy is not valid\n");
                        }
                    }
                }
                fclose(fp);

                P0_AlertProcessed = false;
                P1_AlertProcessed = false;

            }
        }
    }
    else
    {
        sd_journal_print(LOG_DEBUG, "Nothing to Harvest. Not RAS Error\n");
    }

    return true;
}

void exportCrashdumpToDBus(int num) {
    if (rcd == nullptr) {
        // This shouldn't happen.
        sd_journal_print(LOG_ERR, "Broken crashdump data\n");
        return;
    }
    if (num < 0 || num >= MAX_ERROR_FILE) {
        sd_journal_print(LOG_ERR, "Crashdump only allows index 0~9\n");
        return;
    }

    // remove the interface if it exists
    if (crashdumpInterfaces[num].second != nullptr) {
        server->remove_interface(crashdumpInterfaces[num].second);
        crashdumpInterfaces[num].second.reset();
    }

    const std::string filename = getCperFilename(num);
    const std::string fullFilePath = kRasDir.data() + filename;

    // Use ISO-8601 as the timestamp format
    // For example: 2022-07-19T14:13:47Z
    const ERROR_TIME_STAMP& t = rcd->Header.TimeStamp;
    char timestamp[30];
    sprintf(timestamp, "%d-%d-%dT%d:%d:%dZ", (t.Century - 1) * 100 + t.Year, t.Month,
            t.Day, t.Hours, t.Minutes, t.Seconds);

    // Create crashdump DBus instance
    const std::string dbusPath =
        std::string{crashdumpPath} + "/" + std::to_string(num);
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server->add_interface(dbusPath, crashdumpInterface.data());
    iface->register_property("Log", fullFilePath);
    iface->register_property("Filename", filename);
    iface->register_property("Timestamp", std::string{timestamp});
    iface->initialize();

    crashdumpInterfaces[num] = {filename, iface};
}

int main() {

    int dir;
    struct stat buffer;
    FILE* file;

    if(getPlatformID() == false)
    {
        sd_journal_print(LOG_ERR, "Could not find the board id of the platform\n");
        return false;
    }

    getCpuID();

    if (stat(kRasDir.data(), &buffer) != 0) {
        dir = mkdir(kRasDir.data(), 0777);

        if(dir != 0) {
            sd_journal_print(LOG_ERR, "ras-errror-logging directory not created\n");
        }
    }

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

    /*Create Cdump Config file to store the system recovery*/
    if (stat(config_file, &buffer) != 0)
    {
        file = fopen(config_file, "w");

        if(file != NULL)
        {
            fprintf(file,"APML retries:10\n");
            fprintf(file,"# 0 ---> warm\n");
            fprintf(file,"# 1 ---> cold\n");
            fprintf(file,"# 2 ---> no reset\n");
            fprintf(file,"2");
            fclose(file);
        }
    }

    rcd = std::make_shared<CPER_RECORD>();

    std::future<void> fut;

    conn = std::make_shared<sdbusplus::asio::connection>(io);
    conn->request_name(crashdumpService.data());
    server = std::make_shared<sdbusplus::asio::object_server>(conn);

    // This DBus interface/method should be triggered by
    // host-error-monitor(https://github.com/openbmc/host-error-monitor).
    // However `amd-ras` monitors the alert pin by itself instead of asking
    // `host-error-monitor` to do so. So currently no service will call this
    // DBus method (this still can be called by `busctl` CLI).

    // Generate crashdump and expose on DBus when APML_ALERT pin is asserted
    std::shared_ptr<sdbusplus::asio::dbus_interface> assertedIface =
        server->add_interface(crashdumpPath.data(),
                              crashdumpAssertedInterface.data());
    assertedIface->register_method(
        crashdumpAssertedMethod.data(), [&fut](const std::string& alertName) {
          // Do nothing if logging is in progress already
          if (fut.valid() && fut.wait_for(std::chrono::seconds(0)) !=
                                 std::future_status::ready) {
            return "Logging is in progress already";
          }

          fut = std::async(std::launch::async, [&alertName]() {
            const int curErrCnt = err_count;
            // harvest the error
            harvest_ras_errors(alertName == "P0_ALERT" ? p0_info : p1_info,
                               alertName);
            const int nextErrCnt = err_count;
            // Change in err_count means we harvested something
            if (curErrCnt != nextErrCnt) {
              boost::asio::post(
                  io, [&curErrCnt]() { exportCrashdumpToDBus(curErrCnt); });
            }
          });
          return "Log started";
        });
    assertedIface->initialize();

    // Delete all the generated crashdump
    std::shared_ptr<sdbusplus::asio::dbus_interface> deleteAllIface =
        server->add_interface(crashdumpPath.data(), deleteAllInterface.data());
    deleteAllIface->register_method(deleteAllMethod.data(), [&fut]() {
      if (fut.valid() &&
          fut.wait_for(std::chrono::seconds(kCrashdumpTimeInSec)) !=
              std::future_status::ready) {
        sd_journal_print(
            LOG_WARNING,
            "A logging is still in progress, that one won't get removed\n");
      }
      for (auto& [filename, interface] : crashdumpInterfaces) {
        if (!std::filesystem::remove(
                std::filesystem::path(kRasDir.data() + filename))) {
          sd_journal_print(LOG_WARNING, "Can't remove crashdump %s\n",
                           filename.c_str());
        }
        server->remove_interface(interface);
        filename = "";
        interface = nullptr;
      }
      return "Logs cleared";
    });
    deleteAllIface->initialize();

    // com.amd.crashdump.OnDemand/GenerateOnDemandLog currently not supported
    // com.amd.crashdump.Telemetry/GenerateTelemetryLog currently not supported

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
                sd_journal_print(LOG_WARNING,
                                 "Broken crashdump CPER file: %s\n",
                                 cperFilename.c_str());
                continue;
            }

            fin.seekg(offsetof(CPER_RECORD, Header) +
                      offsetof(COMMON_ERROR_RECORD_HEADER, TimeStamp));
            fin.read(reinterpret_cast<char*>(&rcd->Header.TimeStamp),
                     sizeof(ERROR_TIME_STAMP));
            fin.close();
            exportCrashdumpToDBus(kNum);
        }
    }

    requestGPIOEvents("P0_I3C_APML_ALERT_L", P0AlertEventHandler, P0_apmlAlertLine, P0_apmlAlertEvent);
    requestGPIOEvents("P0_DIMM_AF_ERROR", P0PmicAfEventHandler, P0_pmicAfAlertLine, P0_pmicAfAlertEvent);
    requestGPIOEvents("P0_DIMM_GL_ERROR", P0PmicGlEventHandler, P0_pmicGlAlertLine, P0_pmicGlAlertEvent);
    requestGPIOEvents("HPM_FPGA_LOCKOUT", HPMFPGALockoutEventHandler, HPMFPGALockoutAlertLine, HPMFPGALockoutAlertEvent);

    if (num_of_proc == TWO_SOCKET)
    {
        requestGPIOEvents("P1_I3C_APML_ALERT_L", P1AlertEventHandler, P1_apmlAlertLine, P1_apmlAlertEvent);
        requestGPIOEvents("P1_DIMM_AF_ERROR", P1PmicAfEventHandler, P1_pmicAfAlertLine, P1_pmicAfAlertEvent);
        requestGPIOEvents("P1_DIMM_GL_ERROR", P1PmicGlEventHandler, P1_pmicGlAlertLine, P1_pmicGlAlertEvent);
    }

    io.run();

    return 0;
}

