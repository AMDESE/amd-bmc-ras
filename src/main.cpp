#include <iostream>
#include <gpiod.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/error.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/property.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <mutex>          // std::mutex

extern "C" {
#include <sys/stat.h>
#include "linux/i2c-dev.h"
#include "i2c/smbus.h"
#include "apml.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

#define COMMAND_BOARD_ID    ("/sbin/fw_printenv -n board_id")
#define COMMAND_LEN         3
#define MAX_MCA_BANKS       (32)

#define MAX_RETRIES 10
#define RAS_STATUS_REGISTER (0x4C)
#define index_file  ("/var/lib/amd-ras/current_index")
#define BAD_DATA    (0xBAADDA7A)

//#undef LOG_DEBUG
//#define LOG_DEBUG LOG_ERR

static boost::asio::io_service io;
std::shared_ptr<sdbusplus::asio::connection> conn;

static std::string BoardName;
static uint32_t err_count = 0;

static gpiod::line P0_apmlAlertLine;
static boost::asio::posix::stream_descriptor P0_apmlAlertEvent(io);

static gpiod::line P1_apmlAlertLine;
static boost::asio::posix::stream_descriptor P1_apmlAlertEvent(io);

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

static bool P0_MCADataHarvested = false;
static bool P1_MCADataHarvested = false;

bool harvest_ras_errors(uint8_t info,std::string alert_name);

bool getPlatformID()
{
    FILE *pf;
    char data[COMMAND_LEN];
    bool PLATID = false;
    std::stringstream ss;
    unsigned int board_id = 0;

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID,"r");
    // Error handling
    if(pf > 0)
    {
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf) > 0)
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

        harvest_in_progress_mtx.lock();
        harvest_ras_errors(p0_info,"P0_ALERT");
        harvest_in_progress_mtx.unlock();

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
        harvest_in_progress_mtx.lock();
        harvest_ras_errors(p1_info,"P1_ALERT");
        harvest_in_progress_mtx.unlock();
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Rising Edge: P0 APML Alert cancelled\n");
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

static bool harvest_mca_data_banks(std::string filePath, uint8_t info, uint16_t numbanks, uint16_t bytespermca)
{
    FILE *file;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retryCount = MAX_RETRIES;

    file = fopen(filePath.c_str(), "w");

    maxOffset32 = ((bytespermca % 4) ? 1 : 0) + (bytespermca >> 2);
    sd_journal_print(LOG_DEBUG, "Number of Valid MCA bank:%d\n", numbanks);
    sd_journal_print(LOG_DEBUG, "Number of 32 Bit Words:%d\n", maxOffset32);


    while(n < numbanks)
    {
        fprintf(file, "MCA bank Number: 0x%x\n", n);

        for (int offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&mca_dump, 0, sizeof(mca_dump));
            mca_dump.index  = n;
            mca_dump.offset = offset * 4;
            retryCount = MAX_RETRIES;

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
                    sd_journal_print(LOG_DEBUG, "Failed to get MCA bank data from Bank:%d, Offset:0x%x\n", n, offset);
                    fprintf(file, "Offset: 0x%x\n", mca_dump.offset);
                    fprintf(file, "buffer: 0x%x\n", BAD_DATA);
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            fprintf(file, "Offset: 0x%x\n", mca_dump.offset);
            fprintf(file, "buffer: 0x%x\n", buffer);
        } // for loop

        fprintf(file, "______________________\n");
        n++;
    }

    fclose(file);
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

        if (retries > MAX_RETRIES)
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

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;

    std::string filePath;
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
            sd_journal_print(LOG_DEBUG, "The alert signaled is due to a RAS fatal error\n");

            if(alert_name.compare("P0_ALERT") == 0 )
            {
                P0_MCADataHarvested = true;

            }

            if(alert_name.compare("P1_ALERT") == 0 )
            {
                P1_MCADataHarvested = true;

            }

            // RAS MCA Validity Check
            if ( true == harvest_mca_validity_check(info, &numbanks, &bytespermca) )
            {
                filePath = "/var/lib/amd-ras/ras-error" + std::to_string(err_count) + ".txt";

                harvest_mca_data_banks(filePath, info, numbanks, bytespermca);
                err_count++;

                file = fopen(index_file, "w");

                if(file != NULL)
                {
                    fprintf(file,"%d",err_count);
                    fclose(file);
                }

            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in implementation of SMU?
            write_register(info, RAS_STATUS_REGISTER, 1);

            if (num_of_proc == 2)
            {
                if ( (P0_MCADataHarvested == true) &&
                     (P1_MCADataHarvested == true) )
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
                // Trigger Cold or WARM reset
                if ((buf & 0x04))
                {
                    setGPIOValue("ASSERT_RST_BTN_L", 0, resetPulseTimeMs);
                    sd_journal_print(LOG_DEBUG, "COLD RESET triggered\n");

                }
                else
                {
                    setGPIOValue("ASSERT_WARM_RST_BTN_L", 0, resetPulseTimeMs);
                    sd_journal_print(LOG_DEBUG, "WARM RESET triggered\n");

                }


                P0_MCADataHarvested = false;
                P1_MCADataHarvested = false;
            }
        }

    }
    else
    {
        sd_journal_print(LOG_DEBUG, "Nothing to Harvest. Not RAS Error\n");
    }

    return true;
}

int main() {

    int dir;
    struct stat buffer;
    FILE *file;
    std::string ras_dir = "/var/lib/amd-ras/";

    if(getPlatformID() == false)
    {
        sd_journal_print(LOG_ERR, "Could not find the board id of the platform\n");
        return false;
    }

    if (stat(ras_dir.c_str(), &buffer) != 0) {
        dir = mkdir("/var/lib/amd-ras",0777);

        if(dir != 0) {
            sd_journal_print(LOG_ERR, "ras-errror-logging directory not created\n");
        }
    }

    memset(&buffer, 0, sizeof(buffer));
    /*Create index file to store error file cound */
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

    conn = std::make_shared<sdbusplus::asio::connection>(io);

    requestGPIOEvents("P0_I3C_APML_ALERT_L", P0AlertEventHandler, P0_apmlAlertLine, P0_apmlAlertEvent);

    if (num_of_proc == 2)
    {
        requestGPIOEvents("P1_I3C_APML_ALERT_L", P1AlertEventHandler, P1_apmlAlertLine, P1_apmlAlertEvent);
    }

    io.run();

    return 0;
}

