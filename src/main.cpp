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

extern "C" {
#include <sys/stat.h>
#include "linux/i2c-dev.h"
#include "i2c/smbus.h"
#include "esmi_common.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

#define COMMAND_BOARD_ID    ("/sbin/fw_printenv -n board_id")
#define COMMAND_LEN         3

#define MAX_RETRIES 10

static boost::asio::io_service io;
std::shared_ptr<sdbusplus::asio::connection> conn;

static std::string BoardName;
static uint32_t err_count = 0;

static gpiod::line P0_apmlAlertLine;
static boost::asio::posix::stream_descriptor P0_apmlAlertEvent(io);

static gpiod::line P1_apmlAlertLine;
static boost::asio::posix::stream_descriptor P1_apmlAlertEvent(io);

struct i2c_info p0_info = {2, 60, 0};
struct i2c_info p1_info = {3, 56, 0};

const static constexpr int resetPulseTimeMs = 100;

bool harvest_ras_errors(struct i2c_info info,std::string alert_name);

bool getPlatformID()
{
    FILE *pf;
    char data[COMMAND_LEN];

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID,"r");

    // Error handling
    if(pf < 0)
    {
        std::cerr << "Unable to get Board ID, errno: " << errno << "message: " << strerror(errno) << "\n";
        return false;
    }

    // Get the data from the process execution
    if (fgets(data, COMMAND_LEN, pf) == NULL)
    {
        std::cerr << "Board ID data is null, errno: " << errno << "message: " << strerror(errno) << "\n";
        return false;
    }

    // the data is now in 'data'
    if (pclose(pf) != 0)
    {
        std::cerr << " Error: Failed to close command stream\n";
        return false;
    }
    std::string board_id(data);
    if((board_id.compare("3D") == 0) || (board_id.compare("40") == 0) || (board_id.compare("41") == 0)
        || (board_id.compare("42") == 0) || (board_id.compare("52") == 0))
    {
        BoardName = "Onyx";
        return true;
    }
    if((board_id.compare("3E") == 0 ) || (board_id.compare("43") == 0) || (board_id.compare("44") ==0)
        || (board_id.compare("45") == 0) || (board_id.compare("51") == 0))
    {
        BoardName = "Quartz";
        return true;
    }
    if((board_id.compare("46")== 0) || (board_id.compare("47") == 0) || (board_id.compare("48") == 0))
    {
        BoardName = "Ruby";
        return true;
    }
    if((board_id.compare("49") == 0 ) || (board_id.compare("4A") == 0) || (board_id.compare("4B") == 0)
        || (board_id.compare("4C") == 0) || (board_id.compare("4D") == 0) || (board_id.compare("4E") == 0))
    {
        BoardName = "Titanite";
        return true;
    }

    return false;
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
        std::cerr << "Failed to find the " << name << " line\n";
        return false;
    }

    try
    {
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES});
    }
    catch (std::exception& exc)
    {
        std::cerr << "Failed to request events for " << name << exc.what() << "\n";
        return false;
    }

    int gpioLineFd = gpioLine.event_get_fd();
    if (gpioLineFd < 0)
    {
        std::cerr << "Failed to get " << name << " fd\n";
        return false;
    }

    gpioEventDescriptor.assign(gpioLineFd);

    gpioEventDescriptor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [&name, handler](const boost::system::error_code ec) {
            if (ec)
            {
                std::cerr << name << " fd handler error: " << ec.message()
                          << "\n";
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
        std::cerr << "Failed to find the " << name << " line.\n";
        return false;
    }

    try
    {
        gpioLine.request({__FUNCTION__, gpiod::line_request::DIRECTION_OUTPUT});
    }
    catch (std::system_error& exc)
    {
        std::cerr << "Error setting gpio as Output: " << name << exc.what() << "\n";
    }

    try
    {
        // Request GPIO output to specified value
        gpioLine.set_value(value);
    }
    catch (std::exception& exc)
    {
        std::cerr << "Failed to set value for " << name << exc.what()<< "\n";
        return false;
    }


    std::cerr << name << " set to " << std::to_string(value) << "\n";

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

static void P0_apmlAlertHandler()
{
    gpiod::line_event gpioLineEvent = P0_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        std::cerr << "P0 APML Alert received\n";

        harvest_ras_errors(p0_info,"P0_ALERT");

    }
}

static void P1_apmlAlertHandler()
{
    gpiod::line_event gpioLineEvent = P1_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        std::cerr << "P1 APML Alert received\n";
        harvest_ras_errors(p1_info,"P1_ALERT");
    }
}

/* Schedule a wait event */
static void scheduleP0AlertEventHandler()
{
    P0_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                std::cerr << "P0 APML alert handler error: "
                          << ec.message() << std::endl;
                return;
            }
            P0_apmlAlertHandler();
        });
}

static void scheduleP1AlertEventHandler()
{

    P1_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code& ec) {
            if (ec)
            {
                std::cerr << "P1 APML alert handler error: "
                                          << ec.message() << std::endl;
                return;
            }
            P1_apmlAlertHandler();
        });
}

bool harvest_ras_errors(struct i2c_info info,std::string alert_name)
{
    uint16_t n = 0;
    uint16_t retries = 0;
    uint16_t bytespermca;
    uint16_t maxOffset32;
    uint16_t numbanks = 0;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_ERR;
    FILE *file;
    std::string filePath;
    uint8_t buf;

    std::cerr << "read_bmc_ras_mca_validity_check" << std::endl;

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_bmc_ras_mca_validity_check(info, &bytespermca, &numbanks);

        if (retries > MAX_RETRIES)
        {
            std::cerr << "Failed to get MCA banks with valid status Error :" << ret << std::endl;
            break;
        }

        if (numbanks == 0)
        {
            std::cerr << "Invalid MCA bank data. Retry Count = " << retries << std::endl;
            ret = OOB_MAILBOX_ERR;
            continue;
        }
    }


    filePath = "/var/lib/amd-ras/ras-error" + std::to_string(err_count) + ".txt";
    err_count++;

    file = fopen(filePath.c_str(), "w");

    maxOffset32 = ((bytespermca % 4) ? 1 : 0) + (bytespermca >> 2);
    std::cerr << "Number of Valid MCA bank:" << numbanks << " Bytes per MCA:" << bytespermca << std::endl;
    std::cerr << "Harvesting RAS Errors ...MAX 32 Bit Words:" << maxOffset32 << std::endl;

    while(n < numbanks)
    {
        fprintf(file, "MCA bank Number: 0x%x\n", n);

        for (int offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&mca_dump, 0, sizeof(mca_dump));
            mca_dump.index  = n;
            mca_dump.offset = offset * 4;

            ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

            if (ret != OOB_SUCCESS)
            {
                std::cerr << "Failed to get MCA bank data from Bank =" << n << "Offset Addr =" << offset << std::endl;
                continue;
            }

            fprintf(file, "Offset: 0x%x\n", mca_dump.offset);
            fprintf(file, "buffer: 0x%x\n", buffer);
        }
        fprintf(file, "______________________\n");
        n++;
    }
    fclose(file);

    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {

    	if ((buf & 0x04))
    	{
    		setGPIOValue("ASSERT_RST_BTN_L", 0, resetPulseTimeMs);
    		std::cerr << "ASSERT_RST_BTN_L triggered" << std::endl;

    	}
    	else {
    		setGPIOValue("ASSERT_WARM_RST_BTN_L", 0, resetPulseTimeMs);
    		std::cerr << "ASSERT_WARM_RST_BTN_L triggered" << std::endl;

    	}
    }


    if(alert_name.compare("P0_ALERT")   == 0 ) {
        scheduleP0AlertEventHandler();
    }

    if(alert_name.compare("P1_ALERT")   == 0 ) {
        scheduleP1AlertEventHandler();
    }

    return true;
}

int main() {

    int dir;
    struct stat buffer;
    std::string ras_dir = "/var/lib/amd-ras/";

    if(getPlatformID() == false)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Couldnt find the board id of the platform");
        return false;
    }

    if (stat(ras_dir.c_str(), &buffer) != 0) {
        dir = mkdir("/var/lib/amd-ras",0777);

        if(dir) {
            phosphor::logging::log<phosphor::logging::level::INFO>
                ("ras-errror-logging directory not created");
        }
    }

    conn = std::make_shared<sdbusplus::asio::connection>(io);

    requestGPIOEvents("P0_I3C_APML_ALERT_L", P0_apmlAlertHandler, P0_apmlAlertLine, P0_apmlAlertEvent);

    if( (BoardName.compare("Quartz")   == 0 )  ||
        (BoardName.compare("Titanite") == 0 ))
    {

        requestGPIOEvents("P1_I3C_APML_ALERT_L", P1_apmlAlertHandler, P1_apmlAlertLine, P1_apmlAlertEvent);
    }

    io.run();

    return 0;
}

