#include "interface_manager_base.hpp"

#include <fstream>

constexpr int COMMAND_LEN = 3;
constexpr int SYS_MGMT_CTRL_ERR = 0x04;
constexpr char SRC_CONFIG_FILE[] = "/usr/share/ras-config/ras_config.json";
constexpr char INVENTORY_SERVICE[] = "xyz.openbmc_project.Inventory.Manager";
constexpr char CPU_INVENTORY_INTERFACE[] =
    "xyz.openbmc_project.Inventory.Item.Cpu";
constexpr char COMMAND_NUM_OF_CPU[] = "/sbin/fw_printenv -n num_of_cpu";
static const std::string COMMAND_BOARD_ID = "/sbin/fw_printenv -n board_id";

void RasManagerBase::getNumberOfCpu()
{
    FILE* pf;
    char data[COMMAND_LEN];
    std::stringstream ss;

    pf = popen(COMMAND_NUM_OF_CPU, "r");
    if (pf)
    {
        if (fgets(data, COMMAND_LEN, pf))
        {
            numOfCpu = std::stoi(data);

            lg2::info("Number of Cpu: {CPU}", "CPU", numOfCpu);
            cpuId = new CpuId[numOfCpu];

            uCode = new uint32_t[numOfCpu];
            std::memset(uCode, 0, numOfCpu * sizeof(uint32_t));

            ppin = new uint64_t[numOfCpu];
            std::memset(ppin, 0, numOfCpu * sizeof(uint64_t));

            inventoryPath = new std::string[numOfCpu];

            for (int i = 0; i < numOfCpu; i++)
            {
                inventoryPath[i] =
                    "/xyz/openbmc_project/inventory/system/processor/P" +
                    std::to_string(i);
            }
        }
        else
        {
            throw std::runtime_error("Error reading data from the process.");
        }
        pclose(pf);
    }
    else
    {
        throw std::runtime_error("Error opening the process.");
    }
}

void RasManagerBase::getBoardId()
{
    FILE* pf;
    char data[COMMAND_LEN];
    std::stringstream ss;

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID.data(), "r");
    // Error handling
    if (pf)
    {
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> boardId;

            lg2::debug("Board ID: {BOARD_ID}", "BOARD_ID", boardId);
        }
        // the data is now in 'data'
        pclose(pf);
    }
}

void RasManagerBase::createIndexFile()
{
    try
    {
        struct stat buffer;

        // Create the RAS directory if it doesn't exist
        if (stat(RAS_DIR, &buffer) != 0)
        {
            if (mkdir(RAS_DIR, 0777) != 0)
            {
                throw std::runtime_error(
                    "Failed to create ras-error-logging directory");
            }
        }

        memset(&buffer, 0, sizeof(buffer));

        // Create or read the index file
        if (stat(INDEX_FILE, &buffer) != 0)
        {
            std::ofstream file(INDEX_FILE);
            if (file.is_open())
            {
                file << "0";
                file.close();
            }
            else
            {
                throw std::runtime_error("Failed to create index file");
            }
        }
        else
        {
            std::ifstream file(INDEX_FILE);
            if (file.is_open())
            {
                if (!(file >> errCount) || errCount < INDEX_0)
                {
                    throw std::runtime_error(
                        "Failed to read CPER index number");
                }
                file.close();
            }
            else
            {
                throw std::runtime_error("Failed to read from index file");
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERROR}", "ERROR", e.what());
    }
}

void RasManagerBase::createConfigFile()
{
    struct stat buffer;

    /*Create Cdump Config file to store the system recovery*/
    if (stat(CONFIG_FILE, &buffer) != 0)
    {
        std::string copyCommand =
            std::string("cp ") + SRC_CONFIG_FILE + " " + CONFIG_FILE;

        int result = system(copyCommand.c_str());
        if (result != 0)
        {
            lg2::error("Error copying RAS config file.");
        }
    }

    std::ifstream jsonRead(CONFIG_FILE);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    ConfigTable configMap;

    for (const auto& item : data["Configuration"])
    {
        AttributeType attributeType;
        std::string key;
        std::string description;
        std::variant<bool, std::string, int64_t, std::vector<std::string>,
                     std::map<std::string, std::string>>
            value;
        int64_t maxBoundValue = 0;

        if (item.is_object() && item.size() == 1)
        {
            key = item.begin().key();

            const auto& obj = item[key];
            description = obj["Description"];
            if (value.index() == 0)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::Boolean;
            }
            else if (value.index() == 1)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::String;
            }
            else if (value.index() == 2)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::Integer;
            }
            else if (value.index() == 3)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::ArrayOfStrings;
            }
            else if (value.index() == 4)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::KeyValueMap;
            }

            // Determine the type of the value and construct the std::variant
            // accordingly
            if (obj["Value"].is_boolean())
            {
                value = obj["Value"].get<bool>();
            }
            else if (obj["Value"].is_string())
            {
                value = obj["Value"].get<std::string>();
            }
            else if (obj["Value"].is_number_integer())
            {
                value = obj["Value"].get<int64_t>();
            }
            else if (obj["Value"].is_array())
            {
                value = obj["Value"].get<std::vector<std::string>>();
            }
            else if (obj["Value"].is_object())
            {
                value = obj["Value"].get<std::map<std::string, std::string>>();
            }
        }

        configMap[key] =
            std::make_tuple(attributeType, description, value, maxBoundValue);
    }

    rasConfigTable(configMap);

    jsonRead.close();
}

void RasManagerBase::getMicrocodeRev()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    for (int i = 0; i < numOfCpu; i++)
    {
        std::string microCode = getProperty<std::string>(
            bus, INVENTORY_SERVICE, inventoryPath[i].c_str(),
            CPU_INVENTORY_INTERFACE, "Microcode");

        if (microCode.empty())
        {
            lg2::error("Failed to read ucode revision");
        }
        else
        {
            uCode[i] = std::stoul(microCode, nullptr, BASE_16);
        }
    }
}

void RasManagerBase::getPpinFuse()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    for (int i = 0; i < numOfCpu; i++)
    {
        std::string Ppin = getProperty<std::string>(
            bus, INVENTORY_SERVICE, inventoryPath[i].c_str(),
            CPU_INVENTORY_INTERFACE, "PPIN");

        if (Ppin.empty())
        {
            lg2::error("Failed to read ppin");
        }
        else
        {
            ppin[i] = std::stoul(Ppin, nullptr, BASE_16);
        }
    }
}

template <typename T>
T RasManagerBase::getProperty(sdbusplus::bus::bus& bus, const char* service,
                              const char* path, const char* interface,
                              const char* propertyName)
{
    auto method = bus.new_method_call(service, path,
                                      "org.freedesktop.DBus.Properties", "Get");
    method.append(interface, propertyName);
    std::variant<T> value{};
    try
    {
        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        lg2::info("GetProperty call failed");
    }
    return std::get<T>(value);
}

void RasManagerBase::requestGPIOEvents(
    const std::string& name, const std::function<void()>& handler,
    gpiod::line& gpioLine,
    boost::asio::posix::stream_descriptor& gpioEventDescriptor)
{
    try
    {
        // Find the GPIO line
        gpioLine = gpiod::find_line(name);
        if (!gpioLine)
        {
            throw std::runtime_error("Failed to find GPIO line: " + name);
        }

        // Request events for the GPIO line
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES, INDEX_0});

        // Get the GPIO line file descriptor
        int gpioLineFd = gpioLine.event_get_fd();
        if (gpioLineFd < 0)
        {
            throw std::runtime_error(
                "Failed to get GPIO line file descriptor: " + name);
        }

        // Assign the file descriptor to gpioEventDescriptor
        gpioEventDescriptor.assign(gpioLineFd);

        // Set up asynchronous wait for events
        gpioEventDescriptor.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [&name, handler](const boost::system::error_code ec) {
                if (ec)
                {
                    throw std::runtime_error(
                        "Error in fd handler: " + ec.message());
                }
                handler();
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERROR}", "ERROR", e.what());
    }
}

void RasManagerBase::p0AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = p0_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        lg2::debug("Falling Edge: P0 APML Alert received");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<FatalCperRecord>();
        }

        harvestFatalError(SOCKET_0);
    }
    p0_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("P0 APML alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            p0AlertEventHandler();
        });
}

void RasManagerBase::p1AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = p1_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        lg2::debug("Falling Edge: P1 APML Alert received");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<FatalCperRecord>();
        }

        harvestFatalError(SOCKET_1);
    }
    p1_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("P1 APML alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            p1AlertEventHandler();
        });
}

void RasManagerBase::rasRecoveryAction(uint8_t buf)
{
    AttributeValue SystemRecoveryVal = getAttribute("SystemRecovery");
    std::string* SystemRecovery = std::get_if<std::string>(&SystemRecoveryVal);

    if (*SystemRecovery == "WARM_RESET")
    {
        if ((buf & SYS_MGMT_CTRL_ERR))
        {
            triggerColdReset();
        }
        else
        {
            triggerWarmReset();
        }
    }
    else if (*SystemRecovery == "COLD_RESET")
    {
        triggerColdReset();
    }
    else if (*SystemRecovery == "NO_RESET")
    {
        lg2::info("NO RESET triggered");
    }
    else
    {
        lg2::error("CdumpResetPolicy is not valid");
    }
}

void RasManagerBase::triggerRsmrstReset()
{
    boost::system::error_code ec;
    boost::asio::io_context io_conn;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io_conn);

    conn->async_method_call(
        [](boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(
                    LOG_ERR, "Failed to trigger cold reset of the system\n");
            }
        },
        "xyz.openbmc_project.State.Host",
        "/xyz/openbmc_project/control/host0/SOCReset",
        "xyz.openbmc_project.Control.Host.SOCReset", "SOCReset");

    sleep(1);
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string CurrentHostState = getProperty<std::string>(
        bus, "xyz.openbmc_project.State.Host",
        "/xyz/openbmc_project/state/host0", "xyz.openbmc_project.State.Host",
        "CurrentHostState");

    if (CurrentHostState.compare(
            "xyz.openbmc_project.State.Host.HostState.Off") == 0)
    {
        std::string command = "xyz.openbmc_project.State.Host.Transition.On";
        requestHostTransition(command);
    }
}

void RasManagerBase::requestHostTransition(std::string command)
{
    boost::system::error_code ec;
    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->async_method_call(
        [](boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(
                    LOG_ERR, "Failed to trigger cold reset of the system\n");
            }
        },
        "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.State.Host", "RequestedHostTransition",
        std::variant<std::string>{command});
}

void RasManagerBase::triggerSysReset()
{
    std::string command = "xyz.openbmc_project.State.Host.Transition.Reboot";

    requestHostTransition(command);
}

void RasManagerBase::triggerColdReset()
{
    AttributeValue ResetSignalVal = getAttribute("ResetSignal");
    std::string* ResetSignal = std::get_if<std::string>(&ResetSignalVal);

    if (*ResetSignal == "RSMRST")
    {
        sd_journal_print(LOG_INFO, "RSMRST RESET triggered\n");
        triggerRsmrstReset();
    }
    else if (*ResetSignal == "SYS_RST")
    {
        sd_journal_print(LOG_INFO, "SYS RESET triggered\n");
        triggerSysReset();
    }
}
RasManagerBase::~RasManagerBase()
{
    delete[] cpuId;
    delete[] uCode;
    delete[] ppin;
    delete[] inventoryPath;
}
