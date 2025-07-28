#include "apml_manager.hpp"

#include "config_manager.hpp"
#include "oem_cper.hpp"
#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "apml_alertl_uevent.h"
#include "esmi_cpuid_msr.h"
#include "esmi_rmi.h"
#include "linux/amd-apml.h"
}

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

namespace amd
{
namespace ras
{
namespace apml
{
constexpr size_t sbrmiControlRegister = 0x1;
constexpr size_t sysMgmtCtrlErr = 0x4;

constexpr size_t socket0 = 0;
constexpr size_t socket1 = 1;

constexpr uint32_t badData = 0xBAADDA7A;
constexpr size_t epycProgSegId = 0x1;
constexpr size_t fatalError = 1;
constexpr size_t resetHangErr = 0x2;

constexpr size_t pollingMode = 0;
constexpr size_t interruptMode = 1;
constexpr size_t mcaErr = 0;
constexpr size_t dramCeccErr = 1;
constexpr size_t pcieErr = 2;
constexpr size_t chipSelNumPos = 21;
constexpr size_t mcaErrOverflow = 8;
constexpr size_t dramCeccErrOverflow = 16;
constexpr size_t pcieErrOverflow = 32;
constexpr size_t base16 = 16;
constexpr size_t byteMask = 0xFF;

void writeOobRegister(uint8_t info, uint32_t reg, uint32_t value)
{
    oob_status_t ret;

    ret = esmi_oob_write_byte(info, reg, SBRMI, value);
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to write register: {REG}", "REG", lg2::hex, reg);
        return;
    }
    lg2::debug("Write to register {REGISTER} is successful", "REGISTER", reg);
}

oob_status_t readOobRegister(uint8_t info, uint32_t reg, uint8_t* value)
{
    oob_status_t ret;
    uint16_t retryCount = 10;

    while (retryCount > 0)
    {
        ret = esmi_oob_read_byte(info, reg, SBRMI, value);
        if (ret == OOB_SUCCESS)
        {
            break;
        }

        lg2::error("Failed to read register: {REGISTER} Retrying\n", "REGISTER",
                   lg2::hex, reg);
        sleep(1);
        retryCount--;
    }
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to read register: {REGISTER}\n", "REGISTER",
                   lg2::hex, reg);
    }

    return ret;
}

Manager::Manager(amd::ras::config::Manager& manager,
                 sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io) :
    amd::ras::Manager(manager), objectServer(objectServer),
    systemBus(systemBus), progId(1), recordId(1), watchdogTimerCounter(0),
    io(io), apmlInitialized(false), platformInitialized(false),
    runtimeErrPollingSupported(false), p0AlertProcessed(false),
    p1AlertProcessed(false), McaErrorPollingEvent(nullptr),
    DramCeccErrorPollingEvent(nullptr), PcieAerErrorPollingEvent(nullptr),
    ApmlAlertEvent(nullptr), mcaErrorHarvestMtx(), dramErrorHarvestMtx(),
    pcieErrorHarvestMtx()
{}

void Manager::currentHostStateMonitor()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    boost::system::error_code ec;

    static auto match = sdbusplus::bus::match::match(
        bus,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Host'",
        [this](sdbusplus::message::message& message) {
            oob_status_t ret;
            std::string intfName;
            std::map<std::string, std::variant<std::string>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (std::exception& e)
            {
                lg2::info("Unable to read host state");
                return;
            }
            if (properties.empty())
            {
                lg2::error("ERROR: Empty PropertiesChanged signal received");
                return;
            }

            // We only want to check for currentHostState
            if (properties.begin()->first != "CurrentHostState")
            {
                return;
            }
            std::string* currentHostState =
                std::get_if<std::string>(&(properties.begin()->second));
            if (currentHostState == nullptr)
            {
                lg2::error("currentHostState Property invalid");
                return;
            }

            apmlInitialized = false;

            if (*currentHostState !=
                "xyz.openbmc_project.State.Host.HostState.Off")
            {
                lg2::info("Current host state monitor changed");
                uint32_t dataOut = 0;

                while (ret != OOB_SUCCESS)
                {
                    ret = get_bmc_ras_oob_config(0, &dataOut);

                    if (ret == OOB_SUCCESS)
                    {
                        platformInitialize();
                        watchdogTimerCounter = 0;
                        break;
                    }
                    sleep(1);
                }
            }
        });
}

void Manager::platformInitialize()
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    struct processor_info platInfo[1];

    if (platformInitialized == false)
    {
        while (ret != OOB_SUCCESS)
        {
            uint8_t socNum = 0;

            ret = esmi_get_processor_info(socNum, platInfo);

            if (ret == OOB_SUCCESS)
            {
                familyId = platInfo->family;
                break;
            }
            sleep(1);
        }

        if (ret == OOB_SUCCESS)
        {
            if ((platInfo->family == whFamilyId) &&
                (platInfo->model == whModel))
            {
                currentHostStateMonitor();
                for (size_t i = 0; i < cpuCount; i++)
                {
                    clearSbrmiAlertMask(i);
                }

                runTimeErrorPolling();

                runtimeErrPollingSupported = true;
            }
            else
            {
                throw std::runtime_error(std::format(
                    "This program is not supported for the family = 0x{:x} model = 0x{:x}\n",
                    platInfo->family, platInfo->model));
            }

            platformInitialized = true;
            apmlInitialized = true;
        }
        else
        {
            lg2::error("Failed to perform platform initialization");
        }
    }
    else
    {
        apmlInitialized = true;

        for (size_t i = 0; i < cpuCount; i++)
        {
            clearSbrmiAlertMask(i);
        }

        if (runtimeErrPollingSupported == true)
        {
            lg2::info("Setting MCA and DRAM OOB Config");

            setMcaOobConfig();

            lg2::info("Setting MCA and DRAM Error threshold");

            setMcaErrThreshold();
        }
    }
}

void Manager::mcaErrorPollingHandler(int64_t* pollingPeriod)
{
    amd::ras::config::Manager::AttributeValue mcaPolling =
        configMgr.getAttribute("McaPollingEn");
    bool* mcaPollingEn = std::get_if<bool>(&mcaPolling);
    if (*mcaPollingEn == true)
    {
        runTimeErrorInfoCheck(mcaErr, pollingMode);
    }
    if (McaErrorPollingEvent != nullptr)
    {
        delete McaErrorPollingEvent;
    }
    McaErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(*pollingPeriod));

    McaErrorPollingEvent->async_wait(
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("fd handler error failed: {MSG}", "MSG",
                           ec.message().c_str());
                return;
            }
            amd::ras::config::Manager::AttributeValue mcaPolling =
                configMgr.getAttribute("McaPollingPeriod");
            int64_t* mcaPollingPeriod = std::get_if<int64_t>(&mcaPolling);
            mcaErrorPollingHandler(mcaPollingPeriod);
        });
}

void Manager::dramCeccErrorPollingHandler(int64_t* pollingPeriod)
{
    amd::ras::config::Manager::AttributeValue dramCeccPolling =
        configMgr.getAttribute("DramCeccPollingEn");
    bool* dramCeccPollingEn = std::get_if<bool>(&dramCeccPolling);

    if (*dramCeccPollingEn == true)
    {
        runTimeErrorInfoCheck(dramCeccErr, pollingMode);
    }

    if (DramCeccErrorPollingEvent != nullptr)
        delete DramCeccErrorPollingEvent;

    DramCeccErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(*pollingPeriod));

    DramCeccErrorPollingEvent->async_wait(
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("fd handler error failed: {MSG}", "MSG",
                           ec.message().c_str());
                return;
            }

            amd::ras::config::Manager::AttributeValue dramCeccPolling =
                configMgr.getAttribute("DramCeccPollingPeriod");
            int64_t* dramCeccPollingPeriod =
                std::get_if<int64_t>(&dramCeccPolling);

            dramCeccErrorPollingHandler(dramCeccPollingPeriod);
        });
}

void Manager::pcieAerErrorPollingHandler(int64_t* pollingPeriod)
{
    amd::ras::config::Manager::AttributeValue pcieAerPolling =
        configMgr.getAttribute("PcieAerPollingEn");
    bool* pcieAerPollingEn = std::get_if<bool>(&pcieAerPolling);

    if (*pcieAerPollingEn == true)
    {
        runTimeErrorInfoCheck(pcieErr, pollingMode);
    }

    if (PcieAerErrorPollingEvent != nullptr)
        delete PcieAerErrorPollingEvent;

    PcieAerErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(*pollingPeriod));

    PcieAerErrorPollingEvent->async_wait(
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("fd handler error failed: {MSG}", "MSG",
                           ec.message().c_str());
                return;
            }

            amd::ras::config::Manager::AttributeValue pcieAerPolling =
                configMgr.getAttribute("PcieAerPollingPeriod");
            int64_t* pcieAerPollingPeriod =
                std::get_if<int64_t>(&pcieAerPolling);

            pcieAerErrorPollingHandler(pcieAerPollingPeriod);
        });
}

void Manager::init()
{
    lg2::info("APML MANAGER INIT");
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint32_t dataOut = 0;

    getCpuSocketInfo();

    // Try to copy the GPIO config file, throw exception if it fails
    try
    {
        std::filesystem::copy_file(
            SRC_GPIO_CONFIG_FILE, GPIO_CONFIG_FILE,
            std::filesystem::copy_options::overwrite_existing);
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        lg2::error("Failed to copy gpio config file : {ERROR}", "ERROR",
                   strerror(errno));
        throw std::runtime_error("Failed to copy gpio config file");
    }

    while (ret != OOB_SUCCESS)
    {
        ret = get_bmc_ras_oob_config(0, &dataOut);

        if (ret == OOB_MAILBOX_CMD_UNKNOWN)
        {
            ret = esmi_get_processor_info(0, plat_info);
        }
        sleep(1);
    }

    lg2::info("PLATFORM INIT");

    std::ifstream file("/var/lib/platform-config/platform.json");
    if (!file.is_open())
    {
        file.open(PLATFORM_DEFAULT_FILE);
    }

    nlohmann::json jsonData = nlohmann::json::parse(file);

    if (jsonData.contains("Model"))
    {
        std::string modelStr = jsonData["Model"];
        whModel = std::stoi(modelStr, nullptr, 16);
    }

    if (jsonData.contains("FamilyID"))
    {
        std::string familyIdStr = jsonData["FamilyID"];
        whFamilyId = std::stoi(familyIdStr, nullptr, 16);
    }

    if (jsonData.contains("DebugLogID"))
    {
        for (const auto& id : jsonData["DebugLogID"])
        {
            blockId.push_back(static_cast<uint8_t>(id));
        }
    }

    file.close();

    platformInitialize();

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    boost::system::error_code ec;

    static auto match = sdbusplus::bus::match::match(
        bus,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Watchdog'",
        [this](sdbusplus::message::message& message) {
            std::string intfName;
            std::map<std::string, std::variant<bool>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (std::exception& e)
            {
                lg2::error("Unable to read watchdog state");
                return;
            }
            if (properties.empty())
            {
                lg2::error("Empty PropertiesChanged signal received");
                return;
            }

            // We only want to check for currentHostState
            if (properties.begin()->first != "Enabled")
            {
                return;
            }

            bool* currentTimerEnable =
                std::get_if<bool>(&(properties.begin()->second));

            if (*currentTimerEnable == false)
            {
                sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
                std::string currentTimerUse =
                    amd::ras::util::getProperty<std::string>(
                        bus, "xyz.openbmc_project.Watchdog",
                        "/xyz/openbmc_project/watchdog/host0",
                        "xyz.openbmc_project.State.Watchdog",
                        "currentTimerUse");

                if (currentTimerUse ==
                    "xyz.openbmc_project.State.Watchdog.TimerUse.BIOSFRB2")
                {
                    watchdogTimerCounter++;

                    /*Watchdog Timer Enable property will be changed twice after
                      BIOS post complete. Platform initialization should be
                      performed only during the second property change*/
                    if (watchdogTimerCounter == 2)
                    {
                        lg2::info(
                            "BIOS post complete. Setting PCIE OOb config");
                        setPcieOobConfig();

                        lg2::info("Setting PCIE Error threshold");
                        setPcieErrThreshold();
                    }
                }
            }
        });

    /*Read CpuID*/
    for (size_t i = 0; i < cpuCount; i++)
    {
        uint32_t coreId = 0;
        oob_status_t ret;
        cpuId[i].eax = 1;
        cpuId[i].ebx = 0;
        cpuId[i].ecx = 0;
        cpuId[i].edx = 0;

        ret = esmi_oob_cpuid(i, coreId, &cpuId[i].eax, &cpuId[i].ebx,
                             &cpuId[i].ecx, &cpuId[i].edx);

        if (ret)
        {
            lg2::error("Failed to get the CPUID for socket {CPU}", "CPU", i);
        }
    }
}

void Manager::configure()
{
    std::vector<std::string> socketNames;
    amd::ras::util::cper::createRecord(objectServer, systemBus);

    std::ifstream jsonFile(GPIO_CONFIG_FILE);
    if (!jsonFile.is_open())
    {
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    nlohmann::json config;
    jsonFile >> config;
    jsonFile.close();

    if (config.contains("Alert_Config") && config["Alert_Config"].is_array())
    {
        for (const auto& entry : config["Alert_Config"])
        {
            if (entry.contains("AlertHandle"))
            {
                const auto& apmlAlertl = entry["AlertHandle"];

                if (apmlAlertl.contains("Value"))
                {
                    alertHandleMode = apmlAlertl["Value"].get<std::string>();
                    lg2::error("alertHandleMode {APMLALERTLFLAG}\n",
                               "APMLALERTLFLAG", alertHandleMode);
                }
            }
            if (alertHandleMode == "GPIO")
            {
                if (entry.contains("GPIO_ALERT_LINES") &&
                    (entry.contains("GPIO_ALERT_LINES")))
                {
                    lg2::error("Reading GPIO_ALERT_LINES\n");
                    socketNames = entry["GPIO_ALERT_LINES"]
                                      .get<std::vector<std::string>>();
                }
            }
        }
    }
    if (socketNames.empty() && (alertHandleMode == "GPIO"))
    {
        throw std::runtime_error(
            "Failed to read GPIO_ALERT_LINES from gpio_config.json file");
    }

    if (alertHandleMode != "UEVENT" && alertHandleMode != "GPIO")
    {
        throw std::runtime_error("Invalid mode of Alert handling");
    }

    if (alertHandleMode == "UEVENT")
    {
        ud.resize(cpuCount);
        for (size_t i = 0; i < cpuCount; ++i)
        {
            // Register for RAS alerts via APML API
            apml_register_udev_monitor(&ud[i]);
            if (!ud[i].udev)
            {
                lg2::error("Invalid udev device\n");
                return;
            }
            if (!ud[i].mon)
            {
                lg2::error("Invalid udev monitor\n");
                apml_unregister_udev_monitor(&ud[i]);
                return;
            }
            lg2::debug("Register to udev event is successful {CPU}\n", "CPU",
                       i);

            alertSrcHandler(&ud[i], i);
        }
    }
    else
    {
        gpioLines.resize(cpuCount);
        gpioEventDescriptors.reserve(cpuCount);

        for (size_t i = 0; i < cpuCount; ++i)
        {
            gpioEventDescriptors.emplace_back(io);

            requestGPIOEvents(socketNames[i],
                              std::bind(&ras::apml::Manager::alertEventHandler,
                                        this, std::ref(gpioEventDescriptors[i]),
                                        std::ref(gpioLines[i]), i),
                              gpioLines[i], gpioEventDescriptors[i]);
        }
    }
}

void Manager::releaseUdevReSrc()
{
    for (size_t i = 0; i < cpuCount; ++i)
    {
        apml_unregister_udev_monitor(&ud[i]);
    }
}

void Manager::clearSbrmiAlertMask(uint8_t socNum)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint8_t buffer;
    size_t retryCount = 10;

    while (retryCount > 0)
    {
        ret = esmi_oob_read_byte(socNum, sbrmiControlRegister, SBRMI, &buffer);
        if (ret == OOB_SUCCESS)
        {
            break;
        }

        lg2::error("Failed to read register: {REGISTER} Retrying\n", "REGISTER",
                   lg2::hex, sbrmiControlRegister);
        sleep(1);
        retryCount--;
    }
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to read register: {REGISTER}\n", "REGISTER",
                   lg2::hex, sbrmiControlRegister);
        return;
    }

    buffer = buffer & 0xBE;

    ret = esmi_oob_write_byte(socNum, sbrmiControlRegister, SBRMI, buffer);
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to write register: {REG}", "REG", lg2::hex,
                   sbrmiControlRegister);
        return;
    }

    lg2::debug("Write to register {REGISTER} is successful", "REGISTER",
               sbrmiControlRegister);

    for (size_t i = 0; i < sizeof(alert_status); i++)
    {
        ret = esmi_oob_read_byte(socNum, alert_status[i], SBRMI, &buffer);

        if (ret == OOB_SUCCESS)
        {
            if ((buffer & byteMask) != 0)
            {
                lg2::info(
                    "Socket {SOC} : MCE Stat of SBRMIx[0x{REG}] is set to 0x{DATA}",
                    "SOC", socNum, "REG", lg2::hex, alert_status[i], "DATA",
                    lg2::hex, buffer);

                buffer = buffer & byteMask;

                ret =
                    esmi_oob_write_byte(socNum, alert_status[i], SBRMI, buffer);

                if (ret != OOB_SUCCESS)
                {
                    lg2::error("Failed to write register: {REG}", "REG",
                               lg2::hex, alert_status[i]);
                    return;
                }
            }
        }
        else
        {
            lg2::info("Socket {SOC}: Failed to read SBRMIx[0x{REG}] ", "SOC",
                      socNum, "REG", lg2::hex, alert_status[i]);
        }
    }
}

void Manager::alertSrcHandler(struct apml_udev_monitor* udev_mon,
                              uint8_t socket)
{
    uint8_t soc_num = 0;
    uint32_t src = 0;
    bool block = false;
    oob_status_t ret;

    ret = monitor_ras_alert(udev_mon->mon, block, &soc_num, &src);
    if (ret == OOB_SUCCESS)
    {
        if (rcd == nullptr)
        {
            rcd = std::make_shared<FatalCperRecord>();
        }
        if (socket == soc_num)
        {
            decodeInterrupt(soc_num, src);
        }
    }
    else if (ret == OOB_FILE_ERROR || ret == OOB_INTERRUPTED)
    {
        lg2::error("Error monitoring the alertl udev events Err: {ERRNO}",
                   "ERRNO", ret);
        return;
    }

    ApmlAlertEvent =
        new boost::asio::deadline_timer(io, boost::posix_time::seconds(1));
    ApmlAlertEvent->async_wait(
        [this, udev_mon, socket](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("APML alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            alertSrcHandler(udev_mon, socket);
        });
}

void Manager::requestGPIOEvents(
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
        gpioLine.request({"RAS", gpiod::line_request::EVENT_BOTH_EDGES, 0});

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

void Manager::alertEventHandler(
    boost::asio::posix::stream_descriptor& apmlAlertEvent,
    const gpiod::line& alertLine, size_t socket)
{
    gpiod::line_event gpioLineEvent = alertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        lg2::debug("Falling Edge: APML Alert received");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<FatalCperRecord>();
        }

        decodeInterrupt(socket);
    }

    apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this, alertLine, socket, apmlAlertEventPtr = &apmlAlertEvent](
            const boost::system::error_code& ec) mutable {
            if (ec)
            {
                lg2::error("APML alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            alertEventHandler(*apmlAlertEventPtr, alertLine, socket);
        });
}

void Manager::harvestRuntimeErrors(uint8_t errorPollingType,
                                   struct ras_rt_valid_err_inst p0Inst,
                                   struct ras_rt_valid_err_inst p1Inst)
{
    uint32_t* severity = nullptr;
    uint64_t* checkInfo = nullptr;
    uint32_t highestSeverity;
    uint32_t sectionDesSize;
    uint32_t sectionSize;

    uint16_t sectionCount = p0Inst.number_of_inst + p1Inst.number_of_inst;

    severity = new uint32_t[sectionCount];
    checkInfo = new uint64_t[sectionCount];

    if (errorPollingType == mcaErr)
    {
        std::unique_lock lock(mcaErrorHarvestMtx);

        mcaPtr->SectionDescriptor =
            new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
        sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
        memset(mcaPtr->SectionDescriptor, 0, sectionDesSize);

        mcaPtr->McaErrorInfo = new RUNTIME_ERROR_INFO[sectionCount];
        sectionSize = sizeof(RUNTIME_ERROR_INFO) * sectionCount;
        memset(mcaPtr->McaErrorInfo, 0, sectionSize);

        uint16_t sectionStart = 0;

        if (p0Inst.number_of_inst != 0)
        {
            dumpProcErrorSection(mcaPtr, 0, p0Inst, mcaErr, sectionStart,
                                 severity, checkInfo);

            amd::ras::util::cper::dumpProcErrorInfoSection(
                mcaPtr, p0Inst.number_of_inst, checkInfo, sectionStart,
                cpuCount, cpuId);
        }
        if (p1Inst.number_of_inst != 0)
        {
            sectionStart = sectionCount - p1Inst.number_of_inst;

            dumpProcErrorSection(mcaPtr, 1, p1Inst, mcaErr, sectionStart,
                                 severity, checkInfo);
            amd::ras::util::cper::dumpProcErrorInfoSection(
                mcaPtr, p1Inst.number_of_inst, checkInfo, sectionStart,
                cpuCount, cpuId);
        }

        amd::ras::util::cper::calculateSeverity(
            severity, sectionCount, &highestSeverity, runtimeMcaErr);

        amd::ras::util::cper::dumpHeader(mcaPtr, sectionCount, highestSeverity,
                                         runtimeMcaErr, boardId, recordId);

        amd::ras::util::cper::dumpErrorDescriptor(
            mcaPtr, sectionCount, runtimeMcaErr, severity, progId);

        amd::ras::util::cper::createFile(mcaPtr, runtimeMcaErr, sectionCount,
                                         errCount);

        amd::ras::util::cper::exportToDBus(
            errCount - 1, mcaPtr->Header.TimeStamp, objectServer, systemBus);

        if (mcaPtr->SectionDescriptor != nullptr)
        {
            delete[] mcaPtr->SectionDescriptor;
            mcaPtr->SectionDescriptor = nullptr;
        }

        if (mcaPtr->McaErrorInfo != nullptr)
        {
            delete[] mcaPtr->McaErrorInfo;
            mcaPtr->McaErrorInfo = nullptr;
        }
    }
    else if (errorPollingType == dramCeccErr)
    {
        std::unique_lock lock(dramErrorHarvestMtx);

        dramPtr->SectionDescriptor =
            new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
        sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
        memset(dramPtr->SectionDescriptor, 0, sectionDesSize);

        dramPtr->McaErrorInfo = new RUNTIME_ERROR_INFO[sectionCount];
        sectionSize = sizeof(RUNTIME_ERROR_INFO) * sectionCount;
        memset(dramPtr->McaErrorInfo, 0, sectionSize);

        uint16_t sectionStart = 0;

        if (p0Inst.number_of_inst != 0)
        {
            dumpProcErrorSection(dramPtr, 0, p0Inst, dramCeccErr, sectionStart,
                                 severity, checkInfo);
            amd::ras::util::cper::dumpProcErrorInfoSection(
                dramPtr, p0Inst.number_of_inst, checkInfo, sectionStart,
                cpuCount, cpuId);
        }
        if (p1Inst.number_of_inst != 0)
        {
            sectionStart = sectionCount - p1Inst.number_of_inst;

            dumpProcErrorSection(mcaPtr, 1, p1Inst, dramCeccErr, sectionStart,
                                 severity, checkInfo);
            amd::ras::util::cper::dumpProcErrorInfoSection(
                mcaPtr, p1Inst.number_of_inst, checkInfo, sectionStart,
                cpuCount, cpuId);
        }

        amd::ras::util::cper::calculateSeverity(
            severity, sectionCount, &highestSeverity, runtimeDramErr);

        amd::ras::util::cper::dumpHeader(dramPtr, sectionCount, highestSeverity,
                                         runtimeDramErr, boardId, recordId);

        amd::ras::util::cper::dumpErrorDescriptor(
            dramPtr, sectionCount, runtimeDramErr, severity, progId);

        amd::ras::util::cper::createFile(dramPtr, runtimeDramErr, sectionCount,
                                         errCount);

        amd::ras::util::cper::exportToDBus(
            errCount - 1, dramPtr->Header.TimeStamp, objectServer, systemBus);

        if (dramPtr->SectionDescriptor != nullptr)
        {
            delete[] dramPtr->SectionDescriptor;
            dramPtr->SectionDescriptor = nullptr;
        }

        if (dramPtr->McaErrorInfo != nullptr)
        {
            delete[] dramPtr->McaErrorInfo;
            dramPtr->McaErrorInfo = nullptr;
        }
    }
    else if (errorPollingType == pcieErr)
    {
        std::unique_lock lock(pcieErrorHarvestMtx);

        pciePtr->SectionDescriptor =
            new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
        sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
        memset(pciePtr->SectionDescriptor, 0, sectionDesSize);

        pciePtr->PcieErrorData = new EFI_PCIE_ERROR_DATA[sectionCount];
        sectionSize = sizeof(EFI_PCIE_ERROR_DATA) * sectionCount;
        memset(pciePtr->PcieErrorData, 0, sectionSize);

        uint16_t sectionStart = 0;

        if (p0Inst.number_of_inst != 0)
        {
            dumpProcErrorSection(pciePtr, 0, p0Inst, pcieErr, sectionStart,
                                 severity, checkInfo);

            amd::ras::util::cper::dumpPcieErrorInfo(pciePtr, sectionStart,
                                                    p0Inst.number_of_inst);
        }
        if (p1Inst.number_of_inst != 0)
        {
            sectionStart = sectionCount - p1Inst.number_of_inst;

            dumpProcErrorSection(pciePtr, 0, p1Inst, pcieErr, sectionStart,
                                 severity, checkInfo);

            amd::ras::util::cper::dumpPcieErrorInfo(pciePtr, sectionStart,
                                                    p1Inst.number_of_inst);
        }

        amd::ras::util::cper::calculateSeverity(
            severity, sectionCount, &highestSeverity, runtimeDramErr);

        amd::ras::util::cper::dumpHeader(pciePtr, sectionCount, highestSeverity,
                                         runtimePcieErr, boardId, recordId);

        amd::ras::util::cper::dumpErrorDescriptor(
            pciePtr, sectionCount, runtimePcieErr, severity, progId);

        amd::ras::util::cper::createFile(pciePtr, runtimePcieErr, sectionCount,
                                         errCount);

        amd::ras::util::cper::exportToDBus(
            errCount - 1, pciePtr->Header.TimeStamp, objectServer, systemBus);

        if (pciePtr->SectionDescriptor != nullptr)
        {
            delete[] pciePtr->SectionDescriptor;
            pciePtr->SectionDescriptor = nullptr;
        }

        if (pciePtr->PcieErrorData != nullptr)
        {
            delete[] pciePtr->PcieErrorData;
            pciePtr->PcieErrorData = nullptr;
        }
    }

    if (checkInfo != nullptr)
    {
        delete[] checkInfo;
        checkInfo = nullptr;
    }

    if (severity != nullptr)
    {
        delete[] severity;
        severity = nullptr;
    }
}

oob_status_t Manager::runTimeErrValidityCheck(
    uint8_t socNum, struct ras_rt_err_req_type rt_err_category,
    struct ras_rt_valid_err_inst* inst)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    if (apmlInitialized == true)
    {
        ret =
            get_bmc_ras_run_time_err_validity_ck(socNum, rt_err_category, inst);
        if (ret)
        {
            lg2::debug("Failed to get bmc ras runtime error validity check");
        }
    }

    return ret;
}

void Manager::runTimeErrorInfoCheck(uint8_t errType, uint8_t reqType)
{
    struct ras_rt_valid_err_inst p0_inst, p1_inst;
    struct ras_rt_err_req_type rt_err_category;

    oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN;
    oob_status_t p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

    rt_err_category.err_type = errType;
    rt_err_category.req_type = reqType;

    memset(&p0_inst, 0, sizeof(p0_inst));
    memset(&p1_inst, 0, sizeof(p1_inst));

    p0_ret = runTimeErrValidityCheck(0, rt_err_category, &p0_inst);

    if (cpuCount == 2)
    {
        p1_ret = runTimeErrValidityCheck(1, rt_err_category, &p1_inst);
    }

    if (((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
        ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0)))
    {
        if (errType == mcaErr)
        {
            if (mcaPtr == nullptr)
            {
                mcaPtr = std::make_shared<McaRuntimeCperRecord>();
            }
            harvestRuntimeErrors(errType, p0_inst, p1_inst);
        }
        else if (errType == dramCeccErr)
        {
            if (reqType == pollingMode)
            {
                if (p0_inst.number_of_inst != 0)
                {
                    harvestDramCeccErrorCounters(p0_inst, 0);
                }
                if (p1_inst.number_of_inst != 0)
                {
                    harvestDramCeccErrorCounters(p1_inst, 1);
                }
            }
            else if (reqType == interruptMode)
            {
                if (dramPtr == nullptr)
                {
                    dramPtr = std::make_shared<McaRuntimeCperRecord>();
                }
                harvestRuntimeErrors(errType, p0_inst, p1_inst);
            }
        }
        else if (errType == pcieErr)
        {
            if (pciePtr == nullptr)
            {
                pciePtr = std::make_shared<PcieRuntimeCperRecord>();
            }
            harvestRuntimeErrors(errType, p0_inst, p1_inst);
        }
    }
}

void Manager::getLastTransAddr(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                               uint8_t socNum)
{
    oob_status_t ret;
    uint8_t blkId = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    ret = read_ras_df_err_validity_check(socNum, blkId, &err_chk);

    if (ret)
    {
        lg2::error("Failed to read RAS DF validity check");
    }
    else
    {
        if (err_chk.df_block_instances != 0)
        {
            maxOffset32 = ((err_chk.err_log_len % 4) ? 1 : 0) +
                          (err_chk.err_log_len >> 2);
            while (n < err_chk.df_block_instances)
            {
                for (uint32_t offset = 0; offset < maxOffset32; offset++)
                {
                    memset(&data, 0, sizeof(data));
                    /* Offset */
                    df_err.input[0] = offset * 4;
                    /* DF block ID */
                    df_err.input[1] = blkId;
                    /* DF block ID instance */
                    df_err.input[2] = n;

                    ret = read_ras_df_err_dump(socNum, df_err, &data);

                    fatalPtr->ErrorRecord[socNum]
                        .DfDumpData.LastTransAddr[n]
                        .WdtData[offset] = data;
                }
                n++;
            }
        }
    }
}

void Manager::harvestDebugLogDump(
    const std::shared_ptr<FatalCperRecord>& fatalPtr, uint8_t socNum,
    uint8_t blkId, int64_t* apmlRetryCount, uint16_t& debugLogIdOffset)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_ras_df_err_validity_check(socNum, blkId, &err_chk);

        if (ret == OOB_SUCCESS)
        {
            lg2::info(
                "Socket: {SOCKET},Debug Log ID : {DBG_ID} read successful",
                "SOCKET", socNum, "DBG_ID", blkId);
            break;
        }

        if (retries > *apmlRetryCount)
        {
            lg2::error("Socket: {SOCKET},Debug Log ID : {DBG_ID} read failed",
                       "SOCKET", socNum, "DBG_ID", blkId);

            /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE
             * dump region*/
            fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                blkId;
            fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                badData;
            fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                badData;
            fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                badData;

            break;
        }
    }
    if (ret == OOB_SUCCESS)
    {
        if (err_chk.df_block_instances != 0)
        {
            uint32_t debugLogIdHeader =
                (static_cast<uint32_t>(err_chk.err_log_len) << 16) |
                (static_cast<uint32_t>(err_chk.df_block_instances) << 8) |
                static_cast<uint32_t>(blkId);

            fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                debugLogIdHeader;

            maxOffset32 = ((err_chk.err_log_len % 4) ? 1 : 0) +
                          (err_chk.err_log_len >> 2);

            while (n < err_chk.df_block_instances)
            {
                bool apmlHang = false;

                for (uint32_t offset = 0; offset < maxOffset32; offset++)
                {
                    if (apmlHang == false)
                    {
                        memset(&data, 0, sizeof(data));
                        memset(&df_err, 0, sizeof(df_err));

                        /* Offset */
                        df_err.input[0] = offset * 4;
                        /* DF block ID */
                        df_err.input[1] = blkId;
                        /* DF block ID instance */
                        df_err.input[2] = n;

                        ret = read_ras_df_err_dump(socNum, df_err, &data);

                        if (ret != OOB_SUCCESS)
                        {
                            // retry
                            uint16_t retryCount = *apmlRetryCount;

                            while (retryCount > 0)
                            {
                                memset(&data, 0, sizeof(data));
                                memset(&df_err, 0, sizeof(df_err));

                                /* Offset */
                                df_err.input[0] = offset * 4;
                                /* DF block ID */
                                df_err.input[1] = blkId;
                                /* DF block ID instance */
                                df_err.input[2] = n;

                                ret =
                                    read_ras_df_err_dump(socNum, df_err, &data);

                                if (ret == OOB_SUCCESS)
                                {
                                    break;
                                }
                                retryCount--;
                                sleep(1);
                            }

                            if (ret != OOB_SUCCESS)
                            {
                                lg2::error("Failed to read debug log dump for "
                                           "debug log ID : {BLK_ID}",
                                           "BLK_ID", blkId);
                                data = badData;
                                /*the Dump APML command fails in the middle of
                                  the iterative loop, then write BAADDA7A for
                                  the remaining iterations in the for loop*/
                                apmlHang = true;
                            }
                        }
                    }

                    fatalPtr->ErrorRecord[socNum]
                        .DebugLogIdData[debugLogIdOffset++] = data;
                }
                n++;
            }
        }
    }
}

void Manager::harvestMcaDataBanks(uint8_t socNum,
                                  struct ras_df_err_chk errorCheck)
{
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    bool validSignatureId = false;

    uint32_t syndOffsetLo = 0;
    uint32_t syndOffsetHi = 0;
    uint32_t ipidOffsetLo = 0;
    uint32_t ipidOffsetHi = 0;
    uint32_t statusOffsetLo = 0;
    uint32_t statusOffsetHi = 0;

    uint32_t mcaStatusLo = 0;
    uint32_t mcaStatusHi = 0;
    uint32_t mcaIpidLo = 0;
    uint32_t mcaIpidHi = 0;
    uint32_t mcaSyndLo = 0;
    uint32_t mcaSyndHi = 0;

    amd::ras::config::Manager::AttributeValue sigIdOffsetVal =
        configMgr.getAttribute("SigIdOffset");
    std::vector<std::string>* sigIDOffset =
        std::get_if<std::vector<std::string>>(&sigIdOffsetVal);

    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    uint16_t sectionCount = 2;  // Standard section count is 2
    uint32_t errorSeverity = 1; // Error severity for fatal error is 1

    rcd->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    std::memset(rcd->SectionDescriptor, 0,
                2 * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));

    rcd->ErrorRecord = new EFI_AMD_FATAL_ERROR_DATA[sectionCount];
    std::memset(rcd->ErrorRecord, 0, 2 * sizeof(EFI_AMD_FATAL_ERROR_DATA));

    amd::ras::util::cper::dumpHeader(rcd, sectionCount, errorSeverity, fatalErr,
                                     boardId, recordId);
    amd::ras::util::cper::dumpErrorDescriptor(rcd, sectionCount, fatalErr,
                                              &errorSeverity, progId);
    amd::ras::util::cper::dumpProcessorError(rcd, socNum, cpuId, cpuCount,
                                             errorCheck.df_block_instances);
    amd::ras::util::cper::dumpContext(rcd, errorCheck.df_block_instances,
                                      errorCheck.err_log_len, socNum, ppin,
                                      uCode);

    uint8_t blkId;

    getLastTransAddr(rcd, socNum);

    uint16_t debugLogIdOffset = 0;
    union ras_df_err_dump dfError = {0};

    for (blkId = 0; blkId < blockId.size(); blkId++)
    {
        harvestDebugLogDump(rcd, socNum, blockId[blkId], apmlRetryCount,
                            debugLogIdOffset);
    }

    syndOffsetLo = std::stoul((*sigIDOffset)[0], nullptr, base16);
    syndOffsetHi = std::stoul((*sigIDOffset)[1], nullptr, base16);
    ipidOffsetLo = std::stoul((*sigIDOffset)[2], nullptr, base16);
    ipidOffsetHi = std::stoul((*sigIDOffset)[3], nullptr, base16);
    statusOffsetLo = std::stoul((*sigIDOffset)[4], nullptr, base16);
    statusOffsetHi = std::stoul((*sigIDOffset)[5], nullptr, base16);

    maxOffset32 = ((errorCheck.err_log_len % 4) ? 1 : 0) +
                  (errorCheck.err_log_len >> 2);

    uint16_t blockInstances = errorCheck.df_block_instances;

    lg2::info("Number of Valid MCA bank: {NUMBANKS}", "NUMBANKS",
              blockInstances);
    lg2::info("Number of 32 Bit Words:{MAX_OFFSET}", "MAX_OFFSET", maxOffset32);

    while (n < errorCheck.df_block_instances)
    {
        for (uint32_t offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&dfError, 0, sizeof(dfError));
            /* Offset */
            dfError.input[0] = offset * 4;
            /* DF block ID */
            dfError.input[1] = 32;
            /* DF block ID instance */
            dfError.input[2] = n;

            ret = read_ras_df_err_dump(socNum, dfError, &buffer);

            if (ret != OOB_SUCCESS)
            {
                while (*apmlRetryCount > 0)
                {
                    memset(&buffer, 0, sizeof(buffer));
                    memset(&dfError, 0, sizeof(dfError));
                    /* Offset */
                    dfError.input[0] = offset * 4;
                    /* DF block ID */
                    dfError.input[1] = 32;
                    /* DF block ID instance */
                    dfError.input[2] = n;

                    ret = read_ras_df_err_dump(socNum, dfError, &buffer);

                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    (*apmlRetryCount)--;
                    sleep(1);
                }
                if (ret != OOB_SUCCESS)
                {
                    lg2::error("Socket {SOCKET} : Failed to get MCA bank data "
                               "from Bank:{N}, Offset:{OFFSET}",
                               "SOCKET", socNum, "N", n, "OFFSET", lg2::hex,
                               offset);
                    rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[offset] =
                        badData; // Write BAADDA7A pattern on error
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[offset] = buffer;

            if (dfError.input[0] == statusOffsetLo)
            {
                mcaStatusLo = buffer;
            }
            if (dfError.input[0] == statusOffsetHi)
            {
                mcaStatusHi = buffer;

                /*Bit 23 and bit 25 of MCA_STATUS_HI
                  should be set for a valid signature ID*/
                if ((mcaStatusHi & (1 << 25)) && (mcaStatusHi & (1 << 23)))
                {
                    validSignatureId = true;
                }
            }
            if (dfError.input[0] == ipidOffsetLo)
            {
                mcaIpidLo = buffer;
            }
            if (dfError.input[0] == ipidOffsetHi)
            {
                mcaIpidHi = buffer;
            }
            if (dfError.input[0] == syndOffsetLo)
            {
                mcaSyndLo = buffer;
            }
            if (dfError.input[0] == syndOffsetHi)
            {
                mcaSyndHi = buffer;
            }

        } // for loop

        if (validSignatureId == true)
        {
            rcd->ErrorRecord[socNum].SignatureID[0] = mcaSyndLo;
            rcd->ErrorRecord[socNum].SignatureID[1] = mcaSyndHi;
            rcd->ErrorRecord[socNum].SignatureID[2] = mcaIpidLo;
            rcd->ErrorRecord[socNum].SignatureID[3] = mcaIpidHi;
            rcd->ErrorRecord[socNum].SignatureID[4] = mcaStatusLo;
            rcd->ErrorRecord[socNum].SignatureID[5] = mcaStatusHi;

            rcd->ErrorRecord[socNum].ProcError.ValidFields =
                rcd->ErrorRecord[socNum].ProcError.ValidFields | 0x4;

            validSignatureId = false;
        }
        else
        {
            mcaSyndLo = 0;
            mcaSyndHi = 0;
            mcaIpidLo = 0;
            mcaIpidHi = 0;
            mcaStatusLo = 0;
            mcaStatusHi = 0;
        }
        n++;
    }
}

bool Manager::harvestMcaValidityCheck(uint8_t info,
                                      struct ras_df_err_chk* errorCheck)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    bool mcaValidityCheck = true;
    uint8_t mcaDebugLogId = 32;

    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_ras_df_err_validity_check(info, mcaDebugLogId, errorCheck);

        if (retries > *apmlRetryCount)
        {
            lg2::error(
                "Socket {SOCK}: Failed to get MCA debug log ID with valid status",
                "SOCK", info);
            break;
        }

        if ((errorCheck->df_block_instances == 0) ||
            (errorCheck->df_block_instances > 32))
        {
            lg2::error("Socket {SOCKET}: Invalid MCA bank validity status. "
                       "Retry Count: {RETRY_COUNT}",
                       "SOCKET", info, "RETRY_COUNT", retries);
            ret = OOB_MAILBOX_CMD_UNKNOWN;
            sleep(1);
            continue;
        }
    }

    if ((errorCheck->df_block_instances <= 0) ||
        (errorCheck->df_block_instances > 32))
    {
        mcaValidityCheck = false;
    }

    return mcaValidityCheck;
}

bool Manager::decodeInterrupt(uint8_t socNum, uint32_t src)
{
    std::unique_lock lock(harvestMutex);
    struct ras_df_err_chk errorCheck;
    bool fchHangError = false;
    bool controlFabricError = false;
    bool resetReady = false;
    bool runtimeError = false;
    bool nonMcaShutdownError = false;

    // check RAS Status Register
    if (src & 0xFF)
    {
        lg2::error("The alert signaled is due to a RAS fatal error");

        if (src & APML_RESET_CTRL_ALERT)
        {
            /*if RasStatus[reset_ctrl_err] is set in any of the processors,
              proceed to cold reset, regardless of the status of the other P
            */

            std::string rasErrMsg =
                "Fatal error detected in the control fabric. "
                "BMC may trigger a reset based on policy set. ";

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            rasErrMsg.c_str(), NULL);

            p0AlertProcessed = true;
            p1AlertProcessed = true;
            controlFabricError = true;
        }
        else if (src & APML_FCH_ALERT)
        {
            std::string rasErrMsg =
                "System hang while resetting in syncflood."
                "Suggested next step is to do an additional manual "
                "immediate reset";
            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            rasErrMsg.c_str(), NULL);

            fchHangError = true;
        }
        else if (src & APML_FATAL_ALERT)
        {
            std::string rasErrMsg;

            if (src & APML_CPU_SHUTDOWN_ALERT)
            {
                rasErrMsg =
                    "MCA CPU shutdown error detected."
                    "System may reset after harvesting MCA data based on policy set.";

                contextType = shutdown;
            }
            else
            {
                rasErrMsg = "RAS FATAL Error detected. "
                            "System may reset after harvesting "
                            "MCA data based on policy set. ";
                contextType = crashdump;
            }

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            rasErrMsg.c_str(), NULL);

            if (false == harvestMcaValidityCheck(socNum, &errorCheck))
            {
                lg2::info(
                    "No valid mca banks found. Harvesting additional debug log ID dumps");
            }
            harvestMcaDataBanks(socNum, errorCheck);
        }
        else if (src & APML_CPU_SHUTDOWN_ALERT)
        {
            std::string rasErrMsg =
                "Non MCA Shutdown error detected in the system";

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            rasErrMsg.c_str(), NULL);

            nonMcaShutdownError = true;
        }
        else if (src & APML_MCA_ALERT)
        {
            runTimeErrorInfoCheck(mcaErr, interruptMode);

            std::string mcaErrOverflowMsg =
                "MCA runtime error counter overflow occured";

            sd_journal_send("MESSAGE=%s", mcaErrOverflowMsg.c_str(),
                            "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            mcaErrOverflowMsg.c_str(), NULL);

            runtimeError = true;
        }
        else if (src & APML_DRAM_CECC_ALERT)
        {
            runTimeErrorInfoCheck(dramCeccErr, interruptMode);

            std::string dramErrOverlowMsg =
                "DRAM CECC runtime error counter overflow occured";

            sd_journal_send("MESSAGE=%s", dramErrOverlowMsg.c_str(),
                            "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            dramErrOverlowMsg.c_str(), NULL);

            runtimeError = true;
        }
        else if (src & APML_PCIE_ALERT)
        {
            runTimeErrorInfoCheck(pcieErr, interruptMode);

            std::string pcieErrOverlowMsg =
                "PCIE runtime error counter overflow occured";

            sd_journal_send("MESSAGE=%s", pcieErrOverlowMsg.c_str(),
                            "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            pcieErrOverlowMsg.c_str(), NULL);

            runtimeError = true;
        }

        if (socNum == socket0)
        {
            p0AlertProcessed = true;
        }

        if (socNum == socket1)
        {
            p1AlertProcessed = true;
        }

        if (fchHangError == true || runtimeError == true ||
            nonMcaShutdownError == true)
        {
            return true;
        }

        if (cpuCount == 2)
        {
            if ((p0AlertProcessed == true) && (p1AlertProcessed == true))
            {
                resetReady = true;
            }
        }
        else
        {
            resetReady = true;
        }
        if (resetReady == true)
        {
            if (controlFabricError == false)
            {
                amd::ras::util::cper::createFile(rcd, fatalErr, 2, errCount);

                amd::ras::util::cper::exportToDBus(errCount - 1,
                                                   rcd->Header.TimeStamp,
                                                   objectServer, systemBus);
            }

            bool recoveryAction = true;

            amd::ras::config::Manager::AttributeValue aifsArmed =
                configMgr.getAttribute("AifsArmed");
            bool* aifsArmedFlag = std::get_if<bool>(&aifsArmed);

            amd::ras::config::Manager::AttributeValue configSigId =
                configMgr.getAttribute("AifsSignatureIdList");
            std::map<std::string, std::string>* configSigIdList =
                std::get_if<std::map<std::string, std::string>>(&configSigId);

            if ((*aifsArmedFlag == true) &&
                (amd::ras::util::cper::checkSignatureIdMatch(configSigIdList,
                                                             rcd) == true))
            {
                lg2::info("AIFS armed for the system");

                std::ifstream inputFile(
                    "/home/root/bmcweb_persistent_data.json");

                /*Check if there is any active subscriptions for
                  the local AIFS flow*/
                if (inputFile.is_open())
                {
                    nlohmann::json jsonData;
                    inputFile >> jsonData;

                    if (jsonData.find("subscriptions") != jsonData.end())
                    {
                        lg2::info("Subscriptions found");
                        const auto& subscriptionsArray =
                            jsonData["subscriptions"];
                        if (subscriptionsArray.is_array())
                        {
                            for (const auto& subscription : subscriptionsArray)
                            {
                                const auto& messageIds =
                                    subscription["MessageIds"];
                                if (messageIds.is_array())
                                {
                                    bool messageIdFound = std::any_of(
                                        messageIds.begin(), messageIds.end(),
                                        [](const std::string& messageId) {
                                            return messageId ==
                                                   "AmdAifsFailureMatch";
                                        });
                                    if (messageIdFound)
                                    {
                                        recoveryAction = false;

                                        struct ras_override_delay dataIn = {
                                            0, 0, 0};
                                        bool ackResp;
                                        dataIn.stop_delay_counter = 1;
                                        oob_status_t ret;

                                        amd::ras::config::Manager::
                                            AttributeValue disableResetCounter =
                                                configMgr.getAttribute(
                                                    "DisableAifsResetOnSyncfloodCounter");
                                        bool* disableResetCntr =
                                            std::get_if<bool>(
                                                &disableResetCounter);

                                        if (*disableResetCntr == true)
                                        {
                                            lg2::info(
                                                "Disable Aifs Delay Reset on Syncflood counter is true. Sending Delay Reset on Syncflood override APML command");
                                            ret =
                                                override_delay_reset_on_sync_flood(
                                                    socNum, dataIn, &ackResp);

                                            if (ret)
                                            {
                                                lg2::error(
                                                    "Failed to override delay value reset on syncflood Err:{ERRNO}",
                                                    "ERRNO", ret);
                                            }
                                            else
                                            {
                                                lg2::info(
                                                    "Successfully sent Reset delay on Syncflood command");
                                            }
                                        }

                                        sd_journal_send(
                                            "PRIORITY=%i", LOG_INFO,
                                            "REDFISH_MESSAGE_ID=%s",
                                            "OpenBMC.0.1.AmdAifsFailureMatch",
                                            NULL);

                                        break;
                                    }
                                }
                            }
                        }
                    }
                    inputFile.close();
                }
            }
            if (recoveryAction == true)
            {
                amd::ras::config::Manager::AttributeValue ResetSignalVal =
                    configMgr.getAttribute("ResetSignalType");
                std::string* resetSignal =
                    std::get_if<std::string>(&ResetSignalVal);

                amd::ras::config::Manager::AttributeValue SystemRecoveryVal =
                    configMgr.getAttribute("SystemRecoveryMode");
                std::string* systemRecovery =
                    std::get_if<std::string>(&SystemRecoveryVal);
                amd::ras::util::rasRecoveryAction((uint8_t)src, systemRecovery,
                                                  resetSignal);
            }

            if (rcd->SectionDescriptor != nullptr)
            {
                delete[] rcd->SectionDescriptor;
                rcd->SectionDescriptor = nullptr;
            }
            if (rcd->ErrorRecord != nullptr)
            {
                delete[] rcd->ErrorRecord;
                rcd->ErrorRecord = nullptr;
            }

            rcd = nullptr;

            p0AlertProcessed = false;
            p1AlertProcessed = false;
        }
    }
    else
    {
        lg2::debug("Nothing to Harvest. Not RAS Error");
    }
    return true;
}

bool Manager::decodeInterrupt(uint8_t socNum)
{
    std::unique_lock lock(harvestMutex);
    struct ras_df_err_chk errorCheck;
    uint8_t buf;
    bool fchHangError = false;
    bool controlFabricError = false;
    bool resetReady = false;
    bool runtimeError = false;

    if (read_sbrmi_status(socNum, &buf) == OOB_SUCCESS)
    {
        lg2::debug("Socket {SOC}: Read status register. Value: 0x{BUF}", "SOC",
                   socNum, "BUF", buf);

        /*Check if Alert Status bit is set and clear AlertSts*/
        if (buf & 0x1)
        {
            std::string err_msg =
                "The APML_ALERT_L is asserted due to MCE error";
            sd_journal_send("MESSAGE=%s", err_msg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                            err_msg.c_str(), NULL);

            uint8_t buffer;
            oob_status_t ret;

            for (size_t i = 0; i < sizeof(alert_status); i++)
            {
                ret =
                    esmi_oob_read_byte(socNum, alert_status[i], SBRMI, &buffer);

                if (ret == OOB_SUCCESS)
                {
                    if ((buffer & byteMask) != 0)
                    {
                        lg2::info(
                            "Socket {SOC} : MCE Stat of SBRMIx[0x{REG}] is set to 0x{DATA}",
                            "SOC", socNum, "REG", lg2::hex, alert_status[i],
                            "DATA", lg2::hex, buffer);

                        buffer = buffer & byteMask;

                        ret = esmi_oob_write_byte(socNum, alert_status[i],
                                                  SBRMI, buffer);

                        if (ret != OOB_SUCCESS)
                        {
                            lg2::error("Failed to write register: {REG}", "REG",
                                       lg2::hex, alert_status[i]);
                        }
                    }
                }
                else
                {
                    lg2::info("Socket {SOC}: Failed to read SBRMIx[0x{REG}] ",
                              "SOC", socNum, "REG", lg2::hex, alert_status[i]);
                }
            }
        }
    }

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(socNum, &buf) == OOB_SUCCESS)
    {
        lg2::debug("Read RAS status register. Value: {BUF}", "BUF", buf);

        // check RAS Status Register
        if (buf & 0xFF)
        {
            lg2::error("The alert signaled is due to a RAS fatal error");

            if (buf & sysMgmtCtrlErr)
            {
                /*if RasStatus[reset_ctrl_err] is set in any of the processors,
                  proceed to cold reset, regardless of the status of the other P
                */

                std::string rasErrMsg =
                    "Fatal error detected in the control fabric. "
                    "BMC may trigger a reset based on policy set. ";

                sd_journal_send(
                    "MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

                p0AlertProcessed = true;
                p1AlertProcessed = true;
                controlFabricError = true;
            }
            else if (buf & resetHangErr)
            {
                std::string rasErrMsg =
                    "System hang while resetting in syncflood."
                    "Suggested next step is to do an additional manual "
                    "immediate reset";
                sd_journal_send(
                    "MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

                fchHangError = true;
            }
            else if (buf & fatalError)
            {
                std::string rasErrMsg = "RAS FATAL Error detected. "
                                        "System may reset after harvesting "
                                        "MCA data based on policy set. ";

                sd_journal_send(
                    "MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

                if (false == harvestMcaValidityCheck(socNum, &errorCheck))
                {
                    lg2::info(
                        "No valid mca banks found. Harvesting additional debug log ID dumps");
                }
                harvestMcaDataBanks(socNum, errorCheck);
            }
            else if (buf & mcaErrOverflow)
            {
                runTimeErrorInfoCheck(mcaErr, interruptMode);

                std::string mcaErrOverflowMsg =
                    "MCA runtime error counter overflow occured";

                sd_journal_send(
                    "MESSAGE=%s", mcaErrOverflowMsg.c_str(), "PRIORITY=%i",
                    LOG_ERR, "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", mcaErrOverflowMsg.c_str(), NULL);

                runtimeError = true;
            }
            else if (buf & dramCeccErrOverflow)
            {
                runTimeErrorInfoCheck(dramCeccErr, interruptMode);

                std::string dramErrOverlowMsg =
                    "DRAM CECC runtime error counter overflow occured";

                sd_journal_send(
                    "MESSAGE=%s", dramErrOverlowMsg.c_str(), "PRIORITY=%i",
                    LOG_ERR, "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", dramErrOverlowMsg.c_str(), NULL);

                runtimeError = true;
            }
            else if (buf & pcieErrOverflow)
            {
                runTimeErrorInfoCheck(pcieErr, interruptMode);

                std::string pcieErrOverlowMsg =
                    "PCIE runtime error counter overflow occured";

                sd_journal_send(
                    "MESSAGE=%s", pcieErrOverlowMsg.c_str(), "PRIORITY=%i",
                    LOG_ERR, "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", pcieErrOverlowMsg.c_str(), NULL);

                runtimeError = true;
            }

            if (socNum == socket0)
            {
                p0AlertProcessed = true;
            }

            if (socNum == socket1)
            {
                p1AlertProcessed = true;
            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in
            // implementation of SMU?

            writeOobRegister(socNum, 0x4C, buf);

            if (fchHangError == true || runtimeError == true)
            {
                return true;
            }
            if (cpuCount == 2)
            {
                if ((p0AlertProcessed == true) && (p1AlertProcessed == true))
                {
                    resetReady = true;
                }
            }
            else
            {
                resetReady = true;
            }
            if (resetReady == true)
            {
                if (controlFabricError == false)
                {
                    amd::ras::util::cper::createFile(rcd, fatalErr, 2,
                                                     errCount);

                    amd::ras::util::cper::exportToDBus(errCount - 1,
                                                       rcd->Header.TimeStamp,
                                                       objectServer, systemBus);
                }

                bool recoveryAction = true;

                amd::ras::config::Manager::AttributeValue aifsArmed =
                    configMgr.getAttribute("AifsArmed");
                bool* aifsArmedFlag = std::get_if<bool>(&aifsArmed);

                amd::ras::config::Manager::AttributeValue configSigId =
                    configMgr.getAttribute("AifsSignatureIdList");
                std::map<std::string, std::string>* configSigIdList =
                    std::get_if<std::map<std::string, std::string>>(
                        &configSigId);

                if ((*aifsArmedFlag == true) &&
                    (amd::ras::util::cper::checkSignatureIdMatch(
                         configSigIdList, rcd) == true))
                {
                    lg2::info("AIFS armed for the system");

                    std::ifstream inputFile(
                        "/home/root/bmcweb_persistent_data.json");

                    /*Check if there is any active subscriptions for
                      the local AIFS flow*/
                    if (inputFile.is_open())
                    {
                        nlohmann::json jsonData;
                        inputFile >> jsonData;

                        if (jsonData.find("subscriptions") != jsonData.end())
                        {
                            lg2::info("Subscriptions found");
                            const auto& subscriptionsArray =
                                jsonData["subscriptions"];
                            if (subscriptionsArray.is_array())
                            {
                                for (const auto& subscription :
                                     subscriptionsArray)
                                {
                                    const auto& messageIds =
                                        subscription["MessageIds"];
                                    if (messageIds.is_array())
                                    {
                                        bool messageIdFound = std::any_of(
                                            messageIds.begin(),
                                            messageIds.end(),
                                            [](const std::string& messageId) {
                                                return messageId ==
                                                       "AmdAifsFailureMatch";
                                            });
                                        if (messageIdFound)
                                        {
                                            recoveryAction = false;

                                            struct ras_override_delay dataIn = {
                                                0, 0, 0};
                                            bool ackResp;
                                            dataIn.stop_delay_counter = 1;
                                            oob_status_t ret;

                                            amd::ras::config::Manager::AttributeValue
                                                disableResetCounter =
                                                    configMgr.getAttribute(
                                                        "DisableAifsResetOnSyncfloodCounter");
                                            bool* disableResetCntr =
                                                std::get_if<bool>(
                                                    &disableResetCounter);

                                            if (*disableResetCntr == true)
                                            {
                                                lg2::info(
                                                    "Disable Aifs Delay Reset on Syncflood counter is true. Sending Delay Reset on Syncflood override APML command");
                                                ret =
                                                    override_delay_reset_on_sync_flood(
                                                        socNum, dataIn,
                                                        &ackResp);

                                                if (ret)
                                                {
                                                    lg2::error(
                                                        "Failed to override delay value reset on syncflood Err:{ERRNO}",
                                                        "ERRNO", ret);
                                                }
                                                else
                                                {
                                                    lg2::info(
                                                        "Successfully sent Reset delay on Syncflood command");
                                                }
                                            }

                                            sd_journal_send(
                                                "PRIORITY=%i", LOG_INFO,
                                                "REDFISH_MESSAGE_ID=%s",
                                                "OpenBMC.0.1.AmdAifsFailureMatch",
                                                NULL);

                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        inputFile.close();
                    }
                }
                if (recoveryAction == true)
                {
                    amd::ras::config::Manager::AttributeValue ResetSignalVal =
                        configMgr.getAttribute("ResetSignalType");
                    std::string* resetSignal =
                        std::get_if<std::string>(&ResetSignalVal);

                    amd::ras::config::Manager::AttributeValue
                        SystemRecoveryVal =
                            configMgr.getAttribute("SystemRecoveryMode");
                    std::string* systemRecovery =
                        std::get_if<std::string>(&SystemRecoveryVal);

                    amd::ras::util::rasRecoveryAction(buf, systemRecovery,
                                                      resetSignal);
                }

                if (rcd->SectionDescriptor != nullptr)
                {
                    delete[] rcd->SectionDescriptor;
                    rcd->SectionDescriptor = nullptr;
                }
                if (rcd->ErrorRecord != nullptr)
                {
                    delete[] rcd->ErrorRecord;
                    rcd->ErrorRecord = nullptr;
                }

                rcd = nullptr;

                p0AlertProcessed = false;
                p1AlertProcessed = false;
            }
        }
    }
    else
    {
        lg2::debug("Nothing to Harvest. Not RAS Error");
    }
    return true;
}

oob_status_t Manager::setRasOobConfig(struct oob_config_d_in oob_config)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    for (size_t i = 0; i < cpuCount; i++)
    {
        amd::ras::config::Manager::AttributeValue apmlRetry =
            configMgr.getAttribute("ApmlRetries");
        int64_t* retryCount = std::get_if<int64_t>(&apmlRetry);

        while (*retryCount > 0)
        {
            --(*retryCount);
            ret = set_bmc_ras_oob_config(i, oob_config);

            if (ret == OOB_SUCCESS || ret == OOB_MAILBOX_CMD_UNKNOWN)
            {
                break;
            }
            sleep(1);
        }

        if (ret == OOB_SUCCESS)
        {
            lg2::info(
                "BMC RAS oob configuration set successfully for the processor "
                "P{PROCESSOR}",
                "PROCESSOR", i);
        }
        else
        {
            lg2::error(
                "Failed to set BMC RAS OOB configuration for the processor "
                "P{PROCESSOR}",
                "PROCESSOR", i);
            break;
        }
    }

    return ret;
}

oob_status_t Manager::getOobRegisters(struct oob_config_d_in* oob_config)
{
    oob_status_t ret;
    uint32_t dataOut = 0;

    ret = get_bmc_ras_oob_config(0, &dataOut);

    if (ret)
    {
        sd_journal_print(LOG_INFO, "Failed to get ras oob configuration \n");
    }
    else
    {
        oob_config->core_mca_err_reporting_en =
            (dataOut >> MCA_ERR_REPORT_EN & 1);
        oob_config->dram_cecc_oob_ec_mode =
            (dataOut >> DRAM_CECC_OOB_EC_MODE & TRIBBLE_BITS);
        oob_config->pcie_err_reporting_en = (dataOut >> PCIE_ERR_REPORT_EN & 1);
        oob_config->mca_oob_misc0_ec_enable = (dataOut & 1);
    }
    return ret;
}

oob_status_t Manager::setMcaErrThreshold()
{
    oob_status_t ret = OOB_NOT_SUPPORTED;
    struct run_time_threshold th;

    memset(&th, 0, sizeof(th));

    amd::ras::config::Manager::AttributeValue mcaThreshold =
        configMgr.getAttribute("McaThresholdEn");

    bool* mcaThresholdEn = std::get_if<bool>(&mcaThreshold);

    if (*mcaThresholdEn == true)
    {
        th.err_type = 0; /*00 = MCA error type*/

        amd::ras::config::Manager::AttributeValue mcaErrThresholdCount =
            configMgr.getAttribute("McaErrThresholdCnt");

        int64_t* mcaErrThresholdCnt =
            std::get_if<int64_t>(&mcaErrThresholdCount);

        th.err_count_th = *mcaErrThresholdCnt;
        th.max_intrupt_rate = 1;

        struct oob_config_d_in oob_config;

        memset(&oob_config, 0, sizeof(oob_config));

        getOobRegisters(&oob_config);

        /* Core MCA Error Reporting Enable */
        oob_config.core_mca_err_reporting_en = 1;
        oob_config.mca_oob_misc0_ec_enable = 1;

        ret = setRasOobConfig(oob_config);

        if (ret == OOB_SUCCESS)
        {
            lg2::info("Setting MCA error threshold");
            ret = setRasErrThreshold(th);
        }
    }

    amd::ras::config::Manager::AttributeValue dramCeccThreshold =
        configMgr.getAttribute("DramCeccThresholdEn");
    bool* dramCeccThresholdEn = std::get_if<bool>(&dramCeccThreshold);

    if (*dramCeccThresholdEn == true)
    {
        th.err_type = 1; /*01 = DRAM CECC error type*/

        amd::ras::config::Manager::AttributeValue dramCeccErrThresholdCount =
            configMgr.getAttribute("DramCeccErrThresholdCnt");
        int64_t* dramCeccThresholdCnt =
            std::get_if<int64_t>(&dramCeccErrThresholdCount);

        th.err_count_th = *dramCeccThresholdCnt;
        th.max_intrupt_rate = 1;

        struct oob_config_d_in oob_config;

        memset(&oob_config, 0, sizeof(oob_config));

        getOobRegisters(&oob_config);

        oob_config.dram_cecc_oob_ec_mode = 1;
        oob_config.mca_oob_misc0_ec_enable = 1;

        ret = setRasOobConfig(oob_config);

        if (ret == OOB_SUCCESS)
        {
            lg2::info("Setting Dram Cecc Error threshold");
            ret = setRasErrThreshold(th);
        }
    }
    return ret;
}

void Manager::runTimeErrorPolling()
{
    oob_status_t ret;

    lg2::info("Setting MCA and DRAM OOB Config");

    ret = setMcaOobConfig();

    /*setMcaOobConfig is not supported for Genoa platform.
      Enable run time error polling only if SetMcaOobConfig command
      is supported for the platform*/
    if (ret != OOB_MAILBOX_CMD_UNKNOWN)
    {
        lg2::info("Setting PCIE OOB Config");

        setPcieOobConfig();

        lg2::info(
            "Starting seprate threads to perform runtime error polling as "
            "per user settings");

        amd::ras::config::Manager::AttributeValue mcaPolling =
            configMgr.getAttribute("McaPollingPeriod");
        int64_t* mcaPollingPeriod = std::get_if<int64_t>(&mcaPolling);

        amd::ras::config::Manager::AttributeValue dramCeccPolling =
            configMgr.getAttribute("DramCeccPollingPeriod");
        int64_t* dramCeccPollingPeriod = std::get_if<int64_t>(&dramCeccPolling);

        amd::ras::config::Manager::AttributeValue pcieAerPolling =
            configMgr.getAttribute("PcieAerPollingPeriod");
        int64_t* pcieAerPollingPeriod = std::get_if<int64_t>(&pcieAerPolling);

        mcaErrorPollingHandler(mcaPollingPeriod);

        dramCeccErrorPollingHandler(dramCeccPollingPeriod);

        pcieAerErrorPollingHandler(pcieAerPollingPeriod);
    }
    else
    {
        lg2::error("Runtime error polling is not supported for this platform");
        return;
    }

    ret = setMcaErrThreshold();

    if (ret == OOB_MAILBOX_CMD_UNKNOWN)
    {
        lg2::error(
            "Runtime error threshold is not supported for this platform");
    }
    else
    {
        setPcieErrThreshold();
    }
}

oob_status_t Manager::getRasOobConfig(struct oob_config_d_in* oob_config)
{
    oob_status_t ret;
    uint32_t dataOut = 0;

    ret = get_bmc_ras_oob_config(0, &dataOut);

    if (ret)
    {
        sd_journal_print(LOG_INFO, "Failed to get ras oob configuration \n");
    }
    else
    {
        oob_config->core_mca_err_reporting_en =
            (dataOut >> PCIE_ERR_REPORT_EN & 1);
        oob_config->dram_cecc_oob_ec_mode =
            (dataOut >> DRAM_CECC_OOB_EC_MODE & TRIBBLE_BITS);
        oob_config->pcie_err_reporting_en = (dataOut >> PCIE_ERR_REPORT_EN & 1);
        oob_config->mca_oob_misc0_ec_enable = (dataOut & 1);
    }
    return ret;
}

oob_status_t Manager::setMcaOobConfig()
{
    oob_status_t ret;
    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));

    amd::ras::config::Manager::AttributeValue mcaPolling =
        configMgr.getAttribute("McaPollingEn");
    bool* mcaPollingEn = std::get_if<bool>(&mcaPolling);

    amd::ras::config::Manager::AttributeValue dramCeccPolling =
        configMgr.getAttribute("DramCeccPollingEn");
    bool* dramCeccPollingEn = std::get_if<bool>(&dramCeccPolling);

    if (*mcaPollingEn == true)
    {
        /* Core MCA OOB Error Reporting Enable */
        oob_config.core_mca_err_reporting_en = 1;
    }

    if (*dramCeccPollingEn == true)
    {
        /* DRAM CECC OOB Error Counter Mode */
        oob_config.core_mca_err_reporting_en = 1;
        oob_config.dram_cecc_oob_ec_mode = 1; /*Enabled in No leak mode*/
    }

    ret = setRasOobConfig(oob_config);

    return ret;
}

oob_status_t Manager::setPcieOobRegisters()
{
    oob_status_t ret;
    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));
    getRasOobConfig(&oob_config);

    oob_config.pcie_err_reporting_en = 1;

    ret = setRasOobConfig(oob_config);
    return ret;
}

oob_status_t Manager::setPcieOobConfig()
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    amd::ras::config::Manager::AttributeValue PcieAerPolling =
        configMgr.getAttribute("PcieAerPollingEn");
    bool* PcieAerPollingEn = std::get_if<bool>(&PcieAerPolling);

    if (*PcieAerPollingEn == true)
    {
        ret = setPcieOobRegisters();
    }
    return ret;
}

oob_status_t Manager::setRasErrThreshold(struct run_time_threshold th)
{
    oob_status_t ret;

    for (size_t i = 0; i < cpuCount; i++)
    {
        amd::ras::config::Manager::AttributeValue apmlRetry =
            configMgr.getAttribute("ApmlRetries");
        int64_t* retryCount = std::get_if<int64_t>(&apmlRetry);

        while (*retryCount > 0)
        {
            --(*retryCount);
            ret = set_bmc_ras_err_threshold(i, th);

            if (ret != OOB_SUCCESS)
            {
                lg2::error("Failed to set error threshold for processor P0");
            }
            else
            {
                break;
            }

            sleep(1);
        }
    }
    return ret;
}

oob_status_t Manager::setPcieErrThreshold()
{
    oob_status_t ret = OOB_NOT_SUPPORTED;
    struct run_time_threshold th;

    memset(&th, 0, sizeof(th));

    amd::ras::config::Manager::AttributeValue pcieAerThreshold =
        configMgr.getAttribute("PcieAerThresholdEn");
    bool* pcieAerThresholdEn = std::get_if<bool>(&pcieAerThreshold);

    if (*pcieAerThresholdEn)
    {
        setPcieOobRegisters();

        th.err_type = 2; /*00 = PCIE error type*/

        amd::ras::config::Manager::AttributeValue pcieAerErrThresholdCount =
            configMgr.getAttribute("PcieAerErrThresholdCnt");
        int64_t* pcieAerErrThresholdCnt =
            std::get_if<int64_t>(&pcieAerErrThresholdCount);

        th.err_count_th = *pcieAerErrThresholdCnt;
        th.max_intrupt_rate = 1;

        lg2::info("Setting PCIE error threshold");

        ret = setRasErrThreshold(th);
    }
    return ret;
}

template <typename PtrType>
void Manager::dumpProcErrorSection(
    const std::shared_ptr<PtrType>& data, uint8_t socNum,
    struct ras_rt_valid_err_inst inst, uint8_t category, uint16_t section,
    uint32_t* Severity, uint64_t* CheckInfo)
{
    uint16_t n = 0;
    struct run_time_err_d_in dataIn;
    uint32_t dataOut = 0;
    uint64_t mcaStatusRegister = 0;
    uint32_t rootErrStatus = 0;
    uint32_t offset;
    oob_status_t ret;

    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    lg2::info("Harvesting errors for category {CATEGORY}", "CATEGORY",
              category);

    std::shared_ptr<McaRuntimeCperRecord> ProcPtr;
    std::shared_ptr<PcieRuntimeCperRecord> PciePtr;

    if constexpr (std::is_same_v<PtrType, McaRuntimeCperRecord>)
    {
        ProcPtr = std::static_pointer_cast<McaRuntimeCperRecord>(data);
    }
    else if constexpr (std::is_same_v<PtrType, PcieRuntimeCperRecord>)
    {
        PciePtr = std::static_pointer_cast<PcieRuntimeCperRecord>(data);
    }
    else
    {
        return;
    }

    while (n < inst.number_of_inst)
    {
        if (category ==
            1) // For Dram Cecc error , the dump started from offset 4
        {
            offset = 4;
        }
        else
        {
            offset = 0;
        }

        uint32_t dumpIndex = 0;

        for (; offset < inst.number_bytes; offset = offset + 4)
        {
            memset(&dataIn, 0, sizeof(dataIn));
            memset(&dataOut, 0, sizeof(dataOut));
            dataIn.offset = offset;
            dataIn.category = category;
            dataIn.valid_inst_index = n;

            ret = get_bmc_ras_run_time_error_info(socNum, dataIn, &dataOut);

            if (ret != OOB_SUCCESS)
            {
                // retry
                while (*apmlRetryCount > 0)
                {
                    memset(&dataIn, 0, sizeof(dataIn));
                    memset(&dataOut, 0, sizeof(dataOut));
                    dataIn.offset = offset;
                    dataIn.category = category;
                    dataIn.valid_inst_index = n;

                    ret = get_bmc_ras_run_time_error_info(socNum, dataIn,
                                                          &dataOut);

                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    (*apmlRetryCount)--;
                    sleep(1);
                }
            }
            if (ret != OOB_SUCCESS)
            {
                lg2::error(
                    "Socket {SOCKET} : Failed to get runtime error info for instance.",
                    "SOCKET", socNum);
                if (ProcPtr)
                {
                    ProcPtr->McaErrorInfo[section].DumpData[dumpIndex] =
                        badData;
                }
                else if (PciePtr)
                {
                    PciePtr->PcieErrorData[section]
                        .AerInfo.PcieAer[dumpIndex * 4 + 0] =
                        (badData >> 24) & 0xFF;
                    PciePtr->PcieErrorData[section]
                        .AerInfo.PcieAer[dumpIndex * 4 + 1] =
                        (badData >> 16) & 0xFF;
                    PciePtr->PcieErrorData[section]
                        .AerInfo.PcieAer[dumpIndex * 4 + 2] =
                        (badData >> 8) & 0xFF;
                    PciePtr->PcieErrorData[section]
                        .AerInfo.PcieAer[dumpIndex * 4 + 3] = badData & 0xFF;
                }
                continue;
            }
            if (ProcPtr)
            {
                ProcPtr->McaErrorInfo[section].DumpData[dumpIndex] = dataOut;

                if (dataIn.offset == 8)
                {
                    mcaStatusRegister = mcaStatusRegister | ((uint64_t)dataOut);
                }
                else if (dataIn.offset == 12)
                {
                    mcaStatusRegister = ((uint64_t)dataOut << 32) |
                                        mcaStatusRegister;
                }
            }
            else if (PciePtr)
            {
                PciePtr->PcieErrorData[section]
                    .AerInfo.PcieAer[dumpIndex * 4 + 0] =
                    (dataOut >> 24) & 0xFF;
                PciePtr->PcieErrorData[section]
                    .AerInfo.PcieAer[dumpIndex * 4 + 1] =
                    (dataOut >> 16) & 0xFF;
                PciePtr->PcieErrorData[section]
                    .AerInfo.PcieAer[dumpIndex * 4 + 2] = (dataOut >> 8) & 0xFF;
                PciePtr->PcieErrorData[section]
                    .AerInfo.PcieAer[dumpIndex * 4 + 3] = dataOut & 0xFF;

                if (dataIn.offset == 52)
                {
                    rootErrStatus = dataOut;
                }
            }
            dumpIndex++;

        } // for loop

        if ((category == 0) || (category == 1))
        {
            CheckInfo[section] = 0;
            CheckInfo[section] |= ((mcaStatusRegister >> 57) & 1ULL) << 19;
            CheckInfo[section] |= ((mcaStatusRegister >> 61) & 1ULL) << 20;
            CheckInfo[section] |= ((mcaStatusRegister >> 62) & 1ULL) << 23;
            CheckInfo[section] |= (5ULL << 16);

            if (((mcaStatusRegister & (1ULL << 61)) == 0) &&
                ((mcaStatusRegister & (1ULL << 44)) == 0))
            {
                Severity[section] = 2; // Non fatal corrected
            }
            else if ((((mcaStatusRegister & (1ULL << 61)) == 0) &&
                      ((mcaStatusRegister & (1ULL << 44)) != 0)) ||
                     (((mcaStatusRegister & (1ULL << 61)) != 0) &&
                      ((mcaStatusRegister & (1ULL << 57)) == 0)))
            {
                Severity[section] = 0; // Non datal uncorrected
            }
        }
        else if (category == 2) // PCIE error
        {
            if (rootErrStatus & (1 << 6))
            {
                Severity[section] = 1; // Fatal error
            }
            else if (rootErrStatus & (1 << 5))
            {
                Severity[section] = 0; // Non datal uncorrected
            }
            else if (rootErrStatus & 1)
            {
                Severity[section] = 2; // Non fatal corrected
            }
        }
        n++;
        section++;
    }
}

void Manager::harvestDramCeccErrorCounters(struct ras_rt_valid_err_inst inst,
                                           uint8_t socNum)
{
    uint32_t dataOut = 0;
    struct run_time_err_d_in dataIn;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t* retryCount = std::get_if<int64_t>(&apmlRetry);

    if (inst.number_of_inst != 0)
    {
        uint16_t n = 0;
        while (n < inst.number_of_inst)
        {
            memset(&dataIn, 0, sizeof(dataIn));
            memset(&dataOut, 0, sizeof(dataOut));
            dataIn.valid_inst_index = n;
            dataIn.offset = 0;
            dataIn.category = dramCeccErr;

            ret = get_bmc_ras_run_time_error_info(socNum, dataIn, &dataOut);

            if (ret != OOB_SUCCESS)
            {
                // retry
                while (*retryCount > 0)
                {
                    memset(&dataIn, 0, sizeof(dataIn));
                    memset(&dataOut, 0, sizeof(dataOut));
                    dataIn.offset = 0;
                    dataIn.category = dramCeccErr;
                    dataIn.valid_inst_index = n;

                    ret = get_bmc_ras_run_time_error_info(socNum, dataIn,
                                                          &dataOut);
                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    (*retryCount)--;
                    sleep(1);
                }
            }
            n++;
        }

        if (ret == OOB_SUCCESS)
        {
            uint16_t dimmErrCount;
            uint8_t ch_num;
            uint8_t chip_sel_num;

            dimmErrCount = dataOut & 0xFFFF;

            ch_num = (dataOut >> 16) & 0x1F;

            lg2::info("Channel from the APML {CHN}", "CHN", ch_num);

            std::map<int, char> dimmPairSequence = {
                {0, 'H'},  {1, 'H'},  {2, 'D'},  {3, 'D'},  {4, 'F'},
                {5, 'F'},  {6, 'B'},  {7, 'B'},  {8, 'G'},  {9, 'G'},
                {10, 'C'}, {11, 'C'}, {12, 'E'}, {13, 'E'}, {14, 'A'},
                {15, 'A'}, {16, 'P'}, {17, 'P'}, {18, 'L'}, {19, 'L'},
                {20, 'N'}, {21, 'N'}, {22, 'J'}, {23, 'J'}, {24, 'O'},
                {25, 'O'}, {26, 'K'}, {27, 'K'}, {28, 'M'}, {29, 'M'},
                {30, 'I'}, {31, 'I'}};

            char channel = '\0';

            auto it = dimmPairSequence.find(ch_num);

            if (it != dimmPairSequence.end())
            {
                channel = it->second;
            }

            std::string socNumStr = std::to_string(socNum);
            std::string rootErrStatus = "P" + socNumStr + "_CHANNEL_" + channel;

            chip_sel_num = (dataOut >> chipSelNumPos) & 3;

            uint8_t DimmNumber = chip_sel_num >> 1;

            if (DimmNumber)
            {
                rootErrStatus = rootErrStatus + std::to_string(DimmNumber);
            }
            lg2::info("Channel = {DIMM}", "DIMM", rootErrStatus);
            lg2::info("Error count = {COUNT}", "COUNT", dimmErrCount);

            std::string objectPath =
                "/xyz/openbmc_project/inventory/Memory/" + rootErrStatus;

            sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
            uint16_t correctableErrorCount =
                amd::ras::util::getProperty<uint16_t>(
                    bus, "xyz.openbmc_project.PCIe", objectPath.c_str(),
                    "xyz.openbmc_project.Inventory.Item.Dimm",
                    "CorrectableErrorCount");

            correctableErrorCount = correctableErrorCount + dimmErrCount;

            boost::asio::io_context io_conn;
            auto conn = std::make_shared<sdbusplus::asio::connection>(io_conn);
            conn->async_method_call(
                [this](boost::system::error_code ec) {
                    if (ec)
                    {
                        sd_journal_print(
                            LOG_ERR, "Failed to Set Dimm ecc error count \n");
                    }
                },
                "xyz.openbmc_project.PCIe", objectPath.c_str(),
                "org.freedesktop.DBus.Properties", "Set",
                "xyz.openbmc_project.Inventory.Item.Dimm",
                "CorrectableErrorCount",
                std::variant<uint16_t>(correctableErrorCount));
        }
    }
}

} // namespace apml
} // namespace ras
} // namespace amd
