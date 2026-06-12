#include "pldm_manager.hpp"

#include "config_manager.hpp"
#include "oem_cper.hpp"
#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
#include "linux/amd-apml.h"
}

#include <unistd.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <cerrno>
#include <cstring>
#include <fstream>

namespace amd
{
namespace ras
{
namespace pldm
{

constexpr uint32_t badData = 0xBAADDA7A;
constexpr uint8_t sysMgmtCtrlErr = 0x4;
constexpr uint8_t cfError = 0x6;
constexpr uint8_t sbrmiControlRegister = 0x1;

Manager::Manager(amd::ras::config::Manager& manager,
                 sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io, std::string& node) :
    amd::ras::Manager(manager, node), objectServer(objectServer),
    systemBus(systemBus), io(io), pldmInitialized(false),
    platformInitialized(false), runtimeErrPollingSupported(false)
{}

void Manager::onHostStateChanged(bool hostOff)
{
    pldmInitialized = false;

    if (!hostOff)
    {
        lg2::info("Current host state monitor changed");
        platformInitialize();
    }
}

void Manager::platformInitialize()
{
    lg2::info("Initializing Platform over PLDM transport");
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
            lg2::error("Failed to get processor info. RET: {RET}", "RET", ret);
            sleep(1);
        }

        if ((platInfo->family == whFamilyId) &&
            (std::find(whModels.begin(), whModels.end(), platInfo->model) !=
             whModels.end()))
        {
            currentHostStateMonitor();

            for (size_t i : socIndex)
            {
                clearSbrmiAlertMask(static_cast<uint8_t>(i));
            }

            // TODO: Add support for runtime error polling for PLDM when the API
            // is available.
            runtimeErrPollingSupported = true;
        }
        else
        {
            throw std::runtime_error(std::format(
                "This program is not supported for the family = 0x{:x} model = 0x{:x}\n",
                platInfo->family, platInfo->model));
        }

        platformInitialized = true;
        pldmInitialized = true;
    }
    else
    {
        pldmInitialized = true;

        for (size_t i : socIndex)
        {
            clearSbrmiAlertMask(static_cast<uint8_t>(i));
        }

        if (runtimeErrPollingSupported == true)
        {
            lg2::info("Setting MCA and DRAM OOB Config");
            // TODO: Add support for setting MCA and DRAM OOB config for PLDM
            // when the API is available.

            lg2::info("Setting MCA and DRAM Error threshold");
            // TODO: Add support for setting MCA and DRAM error threshold for
            // PLDM when the API is available.
        }
    }
}

void Manager::clearSbrmiAlertMask(uint8_t socNum)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint8_t buffer = 0;
    size_t retryCount = 10;

    while (retryCount > 0)
    {
        ret = esmi_oob_read_byte(socNum, sbrmiControlRegister, SBRMI, &buffer);
        if (ret == OOB_SUCCESS)
        {
            break;
        }

        lg2::error("Failed to read register: {REGISTER} Retrying", "REGISTER",
                   lg2::hex, sbrmiControlRegister);
        sleep(1);
        retryCount--;
    }

    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to read register: {REGISTER}", "REGISTER", lg2::hex,
                   sbrmiControlRegister);
        return;
    }

    // Match APML path: clear alert mask bits required for RAS alert delivery.
    buffer = buffer & 0xBE;

    ret = esmi_oob_write_byte(socNum, sbrmiControlRegister, SBRMI, buffer);
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to write register: {REGISTER}", "REGISTER", lg2::hex,
                   sbrmiControlRegister);
        return;
    }

    lg2::debug("Write to register {REGISTER} is successful", "REGISTER",
               lg2::hex, sbrmiControlRegister);
}

void Manager::init()
{
    lg2::info("PLDM MANAGER INIT");

    getCpuSocketInfo();

    loadPlatformConfig();

    platformInitialize();
}

void Manager::configure()
{
    lg2::info("PLDM MANAGER CONFIGURE");
    configureSysMgmtCtrlErrAlertHandling();
}

void Manager::registerEventHandler()
{
    lg2::info("PLDM MANAGER REGISTER EVENT HANDLER");

    amd::ras::util::cper::createRecord(objectServer, systemBus, node);

    const std::string matchRule =
        "type='signal',"
        "interface='xyz.openbmc_project.PLDM.Event',"
        "member='PldmMessagePollEvent'";

    pldmEventMatch = std::make_unique<sdbusplus::bus::match_t>(
        static_cast<sdbusplus::bus_t&>(*systemBus), matchRule,
        [this](sdbusplus::message_t& msg) { handlePldmRasEvent(msg); });

    lg2::info("Registered PLDM RAS event signal monitor");

    registerSysMgmtCtrlErrAlertHandler();
}

void Manager::configureSysMgmtCtrlErrAlertHandling()
{
    const std::string primaryPath =
        "/var/lib/amd-bmc-ras/amd_ras_gpio_config" + node + ".json";
    const std::string fallbackPath =
        "/usr/share/amd-bmc-ras/amd_ras_gpio_config" + node + ".json";

    std::ifstream jsonFile(primaryPath);
    std::string cfgPath = primaryPath;

    if (!jsonFile.is_open())
    {
        jsonFile.open(fallbackPath);
        cfgPath = fallbackPath;
    }

    if (!jsonFile.is_open())
    {
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    if (jsonFile.peek() == std::ifstream::traits_type::eof())
    {
        jsonFile.close();
        lg2::error("GPIO config file is empty: {FILE}", "FILE", cfgPath);
        throw std::runtime_error("GPIO config file is empty");
    }

    nlohmann::json config;
    jsonFile >> config;
    jsonFile.close();

    alertHandleMode.clear();
    socketNames.clear();

    if (config.contains("Alert_Config") && config["Alert_Config"].is_array())
    {
        for (const auto& entry : config["Alert_Config"])
        {
            if (entry.contains("AlertHandle"))
            {
                const auto& alertCfg = entry["AlertHandle"];
                if (alertCfg.contains("Value"))
                {
                    alertHandleMode = alertCfg["Value"].get<std::string>();
                }
            }

            if (alertHandleMode == "GPIO" &&
                entry.contains("GPIO_ALERT_LINES") &&
                entry["GPIO_ALERT_LINES"].is_array())
            {
                socketNames =
                    entry["GPIO_ALERT_LINES"].get<std::vector<std::string>>();
            }
        }
    }

    if (alertHandleMode != "UEVENT" && alertHandleMode != "GPIO")
    {
        throw std::runtime_error("Invalid mode of Alert handling");
    }

    if (alertHandleMode == "GPIO" && socketNames.size() < cpuCount)
    {
        throw std::runtime_error(
            "Insufficient GPIO_ALERT_LINES entries in gpio_config.json");
    }

    lg2::info("PLDM sysMgmtCtrlErr alert mode: {MODE}", "MODE",
              alertHandleMode);
}

void Manager::registerSysMgmtCtrlErrAlertHandler()
{
    if (alertHandleMode == "UEVENT")
    {
        udevMonitors.resize(cpuCount);
        udevPollTimers.resize(cpuCount);

        for (size_t i = 0; i < cpuCount; ++i)
        {
            apml_register_udev_monitor(&udevMonitors[i]);

            if (!udevMonitors[i].udev || !udevMonitors[i].mon)
            {
                lg2::error(
                    "Failed to initialize udev monitor for socket idx {IDX}",
                    "IDX", i);
                apml_unregister_udev_monitor(&udevMonitors[i]);
                continue;
            }

            lg2::info(
                "Registered UEVENT monitor for PLDM sysMgmtCtrlErr on socket idx {IDX}",
                "IDX", i);
            pollSysMgmtCtrlErrUevent(i);
        }
        return;
    }

    gpioLines.resize(cpuCount);
    gpioEventDescriptors.reserve(cpuCount);

    for (size_t i = 0; i < cpuCount; ++i)
    {
        gpioEventDescriptors.emplace_back(io);

        requestSysMgmtCtrlErrGPIOEvents(
            socketNames[i],
            std::bind(&ras::pldm::Manager::handleSysMgmtCtrlErrGPIOEvent, this,
                      std::ref(gpioEventDescriptors[i]), std::ref(gpioLines[i]),
                      i),
            gpioLines[i], gpioEventDescriptors[i]);
    }
}

void Manager::pollSysMgmtCtrlErrUevent(size_t socketIdx)
{
    if (socketIdx >= udevMonitors.size() || socketIdx >= socIndex.size())
    {
        return;
    }

    uint8_t socNum = static_cast<uint8_t>(socIndex[socketIdx]);
    uint32_t src = 0;
    const bool block = false;
    const oob_status_t ret =
        monitor_ras_alert(udevMonitors[socketIdx].mon, block, &socNum, &src);

    if (ret == OOB_SUCCESS)
    {
        lg2::info("PLDM UEVENT alert: soc={SOC}, src=0x{SRC}", "SOC", socNum,
                  "SRC", lg2::hex, src);

        if ((socNum == static_cast<uint8_t>(socIndex[socketIdx])) &&
            (src & cfError) && (src & sysMgmtCtrlErr))
        {
            handleSysMgmtCtrlError(socNum);
        }
    }
    else if (ret == OOB_FILE_ERROR || ret == OOB_INTERRUPTED)
    {
        lg2::error("PLDM UEVENT monitor error for socket idx {IDX}: {RET}",
                   "IDX", socketIdx, "RET", ret);
    }

    udevPollTimers[socketIdx] = std::make_unique<boost::asio::deadline_timer>(
        io, boost::posix_time::seconds(1));
    udevPollTimers[socketIdx]->async_wait(
        [this, socketIdx](const boost::system::error_code& ec) {
            if (ec)
            {
                lg2::error("PLDM UEVENT polling timer error: {MSG}", "MSG",
                           ec.message().c_str());
                return;
            }
            pollSysMgmtCtrlErrUevent(socketIdx);
        });
}

void Manager::requestSysMgmtCtrlErrGPIOEvents(
    const std::string& name, const std::function<void()>& handler,
    gpiod::line& gpioLine,
    boost::asio::posix::stream_descriptor& gpioEventDescriptor)
{
    try
    {
        gpioLine = gpiod::find_line(name);
        if (!gpioLine)
        {
            throw std::runtime_error("Failed to find GPIO line: " + name);
        }

        gpioLine.request({"RAS", gpiod::line_request::EVENT_BOTH_EDGES, 0});

        const int gpioFd = gpioLine.event_get_fd();
        if (gpioFd < 0)
        {
            throw std::runtime_error("Failed to get GPIO line fd: " + name);
        }

        gpioEventDescriptor.assign(gpioFd);
        gpioEventDescriptor.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [handler](const boost::system::error_code& ec) {
                if (ec)
                {
                    throw std::runtime_error(
                        "GPIO wait error: " + ec.message());
                }
                handler();
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to register GPIO alert {LINE}: {ERROR}", "LINE",
                   name, "ERROR", e.what());
    }
}

void Manager::handleSysMgmtCtrlErrGPIOEvent(
    boost::asio::posix::stream_descriptor& alertEvent,
    const gpiod::line& alertLine, size_t socketIdx)
{
    const gpiod::line_event gpioLineEvent = alertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        if (socketIdx < socIndex.size())
        {
            const uint8_t socNum = static_cast<uint8_t>(socIndex[socketIdx]);
            uint8_t rasStatus = 0;

            if (read_sbrmi_ras_status(socNum, &rasStatus) == OOB_SUCCESS)
            {
                lg2::info("PLDM GPIO alert: soc={SOC}, rasStatus=0x{STATUS}",
                          "SOC", socNum, "STATUS", lg2::hex, rasStatus);

                if ((rasStatus & cfError) && (rasStatus & sysMgmtCtrlErr))
                {
                    handleSysMgmtCtrlError(socNum);
                }
            }
            else
            {
                lg2::error("Failed to read RAS status for socket {SOC}", "SOC",
                           socNum);
            }
        }
    }

    alertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this, alertLine, socketIdx, alertEventPtr = &alertEvent](
            const boost::system::error_code& ec) mutable {
            if (ec)
            {
                lg2::error("PLDM GPIO alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            handleSysMgmtCtrlErrGPIOEvent(*alertEventPtr, alertLine, socketIdx);
        });
}

void Manager::handlePldmRasEvent(sdbusplus::message_t& msg)
{
    uint64_t epochTimestamp = 0;
    uint8_t terminusId = 0;
    std::string terminusName;
    uint8_t formatVersion = 0;
    uint8_t eventClass = 0;
    uint16_t eventId = 0;
    uint32_t dataTransferHandle = 0;
    uint16_t eventDataSize = 0;
    sdbusplus::message::unix_fd eventDataFd;

    try
    {
        msg.read(epochTimestamp, terminusId, terminusName, formatVersion,
                 eventClass, eventId, dataTransferHandle, eventDataSize,
                 eventDataFd);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to read PLDM event signal: {ERROR}", "ERROR",
                   e.what());
        return;
    }

    lg2::info(
        "PLDM RAS event received: terminus={TERMINUS}, eventId=0x{EVENTID}, "
        "dataTransferHandle=0x{HANDLE}, eventDataSize={SIZE}",
        "TERMINUS", terminusName, "EVENTID", lg2::hex, eventId, "HANDLE",
        lg2::hex, dataTransferHandle, "SIZE", eventDataSize);

    // Read error data from the file descriptor
    std::vector<uint8_t> eventData;
    if (eventDataSize > 0)
    {
        if (!readEventDataFromFd(eventDataFd, eventDataSize, eventData))
        {
            return;
        }
    }

    uint8_t socNum = getSocketFromTerminus(terminusName);

    switch (eventId)
    {
        case pldm::eventIdFatalError:
            lg2::error("PLDM RAS Event: Fatal error/SYNCFLOOD on {TERMINUS}",
                       "TERMINUS", terminusName);
            handleFatalOrShutdownError(eventData, socNum, crashdump);
            break;

        case pldm::eventIdFchError:
            lg2::error("PLDM RAS Event: FCH Error on {TERMINUS}", "TERMINUS",
                       terminusName);
            handleFchError(socNum);
            break;

        case pldm::eventIdMcaOverflow:
            lg2::error(
                "PLDM RAS Event: MCA error counter overflow on {TERMINUS}",
                "TERMINUS", terminusName);
            break;

        case pldm::eventIdDramCeccOverflow:
            lg2::error(
                "PLDM RAS Event: DRAM CECC error counter overflow on {TERMINUS}",
                "TERMINUS", terminusName);
            break;

        case pldm::eventIdNonMcaCoreShutdown:
            lg2::error(
                "PLDM RAS Event: Non-MCA initiated core shutdown on {TERMINUS}",
                "TERMINUS", terminusName);
            {
                std::string rasErrMsg =
                    "Non MCA Shutdown error detected in the system";
                sd_journal_send(
                    "MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
                configMgr.incrementNoncorrectableOtherError(socNum);
                configMgr.updateErrorCountDbus();
                configMgr.saveErrorCounts();
            }
            break;

        case pldm::eventIdMcaCoreShutdown:
            lg2::error(
                "PLDM RAS Event: MCA initiated core shutdown on {TERMINUS}",
                "TERMINUS", terminusName);
            handleFatalOrShutdownError(eventData, socNum, shutdown);
            break;

        default:
            lg2::warning(
                "PLDM RAS Event: Unknown eventId 0x{EVENTID} on {TERMINUS}",
                "EVENTID", eventId, "TERMINUS", terminusName);
            break;
    }
}

uint8_t Manager::getSocketFromTerminus(const std::string& terminusName)
{
    // Extract socket number from the trailing digit in terminus name
    // Common patterns: "P0", "P1", "socket0", "socket1", "Processor0", etc.
    for (auto it = terminusName.rbegin(); it != terminusName.rend(); ++it)
    {
        if (std::isdigit(*it))
        {
            return static_cast<uint8_t>(*it - '0');
        }
    }
    // Default to socket 0
    return 0;
}

void Manager::handleFatalOrShutdownError(const std::vector<uint8_t>& eventData,
                                         uint8_t socNum, size_t contextType)
{
    std::unique_lock lock(harvestMutex);

    std::string rasErrMsg;
    uint8_t rasStatusByte;

    if (contextType == crashdump)
    {
        rasErrMsg = "RAS FATAL Error detected. "
                    "System may reset after harvesting "
                    "MCA data based on policy set.";
        rasStatusByte = 0x01; // fatal_err bit
    }
    else
    {
        rasErrMsg =
            "MCA CPU shutdown error detected."
            "System may reset after harvesting MCA data based on policy set.";
        rasStatusByte = 0x41; // fatal_err + shutdown bits
    }

    sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

    configMgr.incrementNoncorrectableCPUError(socNum, 0);
    configMgr.updateErrorCountDbus();
    configMgr.saveErrorCounts();

    harvestMcaDataBanksOverPldm(eventData, socNum, contextType);

    amd::ras::util::cper::createFile(rcd, fatalErr, 2, errCount, node);

    amd::ras::util::cper::exportToDBus(errCount, rcd->Header.TimeStamp,
                                       objectServer, systemBus, node);
    amd::ras::util::cper::updateIndexFile(errCount, node);

    // Trigger recovery action based on configured policy
    amd::ras::config::Manager::AttributeValue ResetSignalVal =
        configMgr.getAttribute("ResetSignalType");
    std::string* resetSignal = std::get_if<std::string>(&ResetSignalVal);

    amd::ras::config::Manager::AttributeValue SystemRecoveryVal =
        configMgr.getAttribute("SystemRecoveryMode");
    std::string* systemRecovery = std::get_if<std::string>(&SystemRecoveryVal);

    amd::ras::util::rasRecoveryAction(node, rasStatusByte, systemRecovery,
                                      resetSignal);

    cleanupFatalCperRecord();
}

void Manager::handleSysMgmtCtrlError(uint8_t socNum)
{
    std::unique_lock lock(harvestMutex);

    std::string rasErrMsg = "Fatal error detected in the control fabric. "
                            "BMC may trigger a reset based on policy set. ";

    sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

    if (rcd == nullptr)
    {
        rcd = std::make_shared<FatalCperRecord>();
    }

    harvestBreakEvent(socNum);

    configMgr.incrementNoncorrectableOtherError(socNum);
    configMgr.updateErrorCountDbus();
    configMgr.saveErrorCounts();

    amd::ras::util::cper::createFile(rcd, fatalErr, 2, errCount, node);
    amd::ras::util::cper::exportToDBus(errCount, rcd->Header.TimeStamp,
                                       objectServer, systemBus, node);
    amd::ras::util::cper::updateIndexFile(errCount, node);

    amd::ras::config::Manager::AttributeValue resetSignalVal =
        configMgr.getAttribute("ResetSignalType");
    std::string* resetSignal = std::get_if<std::string>(&resetSignalVal);

    amd::ras::config::Manager::AttributeValue systemRecoveryVal =
        configMgr.getAttribute("SystemRecoveryMode");
    std::string* systemRecovery = std::get_if<std::string>(&systemRecoveryVal);

    amd::ras::util::rasRecoveryAction(node, sysMgmtCtrlErr, systemRecovery,
                                      resetSignal);

    cleanupFatalCperRecord();
}

void Manager::harvestMcaDataBanksOverPldm(const std::vector<uint8_t>& eventData,
                                          uint8_t socNum, size_t contextType)
{
    constexpr uint16_t sectionCount = 2;

    if (rcd == nullptr)
    {
        rcd = std::make_shared<FatalCperRecord>();
    }

    initFatalCperRecord(sectionCount);

    uint16_t numMcaBanks = eventData.size() / mcaDataBankLen;
    uint16_t wordsPerMcaBank =
        ((eventData.size() % 4) ? 1 : 0) + (eventData.size() >> 2);
    if (numMcaBanks == 0)
    {
        lg2::info(
            "No valid mca banks found. Harvesting additional debug log ID dumps");
    }

    // Clamp to valid range
    if (numMcaBanks > 32)
    {
        lg2::warning(
            "Invalid MCA bank count {COUNT} from PLDM data, clamping to 32",
            "COUNT", numMcaBanks);
        numMcaBanks = 32;
    }

    lg2::info("Number of Valid MCA bank: {NUMBANKS}", "NUMBANKS", numMcaBanks);
    lg2::info("Number of 32 Bit Words per MCA bank: {WORDS_PER_BANK}",
              "WORDS_PER_BANK", wordsPerMcaBank);

    // Populate processor error info
    amd::ras::util::cper::dumpProcessorError(rcd, socNum, cpuId, socIndex,
                                             numMcaBanks);
    amd::ras::util::cper::dumpContext(rcd, numMcaBanks, wordsPerMcaBank, socNum,
                                      ppin, uCode, contextType);

    uint16_t maxOffset32 = mcaDataBankLen / 4;

    for (uint16_t n = 0; n < numMcaBanks; n++)
    {
        // In PLDM mode, all MCA data is available in eventData.
        // Copy the entire bank at once instead of reading 4 bytes
        // per transaction as done in APML mode via read_ras_df_err_dump().
        size_t bankStart = static_cast<size_t>(n) * mcaDataBankLen;

        if (bankStart + mcaDataBankLen <= eventData.size())
        {
            std::memcpy(rcd->ErrorRecord[socNum].CrashDumpData[n].McaData,
                        &eventData[bankStart], mcaDataBankLen);
        }
        else
        {
            // Partial or missing bank data - fill with bad data pattern
            size_t available = (bankStart < eventData.size())
                                   ? (eventData.size() - bankStart)
                                   : 0;
            if (available > 0)
            {
                std::memcpy(rcd->ErrorRecord[socNum].CrashDumpData[n].McaData,
                            &eventData[bankStart], available);
            }
            // Fill remaining words with bad data
            for (uint32_t w = available / 4; w < maxOffset32; w++)
            {
                rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[w] = badData;
            }
        }
    }

    processMcaBankSignatures(socNum, numMcaBanks);
}

bool Manager::readEventDataFromFd(int fd, uint16_t eventDataSize,
                                  std::vector<uint8_t>& eventData)
{
    eventData.resize(eventDataSize);
    ssize_t totalBytesRead = 0;

    while (totalBytesRead < eventDataSize)
    {
        ssize_t bytesRead = read(fd, eventData.data() + totalBytesRead,
                                 eventDataSize - totalBytesRead);
        if (bytesRead < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            lg2::error("Failed to read event data from fd {FD}: {ERROR}", "FD",
                       fd, "ERROR", strerror(errno));
            return false;
        }
        if (bytesRead == 0)
        {
            break;
        }
        totalBytesRead += bytesRead;
    }

    eventData.resize(totalBytesRead);
    lg2::info("Read {BYTES} bytes of event data from fd", "BYTES",
              totalBytesRead);
    return true;
}

} // namespace pldm
} // namespace ras
} // namespace amd
