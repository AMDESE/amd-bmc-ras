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
#include <cstdio>
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
constexpr size_t mcaStatusLoOffset = 8;
constexpr size_t mcaStatusHiOffset = 12;

// ---------------------------------------------------------------------------
// PLDM NumericEffecter D-Bus objects used to program the RAS OOB
// configuration and error thresholds. These effecters are hosted by the
// pldmd service (xyz.openbmc_project.PLDM). The values are exchanged as byte
// arrays (D-Bus "ay") through the EffecterValue (set) and PresentValue (get)
// properties.
// ---------------------------------------------------------------------------
constexpr const char* pldmService = "xyz.openbmc_project.PLDM";
constexpr const char* numericEffecterIface =
    "xyz.openbmc_project.Control.NumericEffecter";
constexpr const char* effecterValueProperty = "EffecterValue";
constexpr const char* presentValueProperty = "PresentValue";
constexpr const char* controlsPathPrefix =
    "/xyz/openbmc_project/controls/Processor";
constexpr const char* oobConfigPathSuffix = "_BMCRasSetOOBConfig";
constexpr const char* errThresholdPathSuffix = "_BMCRasSetErrThreshold";

// OOB configuration byte layout (4 bytes).
constexpr size_t oobConfigSize = 4;
constexpr size_t coreMcaErrReportingEnByte = 0;
constexpr size_t dramCeccOobEcModeByte = 1;
constexpr size_t pcieErrReportingEnByte = 2;
constexpr size_t mcaOobMisc0EcEnableByte = 3;

// Error threshold byte layout (4 bytes).
constexpr size_t errThresholdSize = 4;
constexpr size_t errTypeByte = 0;
constexpr size_t errCountLoByte = 1;
constexpr size_t errCountHiByte = 2;
constexpr size_t maxIntruptRateByte = 3;

// Error type codes carried in the threshold payload.
constexpr uint8_t errTypeMca = 0;
constexpr uint8_t errTypeDramCecc = 1;
constexpr uint8_t errTypePcie = 2;
constexpr uint8_t errTypeMcaUmc = 3;

constexpr uint8_t defaultMaxIntruptRate = 1;

// ---------------------------------------------------------------------------
// File-scope helpers shared by the MCA, DRAM, and PCIe harvest paths.
// ---------------------------------------------------------------------------

/** Build a flat byte-offset map: offsets[i] = byte start of handle i's
 *  payload inside the concatenated eventData buffer. */
static std::vector<size_t>
    buildHandleDataOffsets(const std::vector<uint32_t>& dataTransferHandles,
                           const std::vector<uint32_t>& eventDataSizes)
{
    std::vector<size_t> offsets(dataTransferHandles.size(), 0);
    size_t offset = 0;
    for (size_t i = 0; i < dataTransferHandles.size(); i++)
    {
        offsets[i] = offset;
        if (i < eventDataSizes.size())
        {
            offset += eventDataSizes[i];
        }
    }
    return offsets;
}

static bool isDebugLogDumpOpcode(uint8_t opcode)
{
    return opcode == opcodeDbgLogDump || opcode == opcodeDbgLogDumpAlt;
}

constexpr uint8_t overflowCategoryMca = 0x00;
constexpr uint8_t overflowCategoryDramCecc = 0x01;
constexpr uint8_t overflowCategoryPcie = 0x02;
constexpr uint16_t overflowInstanceZero = 0x0000;

/** Return {dataOffset, segSize} for the runtime-overflow payload matching
 *  opcode=0x62, category=[23:16], and preferred instance/index=0x0000.
 *  If instance 0 is absent for the category, fall back to the first
 *  matching opcode/category entry. Returns {0, 0} when not found. */
static std::pair<size_t, uint32_t> findSegmentForOverflowCategory(
    uint8_t category, const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes,
    const std::vector<size_t>& handleDataOffsets)
{
    std::pair<size_t, uint32_t> fallback{0, 0};

    for (size_t i = 0; i < dataTransferHandles.size(); i++)
    {
        uint8_t opcode =
            static_cast<uint8_t>((dataTransferHandles[i] >> 24) & 0xFF);
        uint8_t handleCategory =
            static_cast<uint8_t>((dataTransferHandles[i] >> 16) & 0xFF);
        uint16_t instance =
            static_cast<uint16_t>(dataTransferHandles[i] & 0xFFFF);

        if (opcode != opcodeDbgLogDumpAlt || handleCategory != category)
        {
            continue;
        }

        uint32_t segSize = (i < eventDataSizes.size()) ? eventDataSizes[i] : 0;

        if (instance == overflowInstanceZero)
        {
            return {handleDataOffsets[i], segSize};
        }

        if (fallback.second == 0)
        {
            fallback = {handleDataOffsets[i], segSize};
        }
    }

    return fallback;
}

Manager::Manager(amd::ras::config::Manager& manager,
                 sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io, std::string& node) :
    amd::ras::Manager(manager, systemBus, node), objectServer(objectServer),
    io(io), pldmInitialized(false), platformInitialized(false),
    runtimeErrSupported(false)
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

            // Runtime error polling (McaPollingEn, DramCeccPollingEn,
            // PcieAerPollingEn) is not supported in PLDM mode. The OOB error
            // thresholds are configured through the base-class configure()
            // flow (see configure()).
            runtimeErrSupported = true;
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

        if (runtimeErrSupported == true)
        {
            // Runtime error polling is not supported in PLDM mode; re-apply
            // the OOB error thresholds after the host state transition.
            lg2::info("Setting MCA, DRAM CECC and PCIe error thresholds over "
                      "PLDM");
            configureErrThresholdsOverPldm();
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

bool Manager::setRasOobConfigOverPldm(uint8_t socNum,
                                      const std::vector<uint8_t>& oobConfig)
{
    const std::string path = std::string(controlsPathPrefix) +
                             std::to_string(socNum) + oobConfigPathSuffix;

    try
    {
        auto method = systemBus->new_method_call(
            pldmService, path.c_str(), "org.freedesktop.DBus.Properties",
            "Set");
        method.append(numericEffecterIface, effecterValueProperty,
                      std::variant<std::vector<uint8_t>>(oobConfig));
        systemBus->call(method);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to set RAS OOB config over PLDM for processor "
                   "P{PROCESSOR}: {ERROR}",
                   "PROCESSOR", socNum, "ERROR", e.what());
        return false;
    }

    lg2::info("BMC RAS OOB configuration set successfully for processor "
              "P{PROCESSOR}",
              "PROCESSOR", socNum);
    return true;
}

bool Manager::getRasOobConfigOverPldm(uint8_t socNum,
                                      std::vector<uint8_t>& oobConfig)
{
    const std::string path = std::string(controlsPathPrefix) +
                             std::to_string(socNum) + oobConfigPathSuffix;

    try
    {
        auto method = systemBus->new_method_call(
            pldmService, path.c_str(), "org.freedesktop.DBus.Properties",
            "Get");
        method.append(numericEffecterIface, presentValueProperty);

        auto reply = systemBus->call(method);
        std::variant<std::vector<uint8_t>> value;
        reply.read(value);
        oobConfig = std::get<std::vector<uint8_t>>(value);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to get RAS OOB config over PLDM for processor "
                   "P{PROCESSOR}: {ERROR}",
                   "PROCESSOR", socNum, "ERROR", e.what());
        return false;
    }

    return true;
}

bool Manager::setRasErrThresholdOverPldm(uint8_t socNum,
                                         const std::vector<uint8_t>& threshold)
{
    const std::string path = std::string(controlsPathPrefix) +
                             std::to_string(socNum) + errThresholdPathSuffix;

    try
    {
        auto method = systemBus->new_method_call(
            pldmService, path.c_str(), "org.freedesktop.DBus.Properties",
            "Set");
        method.append(numericEffecterIface, effecterValueProperty,
                      std::variant<std::vector<uint8_t>>(threshold));
        systemBus->call(method);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to set RAS error threshold over PLDM for processor "
                   "P{PROCESSOR}: {ERROR}",
                   "PROCESSOR", socNum, "ERROR", e.what());
        return false;
    }

    lg2::info("BMC RAS error threshold set successfully for processor "
              "P{PROCESSOR}",
              "PROCESSOR", socNum);
    return true;
}

void Manager::writeErrThresholdOverPldm(uint8_t socNum, uint8_t errType,
                                        uint64_t errCount)
{
    std::vector<uint8_t> threshold(errThresholdSize, 0);
    threshold[errTypeByte] = errType;
    threshold[errCountLoByte] = static_cast<uint8_t>(errCount & 0xFF);
    threshold[errCountHiByte] = static_cast<uint8_t>((errCount >> 8) & 0xFF);
    threshold[maxIntruptRateByte] = defaultMaxIntruptRate;

    setRasErrThresholdOverPldm(socNum, threshold);
}

void Manager::configureErrThresholdsOverPldm()
{
    amd::ras::config::Manager::AttributeValue mcaThreshold =
        configMgr.getAttribute("McaThresholdEn");
    bool* mcaThresholdEn = std::get_if<bool>(&mcaThreshold);

    amd::ras::config::Manager::AttributeValue dramCeccThreshold =
        configMgr.getAttribute("DramCeccThresholdEn");
    bool* dramCeccThresholdEn = std::get_if<bool>(&dramCeccThreshold);

    amd::ras::config::Manager::AttributeValue pcieAerThreshold =
        configMgr.getAttribute("PcieAerThresholdEn");
    bool* pcieAerThresholdEn = std::get_if<bool>(&pcieAerThreshold);

    const bool mcaEnabled = (mcaThresholdEn != nullptr) && (*mcaThresholdEn);
    const bool dramEnabled =
        (dramCeccThresholdEn != nullptr) && (*dramCeccThresholdEn);
    const bool pcieEnabled =
        (pcieAerThresholdEn != nullptr) && (*pcieAerThresholdEn);

    if (!mcaEnabled && !dramEnabled && !pcieEnabled)
    {
        lg2::info("No RAS error thresholds enabled; skipping PLDM OOB "
                  "threshold configuration");
        return;
    }

    // Build the combined OOB configuration (union of the bits required by
    // every enabled threshold type). Each write to the OOB effecter replaces
    // the whole value, so all bits must be programmed in a single write to
    // avoid clobbering previously enabled threshold types.
    std::vector<uint8_t> oobConfig(oobConfigSize, 0);

    if (mcaEnabled)
    {
        oobConfig[coreMcaErrReportingEnByte] = 1;
        oobConfig[mcaOobMisc0EcEnableByte] = 1;
    }
    if (dramEnabled)
    {
        oobConfig[dramCeccOobEcModeByte] = 1;
        oobConfig[mcaOobMisc0EcEnableByte] = 1;
    }
    if (pcieEnabled)
    {
        oobConfig[pcieErrReportingEnByte] = 1;
        oobConfig[coreMcaErrReportingEnByte] = 1;
    }

    for (size_t i : socIndex)
    {
        uint8_t socNum = static_cast<uint8_t>(i);

        lg2::info("Setting RAS OOB configuration over PLDM for processor "
                  "P{PROCESSOR}",
                  "PROCESSOR", socNum);

        if (!setRasOobConfigOverPldm(socNum, oobConfig))
        {
            lg2::error("Skipping error threshold programming for processor "
                       "P{PROCESSOR}: OOB config set failed",
                       "PROCESSOR", socNum);
            continue;
        }

        if (mcaEnabled)
        {
            amd::ras::config::Manager::AttributeValue mcaErrThresholdCount =
                configMgr.getAttribute("McaErrThresholdCnt");
            int64_t* mcaErrThresholdCnt =
                std::get_if<int64_t>(&mcaErrThresholdCount);

            if (mcaErrThresholdCnt != nullptr)
            {
                lg2::info("Setting MCA error threshold over PLDM for processor "
                          "P{PROCESSOR}",
                          "PROCESSOR", socNum);
                writeErrThresholdOverPldm(
                    socNum, errTypeMca,
                    static_cast<uint64_t>(*mcaErrThresholdCnt));
            }

            amd::ras::config::Manager::AttributeValue mcaUmcErrThresholdCount =
                configMgr.getAttribute("McaUmcErrThresholdCnt");
            int64_t* mcaUmcErrThresholdCnt =
                std::get_if<int64_t>(&mcaUmcErrThresholdCount);

            if (mcaUmcErrThresholdCnt != nullptr)
            {
                lg2::info("Setting MCA UMC error threshold over PLDM for "
                          "processor P{PROCESSOR}",
                          "PROCESSOR", socNum);
                writeErrThresholdOverPldm(
                    socNum, errTypeMcaUmc,
                    static_cast<uint64_t>(*mcaUmcErrThresholdCnt));
            }
        }

        if (dramEnabled)
        {
            amd::ras::config::Manager::AttributeValue
                dramCeccErrThresholdCount =
                    configMgr.getAttribute("DramCeccErrThresholdCnt");
            int64_t* dramCeccErrThresholdCnt =
                std::get_if<int64_t>(&dramCeccErrThresholdCount);

            if (dramCeccErrThresholdCnt != nullptr)
            {
                lg2::info("Setting DRAM CECC error threshold over PLDM for "
                          "processor P{PROCESSOR}",
                          "PROCESSOR", socNum);
                writeErrThresholdOverPldm(
                    socNum, errTypeDramCecc,
                    static_cast<uint64_t>(*dramCeccErrThresholdCnt));
            }
        }

        if (pcieEnabled)
        {
            amd::ras::config::Manager::AttributeValue pcieAerErrThresholdCount =
                configMgr.getAttribute("PcieAerErrThresholdCnt");
            int64_t* pcieAerErrThresholdCnt =
                std::get_if<int64_t>(&pcieAerErrThresholdCount);

            if (pcieAerErrThresholdCnt != nullptr)
            {
                lg2::info("Setting PCIe AER error threshold over PLDM for "
                          "processor P{PROCESSOR}",
                          "PROCESSOR", socNum);
                writeErrThresholdOverPldm(
                    socNum, errTypePcie,
                    static_cast<uint64_t>(*pcieAerErrThresholdCnt));
            }
        }
    }
}

void Manager::init()
{
    lg2::info("PLDM MANAGER INIT");

    getCpuSocketInfo();

    loadPlatformConfig();

    // Platform initialization requires PMFW. It is deferred until the PMFW
    // ready signal is received from amd-host-manager.
    subscribePmfwSignals();
}

void Manager::pmfwReadyHandler()
{
    // Perform platform initialization now that the PMFW mailbox is available.
    // Guard against exceptions (e.g. unsupported family) so the service keeps
    // running.
    try
    {
        platformInitialize();
    }
    catch (const std::exception& e)
    {
        lg2::error("Platform initialization failed on PMFW ready: {ERROR}",
                   "ERROR", e.what());
    }
}

void Manager::pmfwNotReadyHandler()
{
    // Mark PLDM/platform uninitialized.
    pldmInitialized = false;
}

void Manager::configure()
{
    lg2::info("PLDM MANAGER CONFIGURE");
    configureSysMgmtCtrlErrAlertHandling();

    // Configuring the error thresholds is a common step across transports and
    // is driven through the base-class configure() virtual. Runtime error
    // polling is not supported in PLDM mode, so only the OOB error thresholds
    // are programmed here.
    if (runtimeErrSupported == true)
    {
        configureErrThresholdsOverPldm();
    }
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

    reconcilePmfwState();
}

void Manager::configureSysMgmtCtrlErrAlertHandling()
{
    // System management control error handling is not supported over the PLDM
    // transport (the ASP endpoint does not generate PLDM events for
    // system/control fabric errors), so there is no alert-handling
    // configuration to apply here.
    lg2::info("System management control error handling is not supported over "
              "PLDM; skipping alert handling configuration");
}

void Manager::registerSysMgmtCtrlErrAlertHandler()
{
    // System management control (control-fabric) errors are delivered to the
    // BMC out-of-band alert path (SBRMI/APML). In PLDM mode the ASP endpoint
    // does not generate PLDM events for system/control fabric errors, so
    // amd-ras cannot receive them over PLDM. This handling is therefore not
    // supported for the PLDM transport.
    lg2::info("System management control error handling is not supported over "
              "PLDM");
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
    std::vector<uint32_t> dataTransferHandles;
    std::vector<uint32_t> eventDataSizes;
    sdbusplus::message::unix_fd eventDataFd;

    try
    {
        msg.read(epochTimestamp, terminusId, terminusName, formatVersion,
                 eventClass, eventId, dataTransferHandles, eventDataSizes,
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
        "numHandles={NHANDLES}",
        "TERMINUS", terminusName, "EVENTID", lg2::hex, eventId, "NHANDLES",
        dataTransferHandles.size());

    for (size_t i = 0; i < dataTransferHandles.size(); i++)
    {
        uint8_t opcode = (dataTransferHandles[i] >> 24) & 0xFF;
        uint8_t dbgLogId = (dataTransferHandles[i] >> 16) & 0xFF;
        uint16_t instance =
            static_cast<uint16_t>(dataTransferHandles[i] & 0xFFFF);
        uint32_t segSize = (i < eventDataSizes.size()) ? eventDataSizes[i] : 0;
        lg2::info(
            "  handle[{IDX}]: opcode=0x{OP} dbgLogId={ID} instance={INST} dataSize={SIZE}",
            "IDX", i, "OP", lg2::hex, opcode, "ID", dbgLogId, "INST", instance,
            "SIZE", segSize);
    }

    // Read error data from the file descriptor
    std::vector<uint8_t> eventData;

    // Sum all segment sizes to get total bytes in the fd
    uint32_t totalDataSize = 0;
    for (auto sz : eventDataSizes)
    {
        totalDataSize += sz;
    }

    if (totalDataSize > 0)
    {
        if (!readEventDataFromFd(eventDataFd, totalDataSize, eventData))
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
            handleFatalOrShutdownError(eventData, dataTransferHandles,
                                       eventDataSizes, socNum, crashdump);
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
            handleMcaOverflowError(eventData, dataTransferHandles,
                                   eventDataSizes, socNum);
            break;

        case pldm::eventIdDramCeccOverflow:
            lg2::error(
                "PLDM RAS Event: DRAM CECC error counter overflow on {TERMINUS}",
                "TERMINUS", terminusName);
            handleDramCeccOverflowError(eventData, dataTransferHandles,
                                        eventDataSizes, socNum);
            break;

        case pldm::eventIdPcieErrOverflow:
            lg2::error(
                "PLDM RAS Event: PCIE error counter overflow on {TERMINUS}",
                "TERMINUS", terminusName);
            handlePcieErrOverflowError(eventData, dataTransferHandles,
                                       eventDataSizes, socNum);
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
            handleFatalOrShutdownError(eventData, dataTransferHandles,
                                       eventDataSizes, socNum, shutdown);
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

void Manager::handleFatalOrShutdownError(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum,
    size_t contextType)
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

    harvestMcaDataBanksOverPldm(eventData, dataTransferHandles, eventDataSizes,
                                socNum, contextType);

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

void Manager::harvestMcaDataBanksOverPldm(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum,
    size_t contextType)
{
    constexpr uint16_t sectionCount = 2;

    if (rcd == nullptr)
    {
        rcd = std::make_shared<FatalCperRecord>();
    }

    initFatalCperRecord(sectionCount);

    // ---------------------------------------------------------------
    // Step 1: Build per-handle byte offsets into the flat eventData
    //         buffer.  Handles arrive in order; their data is
    //         concatenated in the same order in the fd.
    // ---------------------------------------------------------------
    std::vector<size_t> handleDataOffsets(dataTransferHandles.size(), 0);
    {
        size_t offset = 0;
        for (size_t i = 0; i < dataTransferHandles.size(); i++)
        {
            handleDataOffsets[i] = offset;
            if (i < eventDataSizes.size())
            {
                offset += eventDataSizes[i];
            }
        }
    }

    // ---------------------------------------------------------------
    // Step 2: Locate the MCA handle (opcode=0x5C/0x62, DBG_LOG_ID=32) and
    //         determine how many MCA banks the firmware sent.
    //         dataTransferHandle layout: [31:24]=opcode [23:16]=DBG_LOG_ID
    //                                    [15:0]=instance
    // ---------------------------------------------------------------
    uint16_t numMcaBanks = 0;
    uint32_t mcaSegSize = 0;
    size_t mcaDataOffset = 0;

    for (size_t i = 0; i < dataTransferHandles.size(); i++)
    {
        uint8_t opcode = (dataTransferHandles[i] >> 24) & 0xFF;
        uint8_t dbgLogId = (dataTransferHandles[i] >> 16) & 0xFF;
        if (isDebugLogDumpOpcode(opcode) && dbgLogId == mcaDebugLogId)
        {
            mcaSegSize = (i < eventDataSizes.size()) ? eventDataSizes[i] : 0;
            mcaDataOffset = handleDataOffsets[i];
            numMcaBanks = static_cast<uint16_t>(mcaSegSize / mcaDataBankLen);
            break;
        }
    }

    if (numMcaBanks == 0)
    {
        lg2::info("No valid MCA banks found in PLDM event data. "
                  "Harvesting additional debug log ID dumps only.");
    }
    if (numMcaBanks > 32)
    {
        lg2::warning("Invalid MCA bank count {COUNT} from PLDM data, "
                     "clamping to 32",
                     "COUNT", numMcaBanks);
        numMcaBanks = 32;
    }

    lg2::info("Number of Valid MCA bank: {NUMBANKS}", "NUMBANKS", numMcaBanks);

    // Populate processor error section and context
    amd::ras::util::cper::dumpProcessorError(rcd, socNum, cpuId, socIndex,
                                             numMcaBanks);
    amd::ras::util::cper::dumpContext(rcd, numMcaBanks, mcaDataBankLen, socNum,
                                      ppin, uCode, contextType);

    // ---------------------------------------------------------------
    // Step 3: Copy MCA bank data into CrashDumpData.
    // ---------------------------------------------------------------
    constexpr uint16_t maxOffset32 = mcaDataBankLen / 4;
    for (uint16_t n = 0; n < numMcaBanks; n++)
    {
        size_t bankStart =
            mcaDataOffset + static_cast<size_t>(n) * mcaDataBankLen;
        if (bankStart + mcaDataBankLen <= eventData.size())
        {
            std::memcpy(rcd->ErrorRecord[socNum].CrashDumpData[n].McaData,
                        &eventData[bankStart], mcaDataBankLen);
        }
        else
        {
            size_t available = (bankStart < eventData.size())
                                   ? (eventData.size() - bankStart)
                                   : 0;
            if (available > 0)
            {
                std::memcpy(rcd->ErrorRecord[socNum].CrashDumpData[n].McaData,
                            &eventData[bankStart], available);
            }
            for (uint32_t w = static_cast<uint32_t>(available / 4);
                 w < maxOffset32; w++)
            {
                rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[w] = badData;
            }
        }
    }

    // ---------------------------------------------------------------
    // Step 4: Harvest additional debug log ID dumps from all non-MCA
    //         handles.  The firmware sends one handle per (DBG_LOG_ID,
    //         instance) pair.  We reconstruct the APML-compatible
    //         DebugLogIdData layout:
    //           header word: (err_log_len_bytes << 16) |
    //                        (num_instances << 8)      | blkId
    //           followed by the raw 32-bit data words for every instance.
    //
    //         DBG_LOG_IDs to harvest are those present in the firmware
    //         signal; the expected set is read from platform.json at
    //         startup into the blockId vector.
    // ---------------------------------------------------------------
    uint16_t debugLogIdOffset = 0;

    // Collect unique non-MCA DBG_LOG_IDs in signal arrival order.
    std::vector<uint8_t> orderedBlkIds;
    for (size_t i = 0; i < dataTransferHandles.size(); i++)
    {
        uint8_t opcode = (dataTransferHandles[i] >> 24) & 0xFF;
        uint8_t dbgLogId = (dataTransferHandles[i] >> 16) & 0xFF;
        if (!isDebugLogDumpOpcode(opcode) || dbgLogId == mcaDebugLogId)
        {
            continue;
        }
        if (std::find(orderedBlkIds.begin(), orderedBlkIds.end(), dbgLogId) ==
            orderedBlkIds.end())
        {
            orderedBlkIds.push_back(dbgLogId);
        }
    }

    for (uint8_t blkId : orderedBlkIds)
    {
        // Collect all handle indices for this blkId (= all instances).
        std::vector<size_t> instanceHandleIdxs;
        for (size_t i = 0; i < dataTransferHandles.size(); i++)
        {
            uint8_t opcode = (dataTransferHandles[i] >> 24) & 0xFF;
            uint8_t dbgLogId = (dataTransferHandles[i] >> 16) & 0xFF;
            if (isDebugLogDumpOpcode(opcode) && dbgLogId == blkId)
            {
                instanceHandleIdxs.push_back(i);
            }
        }

        uint32_t numInstances =
            static_cast<uint32_t>(instanceHandleIdxs.size());
        size_t firstIdx = instanceHandleIdxs[0];
        uint32_t errLogLen =
            (firstIdx < eventDataSizes.size()) ? eventDataSizes[firstIdx] : 0;

        if (debugLogIdOffset >= debugDumpDataLen)
        {
            lg2::warning("DebugLogIdData buffer full, skipping blkId {ID}",
                         "ID", blkId);
            break;
        }

        // Write APML-compatible header word.
        uint32_t header = (errLogLen << 16) | (numInstances << 8) |
                          static_cast<uint32_t>(blkId);
        rcd->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] = header;

        lg2::info("Socket {SOC}: Debug Log ID : {ID} read successful, "
                  "Block instance : {INST} , Err log length : {LEN}",
                  "SOC", socNum, "ID", blkId, "INST", numInstances, "LEN",
                  errLogLen);

        // Write raw data words for each instance.
        for (size_t handleIdx : instanceHandleIdxs)
        {
            if (debugLogIdOffset >= debugDumpDataLen)
            {
                lg2::warning("DebugLogIdData buffer full mid-instance for "
                             "blkId {ID}",
                             "ID", blkId);
                break;
            }

            size_t segOffset = handleDataOffsets[handleIdx];
            uint32_t segSize = (handleIdx < eventDataSizes.size())
                                   ? eventDataSizes[handleIdx]
                                   : 0;
            uint32_t numWords = (segSize + 3) / 4;

            for (uint32_t w = 0; w < numWords; w++)
            {
                if (debugLogIdOffset >= debugDumpDataLen)
                {
                    break;
                }
                uint32_t word = badData;
                size_t byteOff = segOffset + static_cast<size_t>(w) * 4;
                if (byteOff + 4 <= eventData.size())
                {
                    std::memcpy(&word, &eventData[byteOff], 4);
                }
                else if (byteOff < eventData.size())
                {
                    word = 0;
                    std::memcpy(&word, &eventData[byteOff],
                                eventData.size() - byteOff);
                }
                rcd->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
                    word;
            }
        }
    }

    processMcaBankSignatures(socNum, numMcaBanks);
}

bool Manager::readEventDataFromFd(int fd, uint32_t eventDataSize,
                                  std::vector<uint8_t>& eventData)
{
    eventData.resize(eventDataSize);
    ssize_t totalBytesRead = 0;

    while (totalBytesRead < static_cast<ssize_t>(eventDataSize))
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

void Manager::handleRuntimeOverflowError(
    const char* journalMessage, const char* overflowType,
    const char* thresholdEnableAttr, const char* thresholdCountAttr,
    OverflowHarvestHandler harvestHandler,
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    sd_journal_send("MESSAGE=%s", journalMessage, "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", journalMessage, NULL);

    if (!(this->*harvestHandler)(eventData, dataTransferHandles, eventDataSizes,
                                 socNum))
    {
        lg2::info(
            "PLDM {TYPE} overflow received without runtime payload on socket {SOC}",
            "TYPE", overflowType, "SOC", socNum);
    }

    uint64_t thresholdCount =
        configMgr.getThresholdCount(thresholdEnableAttr, thresholdCountAttr);
    configMgr.incrementCorrectableOtherError(socNum, thresholdCount);
    configMgr.updateErrorCountDbus();
    configMgr.saveErrorCounts();
}

void Manager::handleMcaOverflowError(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    handleRuntimeOverflowError(
        "MCA runtime error counter overflow occured", "MCA",
        "McaErrThresholdEnable", "McaErrThresholdCount",
        &Manager::harvestMcaRuntimeOverflowOverPldm, eventData,
        dataTransferHandles, eventDataSizes, socNum);
}

bool Manager::harvestMcaRuntimeOverflowOverPldm(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    std::unique_lock lock(harvestMutex);

    auto handleDataOffsets =
        buildHandleDataOffsets(dataTransferHandles, eventDataSizes);
    auto [mcaDataOffset, mcaSegSize] =
        findSegmentForOverflowCategory(overflowCategoryMca, dataTransferHandles,
                                       eventDataSizes, handleDataOffsets);

    uint16_t sectionCount = static_cast<uint16_t>(mcaSegSize / mcaDataBankLen);
    if (sectionCount == 0)
    {
        lg2::info("No runtime MCA sections found for socket {SOC}", "SOC",
                  socNum);
        return false;
    }

    if (sectionCount > 32)
    {
        lg2::warning(
            "Invalid runtime MCA section count {COUNT}, clamping to 32",
            "COUNT", sectionCount);
        sectionCount = 32;
    }

    return harvestRuntimeOverflowSections(mcaPtr, eventData, mcaDataOffset,
                                          sectionCount, socNum, runtimeMcaErr);
}

bool Manager::harvestRuntimeOverflowSections(
    std::shared_ptr<McaRuntimeCperRecord>& ptr,
    const std::vector<uint8_t>& eventData, size_t dataOffset,
    uint16_t sectionCount, uint8_t socNum, std::string_view errType)
{
    if (ptr == nullptr)
    {
        ptr = std::make_shared<McaRuntimeCperRecord>();
    }

    ptr->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    std::memset(ptr->SectionDescriptor, 0,
                sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount);

    ptr->McaErrorInfo = new RUNTIME_ERROR_INFO[sectionCount];
    std::memset(ptr->McaErrorInfo, 0,
                sizeof(RUNTIME_ERROR_INFO) * sectionCount);

    std::vector<uint32_t> severity(sectionCount, 2);
    std::vector<uint64_t> checkInfo(sectionCount, 0);

    for (uint16_t i = 0; i < sectionCount; i++)
    {
        size_t bankStart = dataOffset + static_cast<size_t>(i) * mcaDataBankLen;
        size_t available = 0;
        if (bankStart < eventData.size())
        {
            available = std::min(static_cast<size_t>(mcaDataBankLen),
                                 eventData.size() - bankStart);
            std::memcpy(ptr->McaErrorInfo[i].DumpData, &eventData[bankStart],
                        available);
        }

        if (available < mcaDataBankLen)
        {
            const size_t startWord = available / sizeof(uint32_t);
            for (size_t w = startWord; w < length32; w++)
            {
                ptr->McaErrorInfo[i].DumpData[w] = badData;
            }
        }

        uint64_t mcaStatusRegister =
            (static_cast<uint64_t>(
                 ptr->McaErrorInfo[i].DumpData[mcaStatusHiOffset / 4])
             << 32) |
            static_cast<uint64_t>(
                ptr->McaErrorInfo[i].DumpData[mcaStatusLoOffset / 4]);

        checkInfo[i] = 0;
        checkInfo[i] |= ((mcaStatusRegister >> 57) & 1ULL) << 19;
        checkInfo[i] |= ((mcaStatusRegister >> 61) & 1ULL) << 20;
        checkInfo[i] |= ((mcaStatusRegister >> 62) & 1ULL) << 23;
        checkInfo[i] |= (5ULL << 16);

        if (((mcaStatusRegister & (1ULL << 61)) == 0) &&
            ((mcaStatusRegister & (1ULL << 44)) == 0))
        {
            severity[i] = 2; // Non-fatal corrected
        }
        else if ((((mcaStatusRegister & (1ULL << 61)) == 0) &&
                  ((mcaStatusRegister & (1ULL << 44)) != 0)) ||
                 (((mcaStatusRegister & (1ULL << 61)) != 0) &&
                  ((mcaStatusRegister & (1ULL << 57)) == 0)))
        {
            severity[i] = 0; // Non-fatal uncorrected
        }

        std::snprintf(ptr->SectionDescriptor[i].FruString,
                      sizeof(ptr->SectionDescriptor[i].FruString), "P%u",
                      socNum);
    }

    amd::ras::util::cper::dumpProcErrorInfoSection(
        ptr, sectionCount, checkInfo.data(), 0, static_cast<uint8_t>(cpuCount),
        cpuId);

    uint32_t highestSeverity = amd::ras::util::cper::sevInformational;
    amd::ras::util::cper::calculateSeverity(severity.data(), sectionCount,
                                            &highestSeverity, errType);

    amd::ras::util::cper::dumpHeader(ptr, sectionCount, highestSeverity,
                                     errType, boardId, recordId);

    amd::ras::util::cper::dumpErrorDescriptor(ptr, sectionCount, errType,
                                              severity.data(), progId);

    amd::ras::util::cper::createFile(ptr, errType, sectionCount, errCount,
                                     node);
    amd::ras::util::cper::exportToDBus(errCount, ptr->Header.TimeStamp,
                                       objectServer, systemBus, node);
    amd::ras::util::cper::updateIndexFile(errCount, node);

    delete[] ptr->SectionDescriptor;
    ptr->SectionDescriptor = nullptr;
    delete[] ptr->McaErrorInfo;
    ptr->McaErrorInfo = nullptr;
    ptr = nullptr;

    return true;
}

bool Manager::harvestRuntimeOverflowSections(
    std::shared_ptr<PcieRuntimeCperRecord>& ptr,
    const std::vector<uint8_t>& eventData, size_t dataOffset,
    uint16_t sectionCount, uint8_t socNum, std::string_view errType)
{
    constexpr uint32_t pcieDataBankLen =
        static_cast<uint32_t>(length91 * sizeof(uint32_t));

    if (ptr == nullptr)
    {
        ptr = std::make_shared<PcieRuntimeCperRecord>();
    }

    ptr->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    std::memset(ptr->SectionDescriptor, 0,
                sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount);

    ptr->PcieErrorData = new EFI_AMD_PCIE_ERROR_DATA[sectionCount];
    std::memset(ptr->PcieErrorData, 0,
                sizeof(EFI_AMD_PCIE_ERROR_DATA) * sectionCount);

    std::vector<uint32_t> severity(sectionCount, 2);

    // The first 4 bytes of each PCIe section returned by PMFW are AMD custom
    // data carrying the error severity. They are not part of the standard UEFI
    // PCIe error section, so they are discarded from the CPER body; only the
    // standard PCIe error info that follows is copied.
    constexpr uint32_t amdCustomDataLen = sizeof(uint32_t);
    constexpr uint32_t pcieStdDataLen = pcieDataBankLen - amdCustomDataLen;

    for (uint16_t i = 0; i < sectionCount; i++)
    {
        size_t sectionStart =
            dataOffset + static_cast<size_t>(i) * pcieDataBankLen;

        // Extract the AMD custom severity dword and log it for debug before
        // discarding it from the CPER body.
        uint32_t rootErrStatus = badData;
        if (sectionStart + amdCustomDataLen <= eventData.size())
        {
            std::memcpy(&rootErrStatus, &eventData[sectionStart],
                        amdCustomDataLen);
        }

        lg2::info(
            "Socket {SOCKET}: PCIe Error collected on Root Port "
            "{ROOTPORT}, PCIe Controller {CONTROLLER}, IOD {IOD}, "
            "severity {SEVERITY}",
            "SOCKET", socNum, "ROOTPORT",
            (rootErrStatus >> amd::ras::util::cper::pcieRootPortShift) &
                amd::ras::util::cper::severityByteMask,
            "CONTROLLER",
            (rootErrStatus >> amd::ras::util::cper::pcieControllerShift) &
                amd::ras::util::cper::severityByteMask,
            "IOD",
            (rootErrStatus >> amd::ras::util::cper::pcieIodShift) &
                amd::ras::util::cper::severityByteMask,
            "SEVERITY", rootErrStatus & amd::ras::util::cper::severityByteMask);

        // Extract the severity code from the low byte of the custom DWORD.
        severity[i] = rootErrStatus & amd::ras::util::cper::severityByteMask;

        // Copy only the standard PCIe error info that follows the custom dword.
        size_t pcieDataStart = sectionStart + amdCustomDataLen;
        size_t available = 0;
        if (pcieDataStart < eventData.size())
        {
            available = std::min(static_cast<size_t>(pcieStdDataLen),
                                 eventData.size() - pcieDataStart);
            std::memcpy(ptr->PcieErrorData[i].PcieData,
                        &eventData[pcieDataStart], available);
        }

        if (available < pcieDataBankLen)
        {
            const size_t startWord = available / sizeof(uint32_t);
            for (size_t w = startWord; w < length91; w++)
            {
                ptr->PcieErrorData[i].PcieData[w] = badData;
            }
        }

        std::snprintf(ptr->SectionDescriptor[i].FruString,
                      sizeof(ptr->SectionDescriptor[i].FruString), "P%u",
                      socNum);
    }

    uint32_t highestSeverity = amd::ras::util::cper::sevInformational;
    amd::ras::util::cper::calculateSeverity(severity.data(), sectionCount,
                                            &highestSeverity, errType);

    amd::ras::util::cper::dumpHeader(ptr, sectionCount, highestSeverity,
                                     errType, boardId, recordId);

    amd::ras::util::cper::dumpErrorDescriptor(ptr, sectionCount, errType,
                                              severity.data(), progId);

    amd::ras::util::cper::createFile(ptr, errType, sectionCount, errCount,
                                     node);
    amd::ras::util::cper::exportToDBus(errCount, ptr->Header.TimeStamp,
                                       objectServer, systemBus, node);
    amd::ras::util::cper::updateIndexFile(errCount, node);

    delete[] ptr->SectionDescriptor;
    ptr->SectionDescriptor = nullptr;
    delete[] ptr->PcieErrorData;
    ptr->PcieErrorData = nullptr;
    ptr = nullptr;

    return true;
}

void Manager::handleDramCeccOverflowError(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    handleRuntimeOverflowError(
        "DRAM CECC runtime error counter overflow occured", "DRAM CECC",
        "DramCeccErrThresholdEnable", "DramCeccErrThresholdCount",
        &Manager::harvestDramCeccRuntimeOverflowOverPldm, eventData,
        dataTransferHandles, eventDataSizes, socNum);
}

bool Manager::harvestDramCeccRuntimeOverflowOverPldm(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    std::unique_lock lock(harvestMutex);

    auto handleDataOffsets =
        buildHandleDataOffsets(dataTransferHandles, eventDataSizes);
    auto [dramDataOffset, dramSegSize] = findSegmentForOverflowCategory(
        overflowCategoryDramCecc, dataTransferHandles, eventDataSizes,
        handleDataOffsets);

    uint16_t sectionCount = static_cast<uint16_t>(dramSegSize / mcaDataBankLen);
    if (sectionCount == 0)
    {
        lg2::info("No runtime DRAM CECC sections found for socket {SOC}", "SOC",
                  socNum);
        return false;
    }

    if (sectionCount > 32)
    {
        lg2::warning(
            "Invalid runtime DRAM CECC section count {COUNT}, clamping to 32",
            "COUNT", sectionCount);
        sectionCount = 32;
    }

    return harvestRuntimeOverflowSections(dramPtr, eventData, dramDataOffset,
                                          sectionCount, socNum, runtimeDramErr);
}

void Manager::handlePcieErrOverflowError(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    handleRuntimeOverflowError(
        "PCIE runtime error counter overflow occured", "PCIe",
        "PcieErrThresholdEnable", "PcieErrThresholdCount",
        &Manager::harvestPcieRuntimeOverflowOverPldm, eventData,
        dataTransferHandles, eventDataSizes, socNum);
}

bool Manager::harvestPcieRuntimeOverflowOverPldm(
    const std::vector<uint8_t>& eventData,
    const std::vector<uint32_t>& dataTransferHandles,
    const std::vector<uint32_t>& eventDataSizes, uint8_t socNum)
{
    std::unique_lock lock(harvestMutex);

    auto handleDataOffsets =
        buildHandleDataOffsets(dataTransferHandles, eventDataSizes);
    auto [pcieDataOffset, pcieSegSize] = findSegmentForOverflowCategory(
        overflowCategoryPcie, dataTransferHandles, eventDataSizes,
        handleDataOffsets);

    constexpr uint32_t pcieDataBankLen =
        static_cast<uint32_t>(length91 * sizeof(uint32_t));
    uint16_t sectionCount =
        static_cast<uint16_t>(pcieSegSize / pcieDataBankLen);
    if (sectionCount == 0)
    {
        lg2::info("No runtime PCIe sections found for socket {SOC}", "SOC",
                  socNum);
        return false;
    }

    if (sectionCount > 32)
    {
        lg2::warning(
            "Invalid runtime PCIe section count {COUNT}, clamping to 32",
            "COUNT", sectionCount);
        sectionCount = 32;
    }

    return harvestRuntimeOverflowSections(pciePtr, eventData, pcieDataOffset,
                                          sectionCount, socNum, runtimePcieErr);
}

} // namespace pldm
} // namespace ras
} // namespace amd
