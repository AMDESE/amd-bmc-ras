#include "base_manager.hpp"

#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "linux/amd-apml.h"
}

#include <syslog.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>

#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <utility>

constexpr size_t base16 = 16;
constexpr size_t maxByte = 0xFF;
constexpr uint32_t badData = 0xBAADDA7A;
constexpr size_t breakEventContext = 3;
constexpr uint16_t breakEventBanks = 1;

namespace amd
{
namespace ras
{
namespace fs = std::filesystem;

constexpr std::string_view inventoryService =
    "xyz.openbmc_project.Inventory.Item.Cpu_info";
constexpr std::string_view inventoryInterface =
    "xyz.openbmc_project.Inventory.Item.Cpu";

void Manager::getCpuSocketInfo()
{
    // Try to copy the platform default file, throw exception if it fails
    try
    {
        std::filesystem::copy_file(
            SRC_PLATFORM_DEFAULT_FILE, PLATFORM_DEFAULT_FILE,
            std::filesystem::copy_options::overwrite_existing);
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        lg2::error("Failed to copy platform default file : {ERROR}", "ERROR",
                   strerror(errno));
        throw std::runtime_error("Failed to copy platform default file");
    }

    std::ifstream file("/var/lib/platform-config/platform.json");

    if (!file.is_open())
    {
        file.open(PLATFORM_DEFAULT_FILE);
    }

    if (!file.is_open())
    {
        throw std::runtime_error("Unable to open platform config file");
    }

    if (file.peek() == std::ifstream::traits_type::eof())
    {
        throw std::runtime_error("Platform config file is empty");
    }

    nlohmann::json jsonData = nlohmann::json::parse(file);

    if (jsonData.contains("CpuCount"))
    {
        cpuCount = jsonData["CpuCount"];
    }
    else
    {
        throw std::runtime_error("Unable to read the CPU count");
    }

    if (node == "0")
    {
        for (size_t i = 0; i < cpuCount; i++)
        {
            socIndex.push_back(i);
        }
    }
    else
    {
        cpuCount = 1;
        size_t socNum = std::stoul(node) - 1;
        socIndex.push_back(socNum);
    }

    file.close();

    validateSocketTopology();

    cpuId = std::make_unique<CpuId[]>(cpuCount);

    uCode = std::make_unique<uint32_t[]>(cpuCount);
    std::memset(uCode.get(), 0, cpuCount * sizeof(uint32_t));

    ppin = std::make_unique<uint64_t[]>(cpuCount);
    std::memset(ppin.get(), 0, cpuCount * sizeof(uint64_t));

    inventoryPath = std::make_unique<std::string[]>(cpuCount);

    for (size_t i = 0; i < cpuCount; i++)
    {
        inventoryPath[i] = "/xyz/openbmc_project/inventory/system/processor/P" +
                           std::to_string(socIndex[i]);
    }

    amd::ras::config::Manager::AttributeValue uCodeVersion =
        configMgr.getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    amd::ras::config::Manager::AttributeValue harvestPpin =
        configMgr.getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    if (*uCodeVersionFlag == true || *harvestPpinFlag == true)
    {
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

        for (size_t i = 0; i < cpuCount; i++)
        {
            if (*uCodeVersionFlag == true)
            {
                try
                {
                    uint32_t microCode = amd::ras::util::getProperty<uint32_t>(
                        bus, inventoryService.data(), inventoryPath[i].c_str(),
                        inventoryInterface.data(), "Microcode");

                    uCode[i] = microCode;
                    lg2::info("Microcode = {VAL}", "VAL", lg2::hex, microCode);
                }
                catch (const std::exception& e)
                {
                    lg2::error("Failed to get Microcode property: {ERR}", "ERR",
                               e.what());
                }
            }

            if (*harvestPpinFlag == true)
            {
                try
                {
                    uint64_t ppinVal = amd::ras::util::getProperty<uint64_t>(
                        bus, inventoryService.data(), inventoryPath[i].c_str(),
                        inventoryInterface.data(), "Id");

                    ppin[i] = ppinVal;
                    lg2::info("PPIN = {VAL}", "VAL", lg2::hex, ppinVal);
                }
                catch (const std::exception& e)
                {
                    lg2::error("Failed to get PPIN property: {ERR}", "ERR",
                               e.what());
                }
            }
        }
    }
    amd::ras::util::cper::createIndexFile(errCount, node);
}

Manager::Manager(amd::ras::config::Manager& manager,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 std::string& node) :
    errCount(0), progId(1), recordId(1), configMgr(manager), rcd(nullptr),
    mcaPtr(nullptr), dramPtr(nullptr), pciePtr(nullptr),
    coreDebugDumpPtr(nullptr), node(node), whFamilyId(0), systemBus(systemBus)
{}

void Manager::subscribePmfwSignals()
{
    std::string pmfwPath = std::string(pmfwStatusPathPrefix) + node;

    std::string matchRule =
        "type='signal',interface='" + std::string(pmfwStatusInterface) +
        "',path='" + pmfwPath + "',member='" + std::string(pmfwStatusSignal) +
        "'";

    try
    {
        pmfwStatusMatch = std::make_unique<sdbusplus::bus::match_t>(
            static_cast<sdbusplus::bus_t&>(*systemBus), matchRule,
            [this](sdbusplus::message_t& msg) {
                bool ready = false;
                try
                {
                    msg.read(ready);
                }
                catch (const std::exception& e)
                {
                    lg2::error("Failed to read PMFW status signal for node "
                               "{NODE}: {ERROR}",
                               "NODE", node, "ERROR", e.what());
                    return;
                }

                lg2::info("PMFW status notification received for node {NODE}: "
                          "ready={READY}",
                          "NODE", node, "READY", ready);
                applyPmfwStatus(ready);
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to subscribe to PMFW status signal on {PATH}: "
                   "{ERROR}",
                   "PATH", pmfwPath, "ERROR", e.what());
        return;
    }

    lg2::info("Subscribed to PMFW status signal on {PATH}", "PATH", pmfwPath);
}

void Manager::applyPmfwStatus(bool ready)
{
    if (ready)
    {
        pmfwReadyHandler();
    }
    else
    {
        pmfwNotReadyHandler();
    }
}

void Manager::reconcilePmfwState()
{
    // The PMFW status signal is transient. If the host is already powered on
    // when this service starts (e.g. a RAS restart while the host is running),
    // the ready notification may have been emitted and missed. Reconcile by
    // applying the ready state now. Platform initialization is idempotent, so
    // a subsequent ready signal is harmless.
    if (isHostPoweredOn())
    {
        lg2::info("Host already powered on at startup; reconciling PMFW ready "
                  "state for node {NODE}",
                  "NODE", node);
        applyPmfwStatus(true);
    }
}

void Manager::loadPlatformConfig()
{
    std::ifstream file("/var/lib/platform-config/platform.json");
    if (!file.is_open())
    {
        file.open(PLATFORM_DEFAULT_FILE);
    }

    if (!file.is_open())
    {
        throw std::runtime_error("Unable to open platform config file");
    }

    if (file.peek() == std::ifstream::traits_type::eof())
    {
        throw std::runtime_error("Platform config file is empty");
    }

    nlohmann::json jsonData = nlohmann::json::parse(file);

    if (jsonData.contains("Model"))
    {
        if (jsonData["Model"].is_array())
        {
            for (const auto& m : jsonData["Model"])
            {
                whModels.push_back(
                    std::stoi(m.get<std::string>(), nullptr, 16));
            }
        }
        else
        {
            std::string modelStr = jsonData["Model"];
            whModels.push_back(std::stoi(modelStr, nullptr, 16));
        }
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
}

void Manager::currentHostStateMonitor()
{
    hostStateMatch = std::make_unique<sdbusplus::bus::match_t>(
        static_cast<sdbusplus::bus_t&>(*systemBus),
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Host'",
        [this](sdbusplus::message::message& message) {
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

            bool hostOff = (*currentHostState ==
                            "xyz.openbmc_project.State.Host.HostState.Off");
            onHostStateChanged(hostOff);
        });
}

bool Manager::isHostPoweredOn()
{
    try
    {
        std::string hostService = "xyz.openbmc_project.State.Host" + node;
        std::string hostPath = "/xyz/openbmc_project/state/host" + node;

        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
        std::string currentHostState = amd::ras::util::getProperty<std::string>(
            bus, hostService.c_str(), hostPath.c_str(),
            "xyz.openbmc_project.State.Host", "CurrentHostState");

        return currentHostState !=
               "xyz.openbmc_project.State.Host.HostState.Off";
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to query host power state: {ERROR}", "ERROR",
                   e.what());
        return false;
    }
}

void Manager::handleFchError(uint8_t socNum)
{
    std::string rasErrMsg = "System hang while resetting in syncflood."
                            "Suggested next step is to do an additional manual "
                            "immediate reset";
    sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);

    configMgr.incrementNoncorrectableOtherError(socNum);
    configMgr.updateErrorCountDbus();
    configMgr.saveErrorCounts();
}

uint16_t Manager::fatalSectionCount() const
{
    return static_cast<uint16_t>(cpuCount);
}

bool Manager::toLogicalIndex(uint8_t socNum, size_t& logicalIdx) const
{
    auto it = std::find(socIndex.begin(), socIndex.end(),
                        static_cast<size_t>(socNum));

    if (it == socIndex.end())
    {
        return false;
    }

    logicalIdx = static_cast<size_t>(std::distance(socIndex.begin(), it));
    return true;
}

std::string Manager::socketTopologyStr() const
{
    std::string topology;

    for (size_t soc : socIndex)
    {
        if (!topology.empty())
        {
            topology += ", ";
        }
        topology += "P" + std::to_string(soc);
    }

    return topology;
}

void Manager::validateSocketTopology() const
{
    if (cpuCount == 0)
    {
        throw std::runtime_error("CPU count is zero in the platform config");
    }

    if (socIndex.size() != cpuCount)
    {
        throw std::runtime_error(
            "Socket map holds " + std::to_string(socIndex.size()) +
            " entries for a CPU count of " + std::to_string(cpuCount));
    }

    std::set<size_t> seen;

    for (size_t soc : socIndex)
    {
        if (soc > maxByte)
        {
            throw std::runtime_error("Socket number P" + std::to_string(soc) +
                                     " is not addressable over APML");
        }

        if (!seen.insert(soc).second)
        {
            throw std::runtime_error("Socket P" + std::to_string(soc) +
                                     " is listed more than once in the "
                                     "configured topology");
        }
    }
}

void Manager::cleanupFatalCperRecord()
{
    fatalDescriptorsInitialized = false;
    if (rcd != nullptr)
    {
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
    }
}

void Manager::initFatalCperRecord(uint16_t sectionCount)
{
    uint32_t errorSeverity = 1;

    if (rcd->SectionDescriptor == nullptr)
    {
        rcd->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
        std::memset(rcd->SectionDescriptor, 0,
                    sectionCount * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
    }

    if (rcd->ErrorRecord == nullptr)
    {
        rcd->ErrorRecord = new EFI_AMD_FATAL_ERROR_DATA[sectionCount];
        std::memset(rcd->ErrorRecord, 0,
                    sectionCount * sizeof(EFI_AMD_FATAL_ERROR_DATA));
    }

    if (!fatalDescriptorsInitialized)
    {
        amd::ras::util::cper::dumpHeader(rcd, sectionCount, errorSeverity,
                                         fatalErr, boardId, recordId);
        amd::ras::util::cper::dumpErrorDescriptor(
            rcd, sectionCount, fatalErr, &errorSeverity, progId, socIndex);
        fatalDescriptorsInitialized = true;
    }
}

void Manager::processMcaBankSignatures(size_t sectionIdx, uint16_t numBanks)
{
    amd::ras::config::Manager::AttributeValue sigIdOffsetVal =
        configMgr.getAttribute("SigIdOffset");
    std::vector<std::string>* sigIDOffset =
        std::get_if<std::vector<std::string>>(&sigIdOffsetVal);

    uint32_t syndOffsetLo = std::stoul((*sigIDOffset)[0], nullptr, base16);
    uint32_t syndOffsetHi = std::stoul((*sigIDOffset)[1], nullptr, base16);
    uint32_t ipidOffsetLo = std::stoul((*sigIDOffset)[2], nullptr, base16);
    uint32_t ipidOffsetHi = std::stoul((*sigIDOffset)[3], nullptr, base16);
    uint32_t statusOffsetLo = std::stoul((*sigIDOffset)[4], nullptr, base16);
    uint32_t statusOffsetHi = std::stoul((*sigIDOffset)[5], nullptr, base16);

    for (uint16_t n = 0; n < numBanks; n++)
    {
        uint32_t mcaStatusLo = rcd->ErrorRecord[sectionIdx]
                                   .CrashDumpData[n]
                                   .McaData[statusOffsetLo / 4];
        uint32_t mcaStatusHi = rcd->ErrorRecord[sectionIdx]
                                   .CrashDumpData[n]
                                   .McaData[statusOffsetHi / 4];
        uint32_t mcaIpidLo = rcd->ErrorRecord[sectionIdx]
                                 .CrashDumpData[n]
                                 .McaData[ipidOffsetLo / 4];
        uint32_t mcaIpidHi = rcd->ErrorRecord[sectionIdx]
                                 .CrashDumpData[n]
                                 .McaData[ipidOffsetHi / 4];
        uint32_t mcaSyndLo = rcd->ErrorRecord[sectionIdx]
                                 .CrashDumpData[n]
                                 .McaData[syndOffsetLo / 4];
        uint32_t mcaSyndHi = rcd->ErrorRecord[sectionIdx]
                                 .CrashDumpData[n]
                                 .McaData[syndOffsetHi / 4];

        uint32_t mcaPspSynd1Lo = rcd->ErrorRecord[sectionIdx]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd1LoCode / 4];
        uint32_t mcaPspSynd1Hi = rcd->ErrorRecord[sectionIdx]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd1HiCode / 4];
        uint32_t mcaPspSynd2Lo = rcd->ErrorRecord[sectionIdx]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd2LoCode / 4];
        uint32_t mcaPspSynd2Hi = rcd->ErrorRecord[sectionIdx]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd2HiCode / 4];

        if ((mcaStatusHi & (1 << 25)) && (mcaStatusHi & (1 << 23)))
        {
            amd::ras::util::cper::populateSignatureId(
                rcd->ErrorRecord[sectionIdx], mcaSyndLo, mcaSyndHi, mcaIpidLo,
                mcaIpidHi, mcaStatusLo, mcaStatusHi);
        }

        constexpr size_t mcaConfigLoOffset = 0x20;
        constexpr uint32_t mcaFruTextInMcaBit = 9;
        uint32_t mcaConfigLo = rcd->ErrorRecord[sectionIdx]
                                   .CrashDumpData[n]
                                   .McaData[mcaConfigLoOffset / 4];

        if ((mcaConfigLo & (1U << mcaFruTextInMcaBit)) != 0)
        {
            amd::ras::util::cper::populateFruStringPspSynd(
                rcd->SectionDescriptor[sectionIdx], mcaPspSynd1Lo,
                mcaPspSynd1Hi, mcaPspSynd2Lo, mcaPspSynd2Hi);
        }
    }
}

void Manager::harvestBreakEvent(uint8_t socNum)
{
    constexpr uint8_t baseReg = 0x80;
    constexpr size_t regCount = 8;

    size_t sectionIdx = 0;
    if (!toLogicalIndex(socNum, sectionIdx))
    {
        lg2::error("Break event reported for socket P{SOC}, which is not part "
                   "of the configured topology [{TOPOLOGY}]. Dropping the "
                   "event.",
                   "SOC", socNum, "TOPOLOGY", socketTopologyStr());
        return;
    }

    const uint16_t sectionCount = fatalSectionCount();

    if (rcd == nullptr)
    {
        rcd = std::make_shared<FatalCperRecord>();
    }

    initFatalCperRecord(sectionCount);

    amd::ras::util::cper::dumpProcessorError(rcd, sectionIdx, cpuId,
                                             breakEventBanks);
    amd::ras::util::cper::dumpContext(rcd, breakEventBanks, 0, sectionIdx, ppin,
                                      uCode, breakEventContext);

    for (uint16_t section = 0; section < sectionCount; ++section)
    {
        std::memset(rcd->SectionDescriptor[section].FruString, 0, 20);
        std::strncpy(rcd->SectionDescriptor[section].FruString, "SmnError", 19);
        rcd->SectionDescriptor[section].FruString[19] = '\0';
    }

    for (size_t offset = 0; offset < regCount; ++offset)
    {
        uint8_t regValue = 0;
        const uint32_t reg = static_cast<uint32_t>(baseReg + offset);
        oob_status_t ret = esmi_oob_read_byte(socNum, reg, SBRMI, &regValue);

        if (ret != OOB_SUCCESS)
        {
            uint16_t retryCount = 10;
            while (retryCount > 0)
            {
                ret = esmi_oob_read_byte(socNum, reg, SBRMI, &regValue);
                if (ret == OOB_SUCCESS)
                {
                    break;
                }
                retryCount--;
                sleep(1);
            }
        }

        if (ret != OOB_SUCCESS)
        {
            lg2::error("Socket {SOC}: Failed to read register: {REGISTER}",
                       "SOC", socNum, "REGISTER", lg2::hex, reg);
            rcd->ErrorRecord[sectionIdx].CrashDumpData[0].McaData[offset] =
                badData;
            continue;
        }

        rcd->ErrorRecord[sectionIdx].CrashDumpData[0].McaData[offset] =
            regValue;
    }

    // Keep break-event records aligned with existing APML/PLDM CPER format.
    rcd->ErrorRecord[sectionIdx].RegisterArraySize = 32;
}

constexpr const char* hpmFpgaDumpCommand =
    "/usr/sbin/hpm-fpga-dump.sh > /var/lib/amd-ras/fpga_dump.txt 2>&1 &";

bool Manager::armPlatformGpio(PlatformGpioWatch& watch,
                              boost::asio::io_context& io)
{
    try
    {
        watch.line = gpiod::find_line(watch.name);
        if (!watch.line)
        {
            lg2::warning("Platform GPIO {GPIO} is not present; skipping",
                         "GPIO", watch.name);
            return false;
        }

        watch.line.request({"RAS", gpiod::line_request::EVENT_BOTH_EDGES, 0});

        const int gpioFd = watch.line.event_get_fd();
        if (gpioFd < 0)
        {
            lg2::error(
                "Failed to get the file descriptor for platform GPIO {GPIO}; "
                "skipping",
                "GPIO", watch.name);
            watch.line.release();
            return false;
        }

        watch.descriptor =
            std::make_unique<boost::asio::posix::stream_descriptor>(io);
        watch.descriptor->assign(gpioFd);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to arm platform GPIO {GPIO}: {ERROR}. Skipping",
                   "GPIO", watch.name, "ERROR", e.what());
        if (watch.line)
        {
            try
            {
                watch.line.release();
            }
            catch (const std::exception& releaseError)
            {
                lg2::debug("Releasing platform GPIO {GPIO} failed: {ERROR}",
                           "GPIO", watch.name, "ERROR", releaseError.what());
            }
        }
        watch.descriptor.reset();
        return false;
    }

    lg2::info("Armed platform GPIO {GPIO}", "GPIO", watch.name);
    return true;
}

void Manager::registerPlatformGpioAlerts(boost::asio::io_context& io)
{
    struct GpioSpec
    {
        const char* name;
        const char* message;
        bool dumpHpmRegisters;
    };

    // P0 is always present on Turin. P1 follows the configured socket count.
    // HPM lockout is a board line, not a per-socket alert.
    std::vector<GpioSpec> specs = {
        {"P0_DIMM_AF_ERROR",
         "P0 DIMM A-F PMIC FATAL Error detected. System will be power off",
         false},
        {"P0_DIMM_GL_ERROR",
         "P0 DIMM G-L PMIC FATAL Error detected. System will be power off",
         false},
    };

    if (cpuCount > 1)
    {
        specs.push_back(
            {"P1_DIMM_AF_ERROR",
             "P1 DIMM A-F PMIC FATAL Error detected. System will be power off",
             false});
        specs.push_back(
            {"P1_DIMM_GL_ERROR",
             "P1 DIMM G-L PMIC FATAL Error detected. System will be power off",
             false});
    }

    specs.push_back(
        {"HPM_FPGA_LOCKOUT",
         "HPM FPGA detected fatal error. FPGA registers dumped to "
         "/var/lib/amd-ras/fpga_dump.txt. A/C power cycle to recover",
         true});

    for (const auto& spec : specs)
    {
        auto watch = std::make_unique<PlatformGpioWatch>();
        watch->name = spec.name;
        watch->message = spec.message;
        watch->dumpHpmRegisters = spec.dumpHpmRegisters;
        if (!armPlatformGpio(*watch, io))
        {
            continue;
        }

        platformGpioWatches.push_back(std::move(watch));
        watchPlatformGpio(platformGpioWatches.size() - 1);
    }
}

void Manager::watchPlatformGpio(size_t index)
{
    if ((index >= platformGpioWatches.size()) ||
        (platformGpioWatches[index] == nullptr) ||
        (platformGpioWatches[index]->descriptor == nullptr) ||
        !platformGpioWatches[index]->descriptor->is_open())
    {
        return;
    }

    platformGpioWatches[index]->descriptor->async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this, index](const boost::system::error_code& ec) {
            if (ec)
            {
                if (ec == boost::asio::error::operation_aborted)
                {
                    lg2::debug("Platform GPIO handler canceled");
                    return;
                }
                const std::string name = (index < platformGpioWatches.size() &&
                                          platformGpioWatches[index] != nullptr)
                                             ? platformGpioWatches[index]->name
                                             : std::string("unknown");
                lg2::error("Platform GPIO {GPIO} wait failed: {ERROR}", "GPIO",
                           name, "ERROR", ec.message());
                return;
            }

            handlePlatformGpioEvent(index);
            watchPlatformGpio(index);
        });
}

void Manager::handlePlatformGpioEvent(size_t index)
{
    if ((index >= platformGpioWatches.size()) ||
        (platformGpioWatches[index] == nullptr))
    {
        return;
    }

    PlatformGpioWatch& watch = *platformGpioWatches[index];

    try
    {
        const gpiod::line_event gpioLineEvent = watch.line.event_read();
        if (gpioLineEvent.event_type != gpiod::line_event::RISING_EDGE)
        {
            return;
        }

        lg2::info("Rising edge on platform GPIO {GPIO}", "GPIO", watch.name);
        sd_journal_send("MESSAGE=%s", watch.message.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        watch.message.c_str(), NULL);

        if (watch.dumpHpmRegisters)
        {
            const int ret = std::system(hpmFpgaDumpCommand);
            if (ret == -1)
            {
                lg2::error("Failed to trigger HPM FPGA register dump");
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Platform GPIO {GPIO} handling failed: {ERROR}", "GPIO",
                   watch.name, "ERROR", e.what());
    }
}

} // namespace ras
} // namespace amd
