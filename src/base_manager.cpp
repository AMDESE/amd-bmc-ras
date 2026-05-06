#include "base_manager.hpp"

#include "utils/cper.hpp"
#include "utils/util.hpp"

#include <systemd/sd-journal.h>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>

#include <fstream>

constexpr size_t base16 = 16;

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

    cpuId = std::make_unique<CpuId[]>(cpuCount);

    uCode = std::make_unique<uint32_t[]>(cpuCount);
    std::memset(uCode.get(), 0, cpuCount * sizeof(uint32_t));

    ppin = std::make_unique<uint64_t[]>(cpuCount);
    std::memset(uCode.get(), 0, cpuCount * sizeof(uint64_t));

    inventoryPath = std::make_unique<std::string[]>(cpuCount);

    for (size_t i = 0; i < cpuCount; i++)
    {
        inventoryPath[i] = "/xyz/openbmc_project/inventory/system/processor/P" +
                           std::to_string(socIndex[i]);
    }

    amd::ras::config::Manager::AttributeValue uCodeVersion =
        configMgr.getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    if (*uCodeVersionFlag == true)
    {
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

        for (size_t i = 0; i < cpuCount; i++)
        {
            std::string microCode = amd::ras::util::getProperty<std::string>(
                bus, inventoryService.data(), inventoryPath[i].c_str(),
                inventoryInterface.data(), "Microcode");

            if (microCode.empty())
            {
                lg2::error("Failed to read ucode revision");
            }
            else
            {
                uCode[i] = std::stoul(microCode, nullptr, base16);
            }
        }
    }

    amd::ras::config::Manager::AttributeValue harvestPpin =
        configMgr.getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    if (*harvestPpinFlag == true)
    {
        for (size_t i = 0; i < cpuCount; i++)
        {
            std::string ppinStr = amd::ras::util::getProperty<std::string>(
                bus, inventoryService.data(), inventoryPath[i].c_str(),
                inventoryInterface.data(), "Id");

            if (ppinStr.empty())
            {
                lg2::error("Failed to read ppin");
            }
            else
            {
                ppin[i] = std::stoul(ppinStr, nullptr, base16);
            }
        }
    }
    amd::ras::util::cper::createIndexFile(errCount, node);
}

Manager::Manager(amd::ras::config::Manager& manager, std::string& node) :
    errCount(0), progId(1), recordId(1), configMgr(manager), rcd(nullptr),
    mcaPtr(nullptr), dramPtr(nullptr), pciePtr(nullptr),
    coreDebugDumpPtr(nullptr), node(node), whFamilyId(0)
{}

void Manager::loadPlatformConfig()
{
    std::ifstream file("/var/lib/platform-config/platform.json");
    if (!file.is_open())
    {
        file.open(PLATFORM_DEFAULT_FILE);
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
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    static auto match = sdbusplus::bus::match::match(
        bus,
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

void Manager::cleanupFatalCperRecord()
{
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

    amd::ras::util::cper::dumpHeader(rcd, sectionCount, errorSeverity, fatalErr,
                                     boardId, recordId);
    amd::ras::util::cper::dumpErrorDescriptor(rcd, sectionCount, fatalErr,
                                              &errorSeverity, progId);
}

void Manager::processMcaBankSignatures(uint8_t socNum, uint16_t numBanks)
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
        uint32_t mcaStatusLo = rcd->ErrorRecord[socNum]
                                   .CrashDumpData[n]
                                   .McaData[statusOffsetLo / 4];
        uint32_t mcaStatusHi = rcd->ErrorRecord[socNum]
                                   .CrashDumpData[n]
                                   .McaData[statusOffsetHi / 4];
        uint32_t mcaIpidLo =
            rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[ipidOffsetLo / 4];
        uint32_t mcaIpidHi =
            rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[ipidOffsetHi / 4];
        uint32_t mcaSyndLo =
            rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[syndOffsetLo / 4];
        uint32_t mcaSyndHi =
            rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[syndOffsetHi / 4];

        uint32_t mcaPspSynd1Lo = rcd->ErrorRecord[socNum]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd1LoCode / 4];
        uint32_t mcaPspSynd1Hi = rcd->ErrorRecord[socNum]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd1HiCode / 4];
        uint32_t mcaPspSynd2Lo = rcd->ErrorRecord[socNum]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd2LoCode / 4];
        uint32_t mcaPspSynd2Hi = rcd->ErrorRecord[socNum]
                                     .CrashDumpData[n]
                                     .McaData[mcaPspSynd2HiCode / 4];

        if ((mcaStatusHi & (1 << 25)) && (mcaStatusHi & (1 << 23)))
        {
            amd::ras::util::cper::populateSignatureId(
                rcd->ErrorRecord[socNum], mcaSyndLo, mcaSyndHi, mcaIpidLo,
                mcaIpidHi, mcaStatusLo, mcaStatusHi);
        }

        amd::ras::util::cper::populateFruStringPspSynd(
            rcd->SectionDescriptor[socNum], mcaPspSynd1Lo, mcaPspSynd1Hi,
            mcaPspSynd2Lo, mcaPspSynd2Hi);
    }
}

} // namespace ras
} // namespace amd
