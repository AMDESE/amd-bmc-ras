#include "base_manager.hpp"

#include "utils/cper.hpp"
#include "utils/util.hpp"

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>

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
    std::memset(ppin.get(), 0, cpuCount * sizeof(uint64_t));

    inventoryPath = std::make_unique<std::string[]>(cpuCount);

    for (size_t i = 0; i < cpuCount; i++)
    {
        inventoryPath[i] = "/xyz/openbmc_project/inventory/system/processor/P" +
                           std::to_string(socIndex[i]);
    }

    for (size_t i = 0; i < cpuCount; i++)
    {
        readCpuIdentity(i, false);
    }

    amd::ras::util::cper::createIndexFile(errCount, node);
}

void Manager::readCpuIdentity(size_t index, bool onlyMissing)
{
    amd::ras::config::Manager::AttributeValue uCodeVersion =
        configMgr.getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    amd::ras::config::Manager::AttributeValue harvestPpin =
        configMgr.getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    bool readMicrocode = (uCodeVersionFlag != nullptr) && *uCodeVersionFlag &&
                         (!onlyMissing || uCode[index] == 0);
    bool readPpin = (harvestPpinFlag != nullptr) && *harvestPpinFlag &&
                    (!onlyMissing || ppin[index] == 0);

    if (!readMicrocode && !readPpin)
    {
        return;
    }

    sdbusplus::bus_t bus = sdbusplus::bus::new_default();

    if (readMicrocode)
    {
        try
        {
            uint32_t microCode = amd::ras::util::getProperty<uint32_t>(
                bus, inventoryService.data(), inventoryPath[index].c_str(),
                inventoryInterface.data(), "Microcode");

            uCode[index] = microCode;
            if (microCode == 0)
            {
                lg2::error("Microcode not available for {PATH}", "PATH",
                           inventoryPath[index]);
            }
            else
            {
                lg2::info("Microcode = {VAL}", "VAL", lg2::hex, microCode);
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to get Microcode property: {ERR}", "ERR",
                       e.what());
        }
    }

    if (readPpin)
    {
        try
        {
            uint64_t ppinVal = amd::ras::util::getProperty<uint64_t>(
                bus, inventoryService.data(), inventoryPath[index].c_str(),
                inventoryInterface.data(), "Id");

            ppin[index] = ppinVal;
            if (ppinVal == 0)
            {
                lg2::error("PPIN not available for {PATH}", "PATH",
                           inventoryPath[index]);
            }
            else
            {
                lg2::info("PPIN = {VAL}", "VAL", lg2::hex, ppinVal);
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to get PPIN property: {ERR}", "ERR", e.what());
        }
    }
}

void Manager::refreshCpuIdentity(uint8_t socNum)
{
    // The inventory is published after host POST, which can be later than
    // service start; re-read any value still missing when a record is built.
    if (socNum < cpuCount)
    {
        readCpuIdentity(socNum, true);
    }
}

Manager::Manager(amd::ras::config::Manager& manager, std::string& node) :
    errCount(0), configMgr(manager), rcd(nullptr), mcaPtr(nullptr),
    dramPtr(nullptr), pciePtr(nullptr), node(node)
{}

} // namespace ras
} // namespace amd
