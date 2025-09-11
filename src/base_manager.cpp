#include "base_manager.hpp"

#include "utils/cper.hpp"
#include "utils/util.hpp"

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

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
    errCount(0), configMgr(manager), rcd(nullptr), mcaPtr(nullptr),
    dramPtr(nullptr), pciePtr(nullptr), node(node)
{}

} // namespace ras
} // namespace amd
