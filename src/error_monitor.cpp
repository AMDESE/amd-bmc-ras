#include "error_monitor.hpp"

#include "cper_util.hpp"
#include "dbus_util.hpp"
#include "util.hpp"

#include <phosphor-logging/lg2.hpp>

/* Venice Platform IDs */
constexpr size_t congo = 128;    // 0x80
constexpr size_t congo1 = 129;   // 0x81
constexpr size_t congo2 = 134;   // 0x86
constexpr size_t morocco = 130;  // 0x82
constexpr size_t morocco1 = 131; // 0x83
constexpr size_t morocco2 = 135; // 0x87
constexpr size_t kenya = 132;    // 0x84
constexpr size_t nigeria = 133;  // 0x85

constexpr size_t base16 = 16;

namespace amd
{
namespace ras
{
namespace fs = std::filesystem;

constexpr std::string_view inventoryService =
    "xyz.openbmc_project.Inventory.Manager";
constexpr std::string_view inventoryInterface =
    "xyz.openbmc_project.Inventory.Item.Cpu";

void Manager::getSocketInfo()
{
    FILE* pf;
    char data[3];
    std::stringstream ss;

    pf = popen("/sbin/fw_printenv -n board_id", "r");
    if (pf)
    {
        if (fgets(data, 3, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> boardId;

            if ((boardId == morocco) || (boardId == morocco1) ||
                (boardId == morocco2) || (boardId == nigeria))
            {
                cpuCount = socket2;
            }
            else if ((boardId == congo) || (boardId == congo1) ||
                     (boardId == congo2) || (boardId == kenya))
            {
                cpuCount = socket1;
            }
            else
            {
                lg2::error("Board ID: {BOARD_ID}", "BOARD_ID", boardId);
                throw std::runtime_error(
                    "Gen3 ADDC not supported for this platform");
                pclose(pf);
                return;
            }
            lg2::debug("Board ID: {BOARD_ID}", "BOARD_ID", boardId);
            lg2::info("Number of Cpu: {CPU}", "CPU", cpuCount);

            cpuId = std::make_unique<CpuId[]>(cpuCount);

            uCode = std::make_unique<uint32_t[]>(cpuCount);
            std::memset(uCode.get(), 0, cpuCount * sizeof(uint32_t));

            ppin = std::make_unique<uint64_t[]>(cpuCount);
            std::memset(uCode.get(), 0, cpuCount * sizeof(uint64_t));

            inventoryPath = std::make_unique<std::string[]>(cpuCount);

            for (size_t i = 0; i < cpuCount; i++)
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

    amd::ras::config::Manager::AttributeValue uCodeVersion =
        configMgr.getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    if (*uCodeVersionFlag == true)
    {
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

        for (size_t i = 0; i < cpuCount; i++)
        {
            std::string microCode =
                amd::ras::dbus::util::getProperty<std::string>(
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
            std::string ppinStr =
                amd::ras::dbus::util::getProperty<std::string>(
                    bus, inventoryService.data(), inventoryPath[i].c_str(),
                    inventoryInterface.data(), "PPIN");

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
    amd::ras::cper::util::createIndexFile(errCount);
}

Manager::Manager(amd::ras::config::Manager& manager) :
    errCount(0), configMgr(manager), rcd(nullptr), mcaPtr(nullptr),
    dramPtr(nullptr), pciePtr(nullptr)
{
    getSocketInfo();
}

} // namespace ras
} // namespace amd
