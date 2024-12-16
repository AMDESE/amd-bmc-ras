/*
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http:www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "error_monitor.hpp"

#include "util.hpp"

#include <phosphor-logging/lg2.hpp>

namespace ras
{

namespace fs = std::filesystem;

const std::string inventoryService = "xyz.openbmc_project.Inventory.Manager";
const std::string inventoryInterface = "xyz.openbmc_project.Inventory.Item.Cpu";
static constexpr auto objectPath = "/com/amd/RAS";

void Manager::getSocketInfo()
{
    FILE* pf;
    char data[3];
    std::stringstream ss;

    // Read Cpu ID from u-boot variable
    pf = popen("sbin/fw_printenv -n num_of_cpu", "r");
    if (pf)
    {
        if (fgets(data, 3, pf))
        {
            cpuCount = std::stoi(data);

            lg2::info("Number of Cpu: {CPU}", "CPU", cpuCount);
            cpuId = std::make_unique<CpuId[]>(cpuCount);

            uCode = std::make_unique<uint32_t[]>(cpuCount);
            std::memset(uCode.get(), 0, cpuCount * sizeof(uint32_t));

            ppin = std::make_unique<uint64_t[]>(cpuCount);
            std::memset(uCode.get(), 0, cpuCount * sizeof(uint64_t));

            inventoryPath = std::make_unique<std::string[]>(cpuCount);

            for (int i = 0; i < cpuCount; i++)
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

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen("/sbin/fw_printenv -n board_id", "r");
    // Error handling
    if (pf)
    {
        // Get the data from the process execution
        if (fgets(data, 3, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> boardId;

            lg2::debug("Board ID: {BOARD_ID}", "BOARD_ID", boardId);
        }
        // the data is now in 'data'
        pclose(pf);
    }

    // Retrieve microcode version attribute and check if it's a boolean
    amd::ras::config::Manager::AttributeValue uCodeVersion =
        configMgr.getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    if (*uCodeVersionFlag == true)
    {
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

        for (int i = 0; i < cpuCount; i++)
        {
            std::string microCode = ras::util::getProperty<std::string>(
                bus, inventoryService.data(), inventoryPath[i].c_str(),
                inventoryInterface.data(), "Microcode");

            if (microCode.empty())
            {
                lg2::error("Failed to read ucode revision");
            }
            else
            {
                uCode[i] = std::stoul(microCode, nullptr, 16);
            }
        }
    }

    // Retrieve PPIN attribute and check if it's a boolean
    amd::ras::config::Manager::AttributeValue harvestPpin =
        configMgr.getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    if (*harvestPpinFlag == true)
    {
        for (int i = 0; i < cpuCount; i++)
        {
            std::string Ppin = ras::util::getProperty<std::string>(
                bus, inventoryService.data(), inventoryPath[i].c_str(),
                inventoryInterface.data(), "PPIN");

            if (Ppin.empty())
            {
                lg2::error("Failed to read ppin");
            }
            else
            {
                ppin[i] = std::stoul(Ppin, nullptr, 16);
            }
        }
    }
}

void Manager::createIndexFile()
{
    std::string indexFile = INDEX_FILE;
    std::string rasDir = RAS_DIR;

    ras::util::createFile(rasDir, indexFile);

    std::ifstream file(indexFile);
    if (file.is_open())
    {
        if (!(file >> errCount) || errCount < 0)
        {
            throw std::runtime_error("Failed to read CPER index number");
        }
        file.close();
    }
    else
    {
        throw std::runtime_error("Failed to read from index file");
    }
}

Manager::Manager(amd::ras::config::Manager& manager) : configMgr(manager)
{
    getSocketInfo();

    createIndexFile();
}

void Manager::exportCrashdumpToDBus(
    int num, const EFI_ERROR_TIME_STAMP& TimeStampStr,
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus)
{
    if (num < 0 || num >= 10)
    {
        lg2::error("Crashdump only allows index 0~9\n");
        return;
    }

    const std::string filename = ras::util::findCperFilename(num);
    const std::string fullFilePath = RAS_DIR + filename;

    // Use ISO-8601 as the timestamp format
    // For example: 2022-07-19T14:13:47Z
    const EFI_ERROR_TIME_STAMP& t = TimeStampStr;
    char timestamp[30];
    sprintf(timestamp, "%d-%d-%dT%d:%d:%dZ", (t.Century - 1) * 100 + t.Year,
            t.Month, t.Day, t.Hours, t.Minutes, t.Seconds);

    // Create crashdump DBus instance
    const std::string dbusPath =
        std::string(objectPath) + "/" + std::to_string(num);

    if (ras::util::checkDbusPath(dbusPath) == true)
    {
        auto it = managers.find(num);
        if (it != managers.end())
        {
            it->second.reset();
            managers.erase(it);
        }
    }
    std::unique_ptr<CrashdumpInterface> CperRecordMgr =
        std::make_unique<CrashdumpInterface>(objectServer, systemBus, dbusPath);

    CperRecordMgr->filename(filename);
    CperRecordMgr->log(fullFilePath);
    CperRecordMgr->timestamp(std::string{timestamp});

    managers[num] = {std::move(CperRecordMgr)};
}

void Manager::createDbusInterface(
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus)
{
    // Check if any crashdump already exists.
    if (std::filesystem::exists(std::filesystem::path(RAS_DIR)))
    {
        std::regex pattern(".*ras-error([[:digit:]]+).cper");
        std::smatch match;
        for (const auto& p : std::filesystem::directory_iterator(
                 std::filesystem::path(RAS_DIR)))
        {
            std::string filename = p.path().filename();
            if (!std::regex_match(filename, match, pattern))
            {
                continue;
            }
            const int kNum = stoi(match.str(1));
            const std::string cperFilename = RAS_DIR + filename;
            // exportCrashdumpToDBus needs the timestamp inside the CPER
            // file. So load it first.
            std::ifstream fin(cperFilename, std::ifstream::binary);
            if (!fin.is_open())
            {
                lg2::warning("Broken crashdump CPER file: {CPERFILE}",
                             "CPERFILE", cperFilename.c_str());
                continue;
            }
            fin.seekg(24); // Move the file pointer to offset 24
            EFI_ERROR_TIME_STAMP timestamp;

            if (!fin.read(reinterpret_cast<char*>(&timestamp),
                          sizeof(timestamp)))
            {
                lg2::info("Failed to read data from the file");
            }

            fin.close();
            exportCrashdumpToDBus(kNum, timestamp, objectServer, systemBus);
        }
    }
}

} // namespace ras
