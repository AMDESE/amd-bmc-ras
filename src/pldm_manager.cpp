#include "pldm_manager.hpp"

#include "config_manager.hpp"
#include "oem_cper.hpp"
#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
}

#include <unistd.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <cerrno>
#include <cstring>

namespace amd
{
namespace ras
{
namespace pldm
{

constexpr uint32_t badData = 0xBAADDA7A;

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
    // Step 2: Locate the MCA handle (opcode=0x5C, DBG_LOG_ID=32) and
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
        if (opcode == opcodeDbgLogDump && dbgLogId == mcaDebugLogId)
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
        if (opcode != opcodeDbgLogDump || dbgLogId == mcaDebugLogId)
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
            if (opcode == opcodeDbgLogDump && dbgLogId == blkId)
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

} // namespace pldm
} // namespace ras
} // namespace amd
