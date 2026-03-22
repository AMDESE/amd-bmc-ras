#include "utils/ppr_json.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <cstring>

#include <fstream>
#include <string>

namespace amd
{
namespace ras
{
namespace util
{
namespace ppr
{

// repair entry struct
struct DpprclRepairEntry
{
    uint8_t  DeviceTypeToRepair{0}; //  3 bits
    uint8_t  Bank{0};               //  5 bits  BG[4:2] | BA[1:0]
    uint8_t  Device{0};             //  5 bits  failed device index
    uint8_t  ChipSelect{0};         //  2 bits  CS
    uint16_t Column{0};             // 11 bits
    uint8_t  TargetDevice{0};       //  5 bits
    uint8_t  Valid{0};              //  1 bit
    uint32_t Row{0};                // 18 bits
    uint8_t  RankMultiplier{0};     //  3 bits
    uint8_t  Channel{0};            //  4 bits  UMC channel
    uint8_t  SubChannel{0};         //  1 bit   sub-channel
    uint8_t  HardPPRDone{0};        //  1 bit   (set by CPU after hPPR)
    uint8_t  PPRUndo{0};            //  1 bit
    uint8_t  PPRLock{0};            //  1 bit
    uint8_t  Socket{0};             //  3 bits  processor socket number
    uint8_t  RepairType{0};         //  3 bits  inner type (0=soft)
    uint8_t  ErrorCause{0};         //  3 bits  1=corrected, 3=deferred
    uint8_t  Reserved1{0};          //  2 bits
    uint8_t  RepairResult{0};       //  8 bits  filled with status after repair
    uint16_t Reserved2{0};          // 16 bits
    uint32_t AddressLo{0};          // 32 bits  physical address [31:0]
    uint32_t AddressHi{0};          // 32 bits  physical address [63:32]
};

//   Payload packing
//
//   Payload[0] = bits[ 15:  0]
//   Payload[1] = bits[ 31: 16]
//   Payload[2] = bits[ 47: 32]
//   Payload[3] = bits[ 63: 48]
//   Payload[4] = bits[ 79: 64]
//   Payload[5] = bits[ 95: 80]
//   Payload[6] = bits[111: 96]
//   Payload[7] = bits[127:112]
//   Payload[8] = bits[143:128]
//   Payload[9] = bits[159:144]

static void packPayload(const DpprclRepairEntry& e, uint16_t payload[10])
{
    payload[0] = static_cast<uint16_t>(
        ((e.Column & 0x1U)          << 15) |
        ((e.ChipSelect & 0x3U)      << 13) |
        ((e.Device & 0x1FU)         <<  8) |
        ((e.Bank & 0x1FU)           <<  3) |
         (e.DeviceTypeToRepair & 0x7U));

    payload[1] = static_cast<uint16_t>(
        ((e.Valid & 0x1U)           << 15) |
        ((e.TargetDevice & 0x1FU)   << 10) |
        ((e.Column >> 1U) & 0x3FFU));

    payload[2] = static_cast<uint16_t>(e.Row & 0xFFFFU);

    payload[3] = static_cast<uint16_t>(
        ((e.Socket & 0x7U)          << 13) |
        ((e.PPRLock & 0x1U)         << 12) |
        ((e.PPRUndo & 0x1U)         << 11) |
        ((e.HardPPRDone & 0x1U)     << 10) |
        ((e.SubChannel & 0x1U)      <<  9) |
        ((e.Channel & 0xFU)         <<  5) |
        ((e.RankMultiplier & 0x7U)  <<  2) |
        ((e.Row >> 16U) & 0x3U));

    payload[4] = static_cast<uint16_t>(
        ((e.RepairResult & 0xFFU)   <<  8) |
        ((e.Reserved1 & 0x3U)       <<  6) |
        ((e.ErrorCause & 0x7U)      <<  3) |
         (e.RepairType & 0x7U));

    payload[5] = static_cast<uint16_t>(e.Reserved2 & 0xFFFFU);

    payload[6] = static_cast<uint16_t>( e.AddressLo        & 0xFFFFU);
    payload[7] = static_cast<uint16_t>((e.AddressLo >> 16) & 0xFFFFU);
    payload[8] = static_cast<uint16_t>( e.AddressHi        & 0xFFFFU);
    payload[9] = static_cast<uint16_t>((e.AddressHi >> 16) & 0xFFFFU);
}

// Create PPR FileName
static std::string buildPprPath(size_t errCount, const std::string& node,
                                 bool isDram, bool isBt)
{
    std::string name =
        (isDram ? "dram-runtime-" : "mca-runtime-") +
        std::string("ras-error") + std::to_string(errCount) +
        (isBt ? "_btppr.json" : "_rtppr.json");

    if (node == "1" || node == "2")
    {
        name = "node" + node + "-" + name;
    }

    return std::string(RAS_DIR) + name;
}

// Write PPR json entries
static void writeJson(const std::string& path, uint32_t repairType,
                       uint8_t socNum, const uint16_t payload[10])
{
    nlohmann::json j;
    j["pprDataIn"] = nlohmann::json::array();

    nlohmann::json entry;
    entry["RepairType"]    = repairType;
    entry["RepairEntryNum"] = 0;
    entry["SocNum"]         = static_cast<uint32_t>(socNum);
    entry["Payload"]        = nlohmann::json::array();

    for (int i = 0; i < 10; ++i)
    {
        entry["Payload"].push_back(static_cast<uint32_t>(payload[i]));
    }
    j["pprDataIn"].push_back(entry);

    std::ofstream ofs(path);
    if (!ofs.is_open())
    {
        lg2::error("PPR JSON: failed to open {PATH} for writing", "PATH", path);
        return;
    }
    ofs << j.dump(4);
    lg2::info("PPR JSON written: {PATH}", "PATH", path);
}

// Function body to generatePPR while harvesting
void generatePprJsonFiles(const std::shared_ptr<McaRuntimeCperRecord>& ptr,
                           uint16_t sectionStart, uint16_t sectionCount,
                           uint8_t socNum, size_t errCount,
                           const std::string& node, bool isDram)
{
    if (!ptr || !ptr->McaErrorInfo)
    {
        lg2::error("PPR JSON: null ptr or McaErrorInfo, skipping");
        return;
    }

    // wOff = -1 for dramCeccErr, 0 for mcaErr.
    const int wOff = isDram ? -1 : 0;

    // Baseline word indices for mcaErr path (baseOffset=0):
    constexpr int kStatusLo    =  2; // offset 0x08  (MCA_STATUS_LO)
    constexpr int kStatusHi    =  3; // offset 0x0C  (MCA_STATUS_HI)
    constexpr int kAddrLo      =  4; // offset 0x10  (MCA_ADDR_LO)
    constexpr int kAddrHi      =  5; // offset 0x14  (MCA_ADDR_HI)
    constexpr int kIpidLo      = 10; // offset 0x28  (MCA_IPID_LO)
    constexpr int kIpidHi      = 11; // offset 0x2C  (MCA_IPID_HI)
    constexpr int kSyndLo      = 12; // offset 0x30  (MCA_SYND_LO)
    constexpr int kTransAddrLo = 28; // offset 0x70  (TRANS_ADDR_LO)
    constexpr int kTransAddrHi = 29; // offset 0x74  (TRANS_ADDR_HI)

    for (uint16_t s = sectionStart; s < sectionStart + sectionCount; ++s)
    {
        uint32_t dumpBuf[length32];
        memcpy(dumpBuf, ptr->McaErrorInfo[s].DumpData, sizeof(dumpBuf));
        const uint32_t* d = dumpBuf;

        // Extract MCA registers
        const uint64_t mcaStatus =
            (static_cast<uint64_t>(d[kStatusHi + wOff]) << 32) |
             d[kStatusLo + wOff];

        const uint64_t mcaAddr =
            (static_cast<uint64_t>(d[kAddrHi + wOff]) << 32) |
             d[kAddrLo + wOff];

        const uint64_t mcaIpid =
            (static_cast<uint64_t>(d[kIpidHi + wOff]) << 32) |
             d[kIpidLo + wOff];

        const uint32_t mcaSynd = d[kSyndLo + wOff];

        const uint64_t transAddr =
            (static_cast<uint64_t>(d[kTransAddrHi]) << 32) |
             d[kTransAddrLo];
        const bool transAddrValid = static_cast<bool>((transAddr >> 62) & 0x1U);

        // UMC bank detection
        const uint32_t hwId    = static_cast<uint32_t>((mcaIpid >> 32) & 0xFFFU);
        const uint32_t mcaType = static_cast<uint32_t>((mcaIpid >> 48) & 0xFFFFU);

        if (hwId != umcHardwareId || mcaType != umcMcaType)
        {
            continue; // Not a UMC bank no need for PPRs
        }

        // Severity
        const bool uc        = static_cast<bool>((mcaStatus >> 61) & 0x1U);
        const bool deferred  = static_cast<bool>((mcaStatus >> 44) & 0x1U);
        const bool corrected = !uc && !deferred;
        const bool deferOnly = !uc &&  deferred;

        if (!corrected && !deferOnly)
        {
            continue;
        }

        // ErrorCodeExt
        const uint32_t ece = static_cast<uint32_t>((mcaStatus >> 16) & 0x3FU);

        if (ece != errCodeDramEcc && ece != errCodeEcsRow)
        {
            continue;
        }

        // Fill repair entry
        DpprclRepairEntry e{};
        e.Valid      = 1U;
        e.ErrorCause = corrected ? 1U : 3U; // 1=corrected, 3=deferred
        // Python: Device = transaddr >> 42 & 0x1f  when deferred (no valid-bit gate;
        //         when transaddr=0, this naturally gives 0).
        //         Device = 0x1F always for corrected errors.
        e.Device = deferOnly
                       ? static_cast<uint8_t>((transAddr >> 42) & 0x1FU)
                       : 0x1FU;

        const uint8_t iod  = static_cast<uint8_t>((mcaIpid >> 44) & 0xFU);
        const uint8_t umcN = static_cast<uint8_t>((mcaIpid >> 20) & 0xFU);

        if (ece == errCodeDramEcc)
        {
            e.ChipSelect = static_cast<uint8_t>( mcaSynd        & 0x7U);
            e.SubChannel = static_cast<uint8_t>((mcaSynd >>  4) & 0x1U);

            if (transAddrValid)
            {
                e.Bank           = static_cast<uint8_t> ((transAddr >>  2) & 0x1FU);
                e.Column         = static_cast<uint16_t>((transAddr >> 25) & 0x7FFU);
                e.Row            = static_cast<uint32_t>((transAddr >>  7) & 0x3FFFFU);
                e.RankMultiplier = static_cast<uint8_t> ((transAddr >> 36) & 0x7U);
                e.Channel        = static_cast<uint8_t> (umcN / 2U + iod * 8U);
                e.Socket         = static_cast<uint8_t> ((transAddr >> 58) & 0x7U);
            }
            e.AddressLo = static_cast<uint32_t>((mcaAddr >>  4) & 0xFFFF'FFFFU);
            e.AddressHi = static_cast<uint32_t>((mcaAddr >> 36) & 0xFU);
        }
        else
        {
            e.Bank    = static_cast<uint8_t>((mcaAddr >> 18) & 0x1FU);
            e.Column  = 0;
            e.Channel = static_cast<uint8_t>(umcN / 2U + iod * 8U);
            e.Socket  = static_cast<uint8_t>((transAddr >> 58) & 0x7U);

            if (transAddrValid)
            {
                e.RankMultiplier = static_cast<uint8_t> ((transAddr >> 36) & 0x7U);
                e.AddressLo      = static_cast<uint32_t>( transAddr        & 0xFFFF'FFFFU);
                e.AddressHi      = static_cast<uint32_t>((transAddr >> 32) & 0xFFU);
            }
        }

        // Pack RT payload
        e.RepairType = 0U;
        uint16_t rtPayload[10]{};
        packPayload(e, rtPayload);

        // Pack BT payload
        DpprclRepairEntry eBt = e;
        eBt.AddressLo = 0U;
        eBt.AddressHi = 0U;
        uint16_t btPayload[10]{};
        packPayload(eBt, btPayload);

        if (corrected)
        {
            const std::string rtPath = buildPprPath(errCount, node, isDram, false);
            writeJson(rtPath, pprRepairTypeRtSoft, socNum, rtPayload);
        }

        const std::string btPath = buildPprPath(errCount, node, isDram, true);
        writeJson(btPath, pprRepairTypeBtSoft, socNum, btPayload);
    }
}

} // namespace ppr
} // namespace util
} // namespace ras
} // namespace amd
