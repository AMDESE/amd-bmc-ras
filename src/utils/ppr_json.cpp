#include "utils/ppr_json.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

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
    uint8_t  DeviceTypeToRepair{0};
    uint8_t  Bank{0};
    uint8_t  Device{0};
    uint8_t  ChipSelect{0};
    uint16_t Column{0};
    uint8_t  TargetDevice{0};
    uint8_t  Valid{0};
    uint32_t Row{0};
    uint8_t  RankMultiplier{0};
    uint8_t  Channel{0};
    uint8_t  SubChannel{0};
    uint8_t  HardPPRDone{0};
    uint8_t  PPRUndo{0};
    uint8_t  PPRLock{0};
    uint8_t  Socket{0};
    uint8_t  RepairType{0};
    uint8_t  ErrorCause{0};
    uint8_t  Reserved1{0};
    uint8_t  RepairResult{0};
    uint16_t Reserved2{0};
    uint32_t AddressLo{0};
    uint32_t AddressHi{0};
};

using PprPayload = std::array<uint16_t, 10>;

// One entry of a *_rtppr.json / *_btppr.json file
struct PprFileEntry
{
    uint8_t socNum;
    PprPayload payload;
};

// DRAM row targeted by a repair:
// socNum, Socket, Channel, SubChannel, ChipSelect, RankMultiplier, Bank, Row,
// AddressLo, AddressHi (ECS row errors only, which carry no row)
using RepairKey = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
                             uint8_t, uint8_t, uint32_t, uint32_t, uint32_t>;

// Repair history of the current host boot. One harvested CE must not turn
// into repeated repairs of the same row: the DRAM CECC record carries the
// same MCA data in every instance, and MCA polling harvests a record again
// until it is replaced.
static std::mutex pprHistoryMtx;
static std::set<RepairKey> rtRequested;
static std::set<RepairKey> btRequested;
static std::set<std::pair<uint8_t, uint8_t>> rtBlockedChannels;
static std::set<RepairKey> rtBlockedLogged;

//   Payload packing
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

static RepairKey makeRepairKey(uint8_t socNum, const DpprclRepairEntry& e,
                               bool isEcsRow)
{
    // An ECS row entry sets no row, chip select or sub-channel: its target is
    // the translated DRAM address, so key it on that address.
    return RepairKey{socNum,       e.Socket,     e.Channel,
                     e.SubChannel, e.ChipSelect, e.RankMultiplier,
                     e.Bank,       e.Row,
                     isEcsRow ? e.AddressLo : 0U,
                     isEcsRow ? e.AddressHi : 0U};
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
                       const std::vector<PprFileEntry>& entries)
{
    nlohmann::json j;
    j["pprDataIn"] = nlohmann::json::array();

    uint32_t entryNum = 0;
    for (const auto& fileEntry : entries)
    {
        nlohmann::json entry;
        entry["RepairType"]    = repairType;
        entry["RepairEntryNum"] = entryNum++;
        entry["SocNum"]         = static_cast<uint32_t>(fileEntry.socNum);
        entry["Payload"]        = nlohmann::json::array();

        for (const auto word : fileEntry.payload)
        {
            entry["Payload"].push_back(static_cast<uint32_t>(word));
        }
        j["pprDataIn"].push_back(entry);
    }

    // File names are reused once the error counter wraps. A status file left
    // by an older request with the same name makes the consumers (amd-bmc-ppr
    // startup scan, fb-ipmi-oem OEM GET_PPR) skip this new request.
    const std::string statusPath =
        path.substr(0, path.size() - 5) + "_status.json";
    std::error_code ec;
    std::filesystem::remove(statusPath, ec);

    // Written once per record: every close of a *_rtppr.json starts a repair
    // in amd-bmc-ppr.
    std::ofstream ofs(path);
    if (!ofs.is_open())
    {
        lg2::error("PPR JSON: failed to open {PATH} for writing", "PATH", path);
        return;
    }
    ofs << j.dump(4);
    lg2::info("PPR JSON written: {PATH} ({N} entries)", "PATH", path, "N",
              entries.size());
}

void resetRuntimePprHistory()
{
    std::lock_guard<std::mutex> lock(pprHistoryMtx);

    rtRequested.clear();
    btRequested.clear();
    rtBlockedChannels.clear();
    rtBlockedLogged.clear();
}

// Function body to generatePPR while harvesting
void generatePprJsonFiles(const std::shared_ptr<McaRuntimeCperRecord>& ptr,
                          const std::vector<PprSectionRange>& ranges,
                          size_t errCount, const std::string& node,
                          bool isDram)
{
    if (!ptr || !ptr->McaErrorInfo)
    {
        lg2::error("PPR JSON: null ptr or McaErrorInfo, skipping");
        return;
    }

    constexpr int kStatusLo    =  2;
    constexpr int kStatusHi    =  3;
    constexpr int kAddrLo      =  4;
    constexpr int kAddrHi      =  5;
    constexpr int kIpidLo      = 10;
    constexpr int kIpidHi      = 11;
    constexpr int kSyndLo      = 12;
    constexpr int kTransAddrLo = 28;
    constexpr int kTransAddrHi = 29;

    std::lock_guard<std::mutex> lock(pprHistoryMtx);

    // A UMC bank holding a deferred or uncorrected error must not get a
    // runtime repair (ValidateMcaRuntimePostPackageRepair, SP7/SP8 Platform
    // RAS spec 6.3.17). Block the channel until the host boots again; the
    // boot-time request still covers the row.
    for (const auto& range : ranges)
    {
        for (uint16_t s = range.sectionStart;
             s < range.sectionStart + range.sectionCount; ++s)
        {
            uint32_t d[length32];
            memcpy(d, ptr->McaErrorInfo[s].DumpData, sizeof(d));
            const uint64_t mcaStatus =
                (static_cast<uint64_t>(d[kStatusHi]) << 32) | d[kStatusLo];
            const uint64_t mcaIpid =
                (static_cast<uint64_t>(d[kIpidHi]) << 32) | d[kIpidLo];

            if (!isDram &&
                (((mcaIpid >> 32) & 0xFFFU) != umcHardwareId ||
                 ((mcaIpid >> 48) & 0xFFFFU) != umcMcaType))
            {
                continue;
            }

            const bool uc       = static_cast<bool>((mcaStatus >> 61) & 0x1U);
            const bool deferred = static_cast<bool>((mcaStatus >> 44) & 0x1U);
            if (!uc && !deferred)
            {
                continue;
            }

            const uint8_t iod  = static_cast<uint8_t>((mcaIpid >> 44) & 0xFU);
            const uint8_t umcN = static_cast<uint8_t>((mcaIpid >> 20) & 0xFU);
            const uint8_t channel =
                static_cast<uint8_t>(umcN / 2U + iod * 8U);

            if (rtBlockedChannels.emplace(range.socNum, channel).second)
            {
                lg2::warning(
                    "PPR JSON: socket {SOC} channel {CH} logged a deferred or "
                    "uncorrected error, no more runtime PPR on it until the "
                    "host boots again",
                    "SOC", range.socNum, "CH", channel);
            }
        }
    }

    std::vector<PprFileEntry> rtEntries;
    std::vector<PprFileEntry> btEntries;

    for (const auto& range : ranges)
    {
        for (uint16_t s = range.sectionStart;
             s < range.sectionStart + range.sectionCount; ++s)
        {
            uint32_t dumpBuf[length32];
            memcpy(dumpBuf, ptr->McaErrorInfo[s].DumpData, sizeof(dumpBuf));
            const uint32_t* d = dumpBuf;

            // Extract MCA registers
            const uint64_t mcaStatus =
                (static_cast<uint64_t>(d[kStatusHi]) << 32) | d[kStatusLo];

            const uint64_t mcaAddr =
                (static_cast<uint64_t>(d[kAddrHi]) << 32) | d[kAddrLo];

            const uint64_t mcaIpid =
                (static_cast<uint64_t>(d[kIpidHi]) << 32) | d[kIpidLo];

            const uint32_t mcaSynd = d[kSyndLo];

            const uint64_t transAddr =
                (static_cast<uint64_t>(d[kTransAddrHi]) << 32) |
                 d[kTransAddrLo];
            const bool transAddrValid =
                static_cast<bool>((transAddr >> 62) & 0x1U);

            // UMC bank detection — for MCA errors verify via IPID.
            if (!isDram)
            {
                const uint32_t hwId =
                    static_cast<uint32_t>((mcaIpid >> 32) & 0xFFFU);
                const uint32_t mcaType =
                    static_cast<uint32_t>((mcaIpid >> 48) & 0xFFFFU);
                if (hwId != umcHardwareId || mcaType != umcMcaType)
                {
                    continue; // Not a UMC bank — no PPR needed
                }
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
            const uint32_t ece =
                static_cast<uint32_t>((mcaStatus >> 16) & 0x3FU);

            if (ece != errCodeDramEcc && ece != errCodeEcsRow)
            {
                continue;
            }

            // Fill repair entry
            DpprclRepairEntry e{};
            e.Valid      = 1U;
            e.ErrorCause = corrected ? 1U : 3U; // 1=corrected, 3=deferred
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

            // Without a translated address the repair target is unknown: do
            // not ask for a repair of row 0 or DRAM address 0.
            if (!transAddrValid)
            {
                lg2::warning("PPR JSON: no translated DRAM address for socket "
                             "{SOC} MCA_ADDR {ADDR}, no PPR request",
                             "SOC", range.socNum, "ADDR", lg2::hex, mcaAddr);
                continue;
            }

            const RepairKey key =
                makeRepairKey(range.socNum, e, ece == errCodeEcsRow);

            // Runtime request: corrected errors only, once per row per host
            // boot.
            if (corrected)
            {
                const bool channelBlocked = rtBlockedChannels.contains(
                    {range.socNum, static_cast<uint8_t>(umcN / 2U + iod * 8U)});

                if (channelBlocked)
                {
                    // Info once per row, so each skipped request has a
                    // journal line of its own after older lines rotate out.
                    if (rtBlockedLogged.insert(key).second)
                    {
                        lg2::info(
                            "PPR JSON: no runtime PPR for socket {SOC} channel "
                            "{CH} row {ROW}: the channel logged a deferred or "
                            "uncorrected error in this host boot",
                            "SOC", range.socNum, "CH", e.Channel, "ROW",
                            lg2::hex, e.Row);
                    }
                }
                else if (rtRequested.contains(key))
                {
                    lg2::debug("PPR JSON: runtime PPR already requested for "
                              "socket {SOC} channel {CH} row {ROW}",
                              "SOC", range.socNum, "CH", e.Channel, "ROW",
                              lg2::hex, e.Row);
                }
                else if (rtRequested.size() >= maxRtPprPerBoot ||
                         rtEntries.size() >= maxRtPprEntriesPerFile)
                {
                    lg2::warning("PPR JSON: runtime PPR limit reached, row "
                                 "{ROW} not requested",
                                 "ROW", lg2::hex, e.Row);
                }
                else
                {
                    // Pack RT payload
                    e.RepairType = 0U;
                    PprFileEntry rt{range.socNum, {}};
                    packPayload(e, rt.payload.data());
                    rtEntries.push_back(rt);
                    rtRequested.insert(key);
                }
            }

            // Boot-time request: once per row per host boot
            if (!btRequested.contains(key) &&
                btEntries.size() < maxBtPprEntriesPerFile)
            {
                // Pack BT payload
                DpprclRepairEntry eBt = e;
                eBt.RepairType = 0U;
                eBt.AddressLo = 0U;
                eBt.AddressHi = 0U;
                PprFileEntry bt{range.socNum, {}};
                packPayload(eBt, bt.payload.data());
                btEntries.push_back(bt);
                btRequested.insert(key);
            }
        }
    }

    if (!rtEntries.empty())
    {
        const std::string rtPath = buildPprPath(errCount, node, isDram, false);
        writeJson(rtPath, pprRepairTypeRtSoft, rtEntries);
    }

    if (!btEntries.empty())
    {
        const std::string btPath = buildPprPath(errCount, node, isDram, true);
        writeJson(btPath, pprRepairTypeBtSoft, btEntries);
    }
}

} // namespace ppr
} // namespace util
} // namespace ras
} // namespace amd
