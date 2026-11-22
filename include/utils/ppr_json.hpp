#pragma once

#include "oem_cper.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace amd
{
namespace ras
{
namespace util
{
namespace ppr
{

// UMC bank identification from MCA_IPID
// hardware_id = (MCA_IPID >> 32) & 0xFFF
// mca_type    = (MCA_IPID >> 48) & 0xFFFF
constexpr uint32_t umcHardwareId = 0x96;
constexpr uint32_t umcMcaType    = 0x00;

// ErrorCodeExt values from MCA_STATUS[21:16]
constexpr uint32_t errCodeDramEcc = 0x00;
constexpr uint32_t errCodeEcsRow  = 0x08;

constexpr uint32_t pprRepairTypeRtSoft = 0x0000;
constexpr uint32_t pprRepairTypeBtSoft = 0x8000;

// The APML RAS action carries a 3-bit repair entry number, so one runtime
// request file holds at most 8 entries.
constexpr size_t maxRtPprEntriesPerFile = 8;

// fb-ipmi-oem serves each *_btppr.json to the BIOS as one PPR row (OEM
// GET_PPR) and applies one SET_PPR result to the whole file: keep one entry.
constexpr size_t maxBtPprEntriesPerFile = 1;

// Venice supports at most 64 DRAM repairs per platform (SP7/SP8 Platform RAS
// spec, 6.3.17). Never request more runtime repairs than that per host boot.
constexpr size_t maxRtPprPerBoot = 64;

/** @brief Sections of one harvested record that belong to one socket. */
struct PprSectionRange
{
    uint16_t sectionStart;
    uint16_t sectionCount;
    uint8_t socNum;
};

//    DumpData[0..1]   = MCA_CTL
//    DumpData[2]      = MCA_STATUS_LO
//    DumpData[3]      = MCA_STATUS_HI
//    DumpData[4]      = MCA_ADDR_LO
//    DumpData[5]      = MCA_ADDR_HI
//    DumpData[10]     = MCA_IPID_LO
//    DumpData[11]     = MCA_IPID_HI
//    DumpData[12]     = MCA_SYND_LO
//    DumpData[28]     = TRANS_ADDR_LO
//    DumpData[29]     = TRANS_ADDR_HI

/** @brief Function to generate PPR json files
 *
 *  Writes at most one *_rtppr.json and one *_btppr.json per harvested
 *  record. A DRAM row gets one runtime repair request per host boot, no
 *  runtime repair is requested without a translated DRAM address, and none
 *  on a channel that has logged a deferred or uncorrected UMC error since
 *  the host booted.
 *
 *  @param[in] ptr           Shared pointer to the MCA or DRAM runtime CPER
 *                           record.
 *  @param[in] ranges        Section ranges to scan, one per socket.
 *  @param[in] errCount      Current error file counter.
 *  @param[in] node          Node string for filename prefix.
 *  @param[in] isDram        true  → dramCeccErr
 *                           false → mcaErr
 */
void generatePprJsonFiles(const std::shared_ptr<McaRuntimeCperRecord>& ptr,
                          const std::vector<PprSectionRange>& ranges,
                          size_t errCount, const std::string& node,
                          bool isDram);

/** @brief Forget the runtime repairs requested so far.
 *
 *  Soft repairs do not survive a host reset, so this is called when the
 *  host has booted again.
 */
void resetRuntimePprHistory();

} // namespace ppr
} // namespace util
} // namespace ras
} // namespace amd
