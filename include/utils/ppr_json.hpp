#pragma once

#include "oem_cper.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace amd
{
namespace ras
{
namespace util
{
namespace ppr
{

// UMC bank identification from MCA_IPID
// hardware_id = (MCA_IPID >> 32) & 0xFFF  => bits[43:32] of 64-bit IPID
// mca_type    =  MCA_IPID        & 0xFFF  => bits[11: 0]
constexpr uint32_t umcHardwareId = 0x96;
constexpr uint32_t umcMcaType    = 0x00;

// PPR trigger ErrorCodeExt values from MCA_STATUS[21:16]
constexpr uint32_t errCodeDramEcc = 0x00; // DramEccErr
constexpr uint32_t errCodeEcsRow  = 0x08; // EcsRowErr

constexpr uint32_t pprRepairTypeRtSoft = 0x0000;  // RUNTIME_SOFT
constexpr uint32_t pprRepairTypeBtSoft = 0x8000;  // BOOTTIME_SOFT

//  mcaErr offsets  -> word index:
//    MCA_STATUS_LO  offset 0x08  -> DumpData[2]
//    MCA_STATUS_HI  offset 0x0C  -> DumpData[3]
//    MCA_ADDR_LO    offset 0x10  -> DumpData[4]
//    MCA_ADDR_HI    offset 0x14  -> DumpData[5]
//    MCA_IPID_LO    offset 0x28  -> DumpData[10]
//    MCA_IPID_HI    offset 0x2C  -> DumpData[11]
//    MCA_SYND_LO    offset 0x30  -> DumpData[12]
//
//  dramCeccErr adds baseOffset=4, so indices shift down by 1.
//  Use isDram=true to apply the -1 shift.

/** @brief Scan ptr->McaErrorInfo[0..sectionCount-1] and if PPR needed
 *         write *_rtppr.json and/or *_btppr.json files to RAS_DIR.
 *
 *
 *  @param[in] ptr           Shared pointer to the MCA or DRAM runtime CPER
 *                           record.
 *  @param[in] sectionStart  Index of the first section to scan.
 *  @param[in] sectionCount  Number of sections to scan from sectionStart.
 *  @param[in] socNum        Socket number.
 *  @param[in] errCount      Current error file counter.
 *  @param[in] node          Node string for filename prefix.
 *  @param[in] isDram        true  → dramCeccErr
 *                           false → mcaErr
 */
void generatePprJsonFiles(const std::shared_ptr<McaRuntimeCperRecord>& ptr,
                          uint16_t sectionStart, uint16_t sectionCount,
                          uint8_t socNum, size_t errCount,
                          const std::string& node, bool isDram);

} // namespace ppr
} // namespace util
} // namespace ras
} // namespace amd
