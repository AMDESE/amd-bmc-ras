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
// hardware_id = (MCA_IPID >> 32) & 0xFFF
// mca_type    = (MCA_IPID >> 48) & 0xFFFF
constexpr uint32_t umcHardwareId = 0x96;
constexpr uint32_t umcMcaType    = 0x00;

// ErrorCodeExt values from MCA_STATUS[21:16]
constexpr uint32_t errCodeDramEcc = 0x00;
constexpr uint32_t errCodeEcsRow  = 0x08;

constexpr uint32_t pprRepairTypeRtSoft = 0x0000;
constexpr uint32_t pprRepairTypeBtSoft = 0x8000;

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
 *
 *  @param[in] ptr           Shared pointer to the MCA or DRAM runtime CPER
 *                           record.
 *  @param[in] sectionStart  Index of the first section to scan.
 *  @param[in] sectionCount  Number of sections to scan.
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
