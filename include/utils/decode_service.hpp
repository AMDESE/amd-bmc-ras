#pragma once

#include <sdbusplus/asio/connection.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace amd
{
namespace ras
{
namespace util
{
namespace decode_service
{
/** @brief Submits a CPER file to the phosphor-logging CPER processor.
 *
 *  @details Opens the CPER file and passes its file descriptor to
 *  xyz.openbmc_project.Logging.CPER.Processor.Process() together with the
 *  inventory path of the originating CPU. The call is asynchronous and does
 *  not block RAS handling; failures are only logged. The CPER file and the
 *  existing com.amd.crashdump D-Bus objects are left untouched.
 *
 *  Compiled in only when the 'decode-service' meson option is enabled,
 *  otherwise this is a no-op.
 *
 *  @param[in] bus - Shared pointer to the D-Bus system bus connection.
 *  @param[in] cperFilePath - Full path of the generated CPER file.
 *  @param[in] socNum - Socket number used to build the CPU inventory path.
 */
#ifdef DECODE_SERVICE
void submitCper(const std::shared_ptr<sdbusplus::asio::connection>& bus,
                const std::string& cperFilePath, uint8_t socNum);
#else
inline void submitCper(const std::shared_ptr<sdbusplus::asio::connection>&,
                       const std::string&, uint8_t)
{}
#endif

} // namespace decode_service
} // namespace util
} // namespace ras
} // namespace amd
