#pragma once

#include <sdbusplus/bus.hpp>

#include <cstdint>
#include <string>

namespace amd
{
namespace ras
{
namespace util
{
namespace decode_service
{

/** @brief Get inventory path for a CPU socket.
 *
 *  @param[in] socNum - Socket number (0-based).
 *
 *  @return Inventory object path for the CPU.
 */
std::string getCpuInventoryPath(uint8_t socNum);

/** @brief Submit CPER to decode-service for processing.
 *
 *  Opens the CPER file and calls the decode-service D-Bus interface
 *  xyz.openbmc_project.Logging.CPER.Process() to submit the CPER
 *  for decoding and Redfish event generation.
 *
 *  @param[in] bus - D-Bus connection.
 *  @param[in] cperFilePath - Path to CPER file on disk.
 *  @param[in] socNum - Socket number for inventory path mapping.
 *
 *  @return 0 on success, negative errno on failure.
 */
int submitCperForProcessing(sdbusplus::bus_t& bus,
                            const std::string& cperFilePath, uint8_t socNum);

/** @brief Check if decode-service is available.
 *
 *  @param[in] bus - D-Bus connection.
 *
 *  @return true if service is running, false otherwise.
 */
bool isDecodeServiceAvailable(sdbusplus::bus_t& bus);

} // namespace decode_service
} // namespace util
} // namespace ras
} // namespace amd
