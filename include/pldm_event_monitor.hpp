#pragma once

#include <boost/asio/io_context.hpp>
#include <functional>
#include <memory>
#include <vector>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

namespace amd
{
namespace ras
{

/** @brief Listens for `xyz.openbmc_project.PLDM.Event` / `PldmMessagePollEvent`.
 *
 *  @details Matches the PLDM daemon signal shape verified with sd-bus: body
 *  signature `tysyyquqh` with the UNIX fd last. Uses `fstat` + `mmap` (or
 *  `read` fallback) to copy up to `PLDM_EVENT_MAX_PAYLOAD` bytes, then delivers
 *  the buffer on the Boost.Asio `io_context` thread. The match rule and caps are
 *  set via Meson (`pldm_event_*` options).
 */
class PldmEventMonitor
{
  public:
    using OnEventBuffer = std::function<void(std::vector<uint8_t>)>;

    PldmEventMonitor(boost::asio::io_context& io, sdbusplus::bus::bus& systemBus,
                     OnEventBuffer onBuffer);
    ~PldmEventMonitor();

    PldmEventMonitor(const PldmEventMonitor&) = delete;
    PldmEventMonitor& operator=(const PldmEventMonitor&) = delete;
    PldmEventMonitor(PldmEventMonitor&&) = delete;
    PldmEventMonitor& operator=(PldmEventMonitor&&) = delete;

  private:
    boost::asio::io_context& io_;
    OnEventBuffer onBuffer_;
    std::unique_ptr<sdbusplus::bus::match::match> match_;
};

} // namespace ras
} // namespace amd
