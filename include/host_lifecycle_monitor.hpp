#pragma once

#include <functional>
#include <memory>
#include <string>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>

namespace amd
{
namespace ras
{

/** @brief Subscribes to OpenBMC host / watchdog D-Bus signals (transport-agnostic).
 *
 *  @details Parses `PropertiesChanged` for `xyz.openbmc_project.State.Host` and
 *  `xyz.openbmc_project.State.Watchdog`; strategy code supplies callbacks for
 *  APML-specific follow-up.
 */
class HostLifecycleMonitor
{
  public:
    HostLifecycleMonitor();
    ~HostLifecycleMonitor() = default;
    HostLifecycleMonitor(const HostLifecycleMonitor&) = delete;
    HostLifecycleMonitor& operator=(const HostLifecycleMonitor&) = delete;
    HostLifecycleMonitor(HostLifecycleMonitor&&) = delete;
    HostLifecycleMonitor& operator=(HostLifecycleMonitor&&) = delete;

    using OnHostCurrentState = std::function<void(const std::string& state)>;
    using OnWatchdogEnabled = std::function<void(bool enabled)>;

    /** @brief Register match for `CurrentHostState` on State.Host (once). */
    void startHostStateMonitor(OnHostCurrentState onState);

    /** @brief Register match for `Enabled` on State.Watchdog (once). */
    void startWatchdogMonitor(OnWatchdogEnabled onEnabled);

  private:
    sdbusplus::bus::bus bus_;
    std::unique_ptr<sdbusplus::bus::match::match> hostMatch_;
    std::unique_ptr<sdbusplus::bus::match::match> watchdogMatch_;
};

} // namespace ras
} // namespace amd
