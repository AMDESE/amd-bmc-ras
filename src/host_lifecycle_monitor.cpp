#include "host_lifecycle_monitor.hpp"

#include <phosphor-logging/lg2.hpp>

#include <map>
#include <string>
#include <variant>

namespace amd
{
namespace ras
{

HostLifecycleMonitor::HostLifecycleMonitor() : bus_(sdbusplus::bus::new_default())
{}

void HostLifecycleMonitor::startHostStateMonitor(OnHostCurrentState onState)
{
    if (hostMatch_)
    {
        return;
    }

    hostMatch_ = std::make_unique<sdbusplus::bus::match::match>(
        bus_,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Host'",
        [onState = std::move(onState)](sdbusplus::message::message& message) {
            std::string intfName;
            std::map<std::string, std::variant<std::string>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (const std::exception&)
            {
                lg2::info("Unable to read host state");
                return;
            }
            if (properties.empty())
            {
                lg2::error("ERROR: Empty PropertiesChanged signal received");
                return;
            }

            if (properties.begin()->first != "CurrentHostState")
            {
                return;
            }
            const std::string* currentHostState =
                std::get_if<std::string>(&(properties.begin()->second));
            if (currentHostState == nullptr)
            {
                lg2::error("currentHostState Property invalid");
                return;
            }

            onState(*currentHostState);
        });
}

void HostLifecycleMonitor::startWatchdogMonitor(OnWatchdogEnabled onEnabled)
{
    if (watchdogMatch_)
    {
        return;
    }

    watchdogMatch_ = std::make_unique<sdbusplus::bus::match::match>(
        bus_,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Watchdog'",
        [onEnabled = std::move(onEnabled)](sdbusplus::message::message& message) {
            std::string intfName;
            std::map<std::string, std::variant<bool>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (const std::exception&)
            {
                lg2::error("Unable to read watchdog state");
                return;
            }
            if (properties.empty())
            {
                lg2::error("Empty PropertiesChanged signal received");
                return;
            }

            if (properties.begin()->first != "Enabled")
            {
                return;
            }

            const bool* currentTimerEnable =
                std::get_if<bool>(&(properties.begin()->second));
            if (currentTimerEnable == nullptr)
            {
                return;
            }

            onEnabled(*currentTimerEnable);
        });
}

} // namespace ras
} // namespace amd
