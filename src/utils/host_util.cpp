#include "host_util.hpp"

extern "C"
{
#include "apml.h"
#include "apml_common.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

namespace amd
{
namespace ras
{
namespace host
{
namespace util
{

constexpr size_t sysMgmtCtrlErr = 0x4;
constexpr size_t socket0 = 0;

void requestHostTransition(std::string command)
{
    boost::system::error_code ec;
    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->async_method_call(
        [](boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("Failed to trigger cold reset of the system\n");
            }
        },
        "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.State.Host", "RequestedHostTransition",
        std::variant<std::string>{command});
}

void triggerRsmrstReset()
{
    boost::system::error_code ec;
    boost::asio::io_context io_conn;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io_conn);

    conn->async_method_call(
        [](boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("Failed to trigger cold reset of the system\n");
            }
        },
        "xyz.openbmc_project.State.Host",
        "/xyz/openbmc_project/control/host0/SOCReset",
        "xyz.openbmc_project.Control.Host.SOCReset", "SOCReset");

    sleep(1);
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string currentHostState =
        amd::ras::dbus::util::getProperty<std::string>(
            bus, "xyz.openbmc_project.State.Host",
            "/xyz/openbmc_project/state/host0",
            "xyz.openbmc_project.State.Host", "currentHostState");

    if (currentHostState.compare(
            "xyz.openbmc_project.State.Host.HostState.Off") == 0)
    {
        std::string command = "xyz.openbmc_project.State.Host.Transition.On";
        requestHostTransition(command);
    }
}

void triggerSysReset()
{
    std::string command = "xyz.openbmc_project.State.Host.Transition.Reboot";

    requestHostTransition(command);
}

void triggerColdReset(const std::string* resetSignal)
{
    if (*resetSignal == "RSMRST")
    {
        lg2::info("RSMRST reset triggered");
        triggerRsmrstReset();
    }
    else if (*resetSignal == "SYS_RST")
    {
        lg2::info("SYS_RST signal triggered");
        triggerSysReset();
    }
}

void triggerWarmReset()
{
    oob_status_t ret;
    uint32_t ackResp = 0;
    /* In a 2P config, it is recommended to only send this command to P0
    Hence, sending the Signal only to socket 0*/

#ifdef APML
    ret = reset_on_sync_flood(socket0, &ackResp);

    if (ret)
    {
        lg2::error("Failed to request reset after sync flood");
    }
    else
    {
        lg2::info("Warm reset triggered");
    }
#else
    lg2::error("TODO: Warm reset pending as APML is not supported");
#endif
}

void rasRecoveryAction(uint8_t buf, const std::string* systemRecovery,
                       const std::string* resetSignal)
{
    if (*systemRecovery == "WARM_RESET")
    {
        if ((buf & sysMgmtCtrlErr))
        {
            triggerColdReset(resetSignal);
        }
        else
        {
            triggerWarmReset();
        }
    }
    else if (*systemRecovery == "COLD_RESET")
    {
        triggerColdReset(resetSignal);
    }
    else if (*systemRecovery == "NO_RESET")
    {
        lg2::info("NO RESET triggered");
    }
    else
    {
        lg2::error("CdumpResetPolicy is not valid");
    }
}

} // namespace util
} // namespace host
} // namespace ras
} // namespace amd
