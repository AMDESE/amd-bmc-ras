#include "pldm_manager.hpp"

#include "config_manager.hpp"
#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
}

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

namespace amd
{
namespace ras
{
namespace pldm
{

Manager::Manager(amd::ras::config::Manager& manager,
                 sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io, std::string& node) :
    amd::ras::Manager(manager, node), objectServer(objectServer),
    systemBus(systemBus), io(io), pldmInitialized(false),
    platformInitialized(false), runtimeErrPollingSupported(false)
{}

void Manager::onHostStateChanged(bool hostOff)
{
    pldmInitialized = false;

    if (!hostOff)
    {
        lg2::info("Current host state monitor changed");
        platformInitialize();
    }
}

void Manager::platformInitialize()
{
    lg2::info("Initializing Platform over PLDM transport");
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    struct processor_info platInfo[1];

    if (platformInitialized == false)
    {
        while (ret != OOB_SUCCESS)
        {
            uint8_t socNum = 0;
            ret = esmi_get_processor_info(socNum, platInfo);

            if (ret == OOB_SUCCESS)
            {
                familyId = platInfo->family;
                break;
            }
            lg2::error("Failed to get processor info. RET: {RET}", "RET", ret);
            sleep(1);
        }

        if ((platInfo->family == whFamilyId) && (platInfo->model == whModel))
        {
            currentHostStateMonitor();

            // TODO: Add support for runtime error polling for PLDM when the API
            // is available.
            runtimeErrPollingSupported = true;
        }
        else
        {
            throw std::runtime_error(std::format(
                "This program is not supported for the family = 0x{:x} model = 0x{:x}\n",
                platInfo->family, platInfo->model));
        }

        platformInitialized = true;
        pldmInitialized = true;
    }
    else
    {
        pldmInitialized = true;
        if (runtimeErrPollingSupported == true)
        {
            lg2::info("Setting MCA and DRAM OOB Config");
            // TODO: Add support for setting MCA and DRAM OOB config for PLDM
            // when the API is available.

            lg2::info("Setting MCA and DRAM Error threshold");
            // TODO: Add support for setting MCA and DRAM error threshold for
            // PLDM when the API is available.
        }
    }
}

void Manager::init()
{
    lg2::info("PLDM MANAGER INIT");

    getCpuSocketInfo();

    loadPlatformConfig();

    platformInitialize();
}

void Manager::configure()
{
    lg2::info("PLDM MANAGER CONFIGURE");
}

void Manager::registerEventHandler()
{
    lg2::info("PLDM MANAGER REGISTER EVENT HANDLER");

    amd::ras::util::cper::createRecord(objectServer, systemBus, node);
}

} // namespace pldm
} // namespace ras
} // namespace amd
