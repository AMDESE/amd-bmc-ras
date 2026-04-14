#include "apml_manager.hpp"
#include "base_manager.hpp"
#include "config_manager.hpp"
#include "pldm_manager.hpp"
#include "utils/util.hpp"

#include <boost/asio.hpp>
#include <memory>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>

static constexpr auto settingsService = "xyz.openbmc_project.Settings";
static constexpr auto miscSettingsPath =
    "/xyz/openbmc_project/control/AmdMiscSettings";
static constexpr auto miscSettingsIface = "com.amd.AmdMiscSettings";
static constexpr auto mgmtModeProperty = "OobSbrmiMgmtMode";

static constexpr auto apmlModeValue =
    "com.amd.AmdMiscSettings.OobSbrmiMgmtModes.apml";
static constexpr auto pldmModeValue =
    "com.amd.AmdMiscSettings.OobSbrmiMgmtModes.pldm";

int main(int argc, char* argv[])
{
    std::string node;

    if (argc != 2)
    {
        lg2::error("Invalid argument: Node is invalid");
    }

    node = argv[1];

    lg2::info("Start amd ras service for host : {NODE}", "NODE", node);

    // Read the OOB management mode from D-Bus to determine APML or PLDM
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string mgmtMode = amd::ras::util::getProperty<std::string>(
        bus, settingsService, miscSettingsPath, miscSettingsIface,
        mgmtModeProperty);

    lg2::info("OobSbrmiMgmtMode: {MODE}", "MODE", mgmtMode);

    bool isPldmMode = (mgmtMode == pldmModeValue);

    if (mgmtMode != apmlModeValue && !isPldmMode)
    {
        lg2::error("Unknown OobSbrmiMgmtMode: {MODE}, defaulting to APML",
                   "MODE", mgmtMode);
    }

    // Setup connection to D-Bus
    boost::asio::io_context io;

    // Create a shared connection to the system bus
    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    std::string rasService = std::string(amd::ras::config::service) + node;

    lg2::info("Ras service {SER}", "SER", rasService);
    // Request a unique name on the D-Bus
    systemBus->request_name(rasService.c_str());

    // Create an object server for managing D-Bus objects
    sdbusplus::asio::object_server objectServer(systemBus);

    amd::ras::config::Manager manager(objectServer, systemBus, node);

    // Factory: create the appropriate manager based on the mode
    std::unique_ptr<amd::ras::Manager> errorMgr;
    if (isPldmMode)
    {
        errorMgr = std::make_unique<amd::ras::pldm::Manager>(
            manager, objectServer, systemBus, io, node);
    }
    else
    {
        errorMgr = std::make_unique<amd::ras::apml::Manager>(
            manager, objectServer, systemBus, io, node);
    }

    errorMgr->init();
    errorMgr->configure();
    errorMgr->registerEventHandler();

    io.run();

    if (!isPldmMode)
    {
        auto* apmlMgr =
            dynamic_cast<amd::ras::apml::Manager*>(errorMgr.get());
        if (apmlMgr && apmlMgr->getAlertHandleMode() == "UEVENT")
        {
            apmlMgr->releaseUdevReSrc();
        }
    }

    return 0;
}
