#include "config_manager.hpp"
#ifdef APML
#include "apml_manager.hpp"
#endif
#include "base_manager.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

int main()
{
    // Setup connection to D-Bus
    boost::asio::io_service io;

    // Create a shared connection to the system bus
    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    // Request a unique name on the D-Bus
    systemBus->request_name(amd::ras::config::service);

    // Create an object server for managing D-Bus objects
    sdbusplus::asio::object_server objectServer(systemBus);

    amd::ras::config::Manager manager(objectServer, systemBus);

#ifdef APML
    amd::ras::Manager* errorMgr =
        new amd::ras::apml::Manager(manager, objectServer, systemBus, io);

    errorMgr->init();

    errorMgr->configure();
#endif

#ifdef PLDM
    // Log an error message if PLDM capabilities are not enabled
    lg2::error("TODO: PLDM RAS capabilities are yet to be enabled");
#endif

    io.run();
#ifdef APML
    auto* apmlMgr = dynamic_cast<amd::ras::apml::Manager*>(errorMgr);
    if (apmlMgr && apmlMgr->getAlertHandleMode() == "UEVENT")
    {
        apmlMgr->releaseUdevReSrc();
    }
#endif

    return 0;
}
