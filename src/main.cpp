#include "config_manager.hpp"
#ifdef APML
#include "apml_manager.hpp"
#include "tbai_manager.hpp"
#endif
#include "base_manager.hpp"

#include <boost/asio.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

int main(int argc, char* argv[])
{
    std::string node;

    if (argc != 2)
    {
        lg2::error("Invalid argument: Node is invalid");
    }

    node = argv[1];

    lg2::info("Start amd ras service for host : {NODE}", "NODE", node);

    // Setup connection to D-Bus
    boost::asio::io_service io;

    // Create a shared connection to the system bus
    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    const char* rasService =
        (std::string(amd::ras::config::service) + node).c_str();

    lg2::info("Ras service {SER}", "SER", rasService);
    // Request a unique name on the D-Bus
    systemBus->request_name(rasService);

    // Create an object server for managing D-Bus objects
    sdbusplus::asio::object_server objectServer(systemBus);

    amd::ras::config::Manager manager(objectServer, systemBus, node);

#ifdef APML

    amd::ras::tbai::Manager tbaiManager(objectServer, systemBus, io, node);

    amd::ras::Manager* errorMgr =
        new amd::ras::apml::Manager(manager, objectServer, systemBus, io, node);

    errorMgr->init();

    errorMgr->configure();
#endif

#ifdef PLDM
    // Log an error message if PLDM capabilities are not enabled
    lg2::error("TODO: PLDM RAS capabilities are yet to be enabled");
#endif

    io.run();

    return 0;
}
