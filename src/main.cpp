#include "base_manager.hpp"
#include "config_manager.hpp"
#include "ras_manager_factory.hpp"

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

    const amd::ras::RasTransport transport =
        amd::ras::resolveRasTransportForNode(node);

    const char* oobInterface = "unknown";
    switch (transport)
    {
        case amd::ras::RasTransport::Apml:
            oobInterface = "APML";
            break;
        case amd::ras::RasTransport::Pldm:
            oobInterface = "PLDM";
            break;
    }
    lg2::info("amd-ras starting in {MODE} OOB interface mode", "MODE",
              oobInterface);

    std::unique_ptr<amd::ras::Manager> errorMgr = amd::ras::createRasManager(
        manager, objectServer, systemBus, io, node, transport);

    if (errorMgr)
    {
        errorMgr->init();
        errorMgr->configure();
    }

    io.run();

    if (errorMgr)
    {
        errorMgr->finalize();
    }

    return 0;
}
