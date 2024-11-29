#include "config_manager.hpp"
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

    io.run();

    return 0;
}
