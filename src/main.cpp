#include "config_manager.hpp"
#include "interface_manager.hpp"

int main()
{
    boost::asio::io_service io;

    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    systemBus->request_name(DBUS_SERVICE_NAME);
    sdbusplus::asio::object_server objectServer(systemBus);

    InterfaceManager manager(objectServer, systemBus, io);

    manager.init();

    manager.configure();

    manager.harvestDumps(ERROR_TYPE_FATAL);

    io.run();

    return 0;
}
