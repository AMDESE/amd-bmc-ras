#include "config_manager.hpp"
#include "interface_manager.hpp"

int main()
{
    boost::asio::io_service io;

    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    systemBus->request_name(DBUS_SERVICE_NAME.data());

    sdbusplus::asio::object_server objectServer(systemBus);

    InterfaceManager manager(objectServer, systemBus, io);

    io.run();

    return 0;
}
