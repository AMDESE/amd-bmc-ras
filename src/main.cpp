/**
 * A user-space application that monitors APML_ALERT_L gpio line
 * for fatal error detecttion and creates CPER record
 *
 * Author: abinaya.dhandapani@amd.com
 **/

#include "apml_manager.hpp"

#include <iostream>

int main()
{
    boost::asio::io_service io;

    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    systemBus->request_name(DBUS_SERVICE_NAME.data());

    sdbusplus::asio::object_server objectServer(systemBus);

    RasManagerBase* rasManagerObj;

#ifdef APML
    rasManagerObj = new ApmlInterfaceManager(objectServer, systemBus, io);

    rasManagerObj->init();

    rasManagerObj->configure();

#endif
    /* TODO: Enable PLDM : Create rasManagerObj pointer
     * poiting to PLDM derived class object if PLDM is enabled in meson*/

    io.run();

    if (rasManagerObj != NULL)
    {
        delete rasManagerObj;
    }
    return 0;
}
