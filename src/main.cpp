/*
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http:www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "apml_manager.hpp"

int main()
{
    // Setup connection to D-Bus
    boost::asio::io_service io;

    // Create a shared connection to the system bus
    auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

    // Request a unique name on the D-Bus
    systemBus->request_name("com.amd.RAS");

    // Create an object server for managing D-Bus objects
    sdbusplus::asio::object_server objectServer(systemBus);

    RasManagerBase* rasManagerObj = nullptr;

#ifdef APML
    // Create an instance of ApmlInterfaceManager if APML is defined
    rasManagerObj = new ApmlInterfaceManager(objectServer, systemBus, io);

    rasManagerObj->init();

    rasManagerObj->configure();
#endif

#ifdef PLDM
    // Log an error message if PLDM capabilities are not enabled
    lg2::error("TODO: PLDM RAS capabilities are yet to be enabled");
#endif

    io.run();

    // Clean up the RAS manager object if it was created
    if (rasManagerObj != nullptr)
    {
        delete rasManagerObj;
    }

    return 0;
}
