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

#include "error_monitor.hpp"
#ifdef APML
#include "apml_manager.hpp"
#endif
#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

int main() {
  // Setup connection to D-Bus
  boost::asio::io_context io;

  // Create a shared connection to the system bus
  auto systemBus = std::make_shared<sdbusplus::asio::connection>(io);

  // Request a unique name on the D-Bus
  systemBus->request_name(amd::ras::config::service);

  // Create an object server for managing D-Bus objects
  sdbusplus::asio::object_server objectServer(systemBus);

  amd::ras::config::Manager manager(objectServer, systemBus);

#ifdef APML
  ras::Manager *errorMgr =
      new ras::apml::Manager(manager, objectServer, systemBus, io);

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
