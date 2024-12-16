#include "crashdump_manager.hpp"

/**
 * @brief Constructor for CrashdumpInterface
 *
 * This constructor initializes a CrashdumpInterface object with a given object
 * server and system bus connection.
 *
 * @param[in] objectServer Reference to an object server for managing D-Bus
 * objects.
 * @param[in] systemBus Shared pointer to a D-Bus connection.
 */
CrashdumpInterface::CrashdumpInterface(
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus,
    const std::string& crashdumpObjPath) :
    sdbusplus::com::amd::server::Crashdump(*systemBus, crashdumpObjPath.data()),
    objServer(objectServer), systemBus(systemBus),
    crashdumpObjPath(crashdumpObjPath)
{}
