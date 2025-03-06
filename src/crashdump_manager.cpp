#include "crashdump_manager.hpp"

CrashdumpInterface::CrashdumpInterface(
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus,
    const std::string& crashdumpObjPath) :
    sdbusplus::com::amd::server::Crashdump(*systemBus, crashdumpObjPath.data()),
    objServer(objectServer), systemBus(systemBus),
    crashdumpObjPath(crashdumpObjPath)
{}
