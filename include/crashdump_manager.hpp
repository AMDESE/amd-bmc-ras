#pragma once

#include <com/amd/crashdump/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

using CrashdumpBase = sdbusplus::com::amd::server::Crashdump;

/**
 * @brief Definition of the CrashdumpInterface class.
 */
class CrashdumpInterface : public CrashdumpBase
{
  public:
    CrashdumpInterface(sdbusplus::asio::object_server& objectServer,
                       std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                       const std::string& crashdumpObjPath);

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    std::string crashdumpObjPath;
};
