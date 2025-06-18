#pragma once

#include <com/amd/crashdump/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

using CrashdumpBase = sdbusplus::com::amd::server::Crashdump;

/**
 * @brief CrashdumpInterface class which adds the RAS configuration
 * parameter values to the D-Bus interface.
 *
 * @details The class pulls the default values of ras_config.json file
 * into the D-Bus interface and overrides the getAttribute()
 * and setAttribute() of the RAS configuration interface.
 */
class CrashdumpInterface : virtual public sdbusplus::server::object_t<CrashdumpBase>
{
  public:
    CrashdumpInterface() = delete;
    CrashdumpInterface(const CrashdumpInterface&) = delete;
    CrashdumpInterface& operator=(const CrashdumpInterface&) = delete;
    CrashdumpInterface(CrashdumpInterface&&) = delete;
    CrashdumpInterface& operator=(CrashdumpInterface&&) = delete;
    ~CrashdumpInterface() = default;

    /** @brief Constructs CrashdumpInterface object.
     *
     *  @param[in] objectServer  - object server
     *  @param[in] systemBus - bus connection
     */
    CrashdumpInterface(sdbusplus::asio::object_server& objectServer,
                       std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                       const std::string& crashdumpObjPath);

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    std::string crashdumpObjPath;
};
