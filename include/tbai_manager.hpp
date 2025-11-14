#pragma once

#include "crashdump_manager.hpp"
#include "oem_cper.hpp"

#include <com/amd/Dump/Create/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Dump/Create/server.hpp>

namespace amd
{
namespace ras
{
namespace tbai
{
static constexpr auto service = "com.amd.RAS";
static constexpr auto objectPath = "/com/amd/TBAI";

using createDumpIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Dump::server::Create,
    sdbusplus::com::amd::Dump::server::Create>;

using DumpCreateParams =
    std::map<std::string, std::variant<std::string, uint64_t>>;

/**
 * @brief Manager class which adds the RAS configuration
 * parameter values to the D-Bus interface.
 *
 * @details The class pulls the default values of ras_config.json file
 * into the D-Bus interface and overrides the getAttribute()
 * and setAttribute() of the RAS configuration interface.
 *
 *  @param[in] manager - Reference to the TBAI manager.
 *  @param[in] objectServer - The D-Bus object server.
 *  @param[in] systemBus - Shared pointer to the D-Bus system bus connection.
 *  @param[in] io - Boost ASIO I/O context for asynchronous operations.
 *  @param[in] node - host node number to determine single or multi host.
 */
class Manager : virtual public createDumpIface
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    ~Manager() = default;

    Manager(sdbusplus::asio::object_server&,
            std::shared_ptr<sdbusplus::asio::connection>&,
            boost::asio::io_context&, std::string&);

    /** @brief Implementation for CreateDump
     *  Method to create Dump.
     *
     *  @return object_path - The object path of the new entry.
     */
    sdbusplus::message::object_path
        createDump(DumpCreateParams params) override;

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    boost::asio::io_context& io;

    std::string node;
    std::string mpName;

    std::mutex tbaiMutex;

    std::vector<std::pair<std::string, int>> mpToIndexMap;

    size_t currentSectionCount;
    size_t inputSocNum;
    size_t cpuCount;

    std::vector<size_t> socIndex;

    std::shared_ptr<FatalCperRecord> mpxPtr;

    std::map<int, std::unique_ptr<CrashdumpInterface>> tbaiRecordMgr;

    void harvestMpxTraceLog(DumpCreateParams params);
};

} // namespace tbai
} // namespace ras
} // namespace amd
