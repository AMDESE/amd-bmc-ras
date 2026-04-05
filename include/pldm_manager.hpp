#pragma once

#include "base_manager.hpp"

#include <memory>
#include <vector>

namespace boost
{
namespace asio
{
class io_context;
}
} // namespace boost

namespace sdbusplus
{
namespace asio
{
class connection;
class object_server;
}
} // namespace sdbusplus

namespace amd
{
namespace ras
{
class PldmEventMonitor;

namespace pldm
{
/** @brief PLDM **strategy**: RAS when OOB uses MCTP/PLDM instead of APML.
 *
 *  @details Same factory entry point and shared CPER / ras_config path as
 *  `apml::Manager`. Overrides `platformInitialize` and
 *  the same transport hooks as APML (`platformInitialize`, runtime OOB,
 *  thresholds, etc.) with PLDM implementations. RAS event
 *  `init()` subscribes to the PLDM D-Bus event signal; `configure()` registers
 *  CPER D-Bus objects.
 */
class Manager : public amd::ras::Manager
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    ~Manager() override;

    Manager(amd::ras::config::Manager&, sdbusplus::asio::object_server&,
            std::shared_ptr<sdbusplus::asio::connection>&,
            boost::asio::io_context&, std::string&);

    void init() override;
    void configure() override;
    void finalize() override;

  private:
    void platformInitialize() override;
    int readOobProcessorFamilyModel(uint32_t& familyOut,
                                   uint32_t& modelOut) override;
    void startHostPowerTransitionMonitoring() override;
    void clearPlatformRasAlertMask() override;
    void runTimeErrorPolling() override;
    int applyRuntimeMcaDramOobConfig() override;
    int applyRuntimePcieOobConfig() override;
    int applyRuntimePcieErrThreshold() override;
    int applyRuntimeMcaErrorThresholds() override;

    void onPldmEventBuffer(std::vector<uint8_t>&& payload);

    boost::asio::io_context& io_;
    sdbusplus::asio::object_server& objectServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    std::unique_ptr<PldmEventMonitor> pldmEventMonitor_;
};

} // namespace pldm
} // namespace ras
} // namespace amd
