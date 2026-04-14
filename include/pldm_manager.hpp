#pragma once

#include "base_manager.hpp"

#include <boost/asio/deadline_timer.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

namespace amd
{
namespace ras
{
namespace pldm
{
/** @brief Manages RAS (Reliability, Availability, and Serviceability)
 * operations for PLDM.
 *
 *  @details This class is responsible for initializing and configuring RAS
 * operations specific to PLDM. It inherits from the base `amd::ras::Manager`
 * class and provides additional functionality tailored to PLDM.
 *
 *  @param[in] manager - Reference to the configuration manager.
 *  @param[in] objectServer - The D-Bus object server.
 *  @param[in] systemBus - Shared pointer to the D-Bus system bus connection.
 *  @param[in] io - Boost ASIO I/O context for asynchronous operations.
 *  @param[in] node - host node number to determine single or multi host.
 */
class Manager : public amd::ras::Manager
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    ~Manager() = default;

    Manager(amd::ras::config::Manager&, sdbusplus::asio::object_server&,
            std::shared_ptr<sdbusplus::asio::connection>&,
            boost::asio::io_context&, std::string&);

    /** @brief Perform initialization for the error monitoring via PLDM.
     *
     *  @details It initializes the PLDM RAS Manager by setting up platform
     *  and watchdog state monitoring for bios post complete. It reads CPU
     *  IDs, configures PCIE settings using PLDM transport.
     */
    void init() override;

    /** @brief Configure PLDM RAS settings.
     *
     *  @details This function configures PLDM RAS settings such as
     *  thresholds from the JSON configuration file.
     */
    void configure() override;

    /** @brief Register for PLDM event handling.
     *
     *  @details This function registers for PLDM events on RAS alerts.
     *  It sets up the event handling mechanism for receiving PLDM-based
     *  RAS notifications from the processor.
     */
    void registerEventHandler() override;

  private:
    sdbusplus::asio::object_server& objectServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    boost::asio::io_context& io;

    // Indicates whether the PLDM subsystem has been initialized
    bool pldmInitialized;
    // Indicates whether the platform-specific setup is complete
    bool platformInitialized;
    // Indicates whether runtime error polling is supported for PLDM
    bool runtimeErrPollingSupported;

    /** @brief Called when the host power state changes.
     *
     *  @details Performs PLDM-specific actions on host state transitions,
     *  such as triggering platform initialization.
     *
     *  @param[in] hostOff - true if the host transitioned to Off state.
     */
    void onHostStateChanged(bool hostOff) override;

    /** @brief Initializes platform-specific settings.
     *
     *  @details It initializes the platform based on the family ID.
     *  It sets up the necessary configurations for PLDM-based RAS
     *  error reporting.
     */
    void platformInitialize();
};

} // namespace pldm
} // namespace ras
} // namespace amd
