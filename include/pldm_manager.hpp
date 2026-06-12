#pragma once

#include "base_manager.hpp"

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <gpiod.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus/match.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

extern "C"
{
#include "apml_alertl_uevent.h"
}

namespace amd
{
namespace ras
{
namespace pldm
{

/** @brief PLDM RAS Event IDs from the RasStatus Sensor (0x4C) */
constexpr uint16_t eventIdFatalError = 0x4C01;
constexpr uint16_t eventIdFchError = 0x4C02;
constexpr uint16_t eventIdMcaOverflow = 0x4C08;
constexpr uint16_t eventIdDramCeccOverflow = 0x4C10;
constexpr uint16_t eventIdNonMcaCoreShutdown = 0x4C40;
constexpr uint16_t eventIdMcaCoreShutdown = 0x4C41;

/** @brief DataTransferHandle opcode in upper byte */
constexpr uint8_t opcodeDbgLogDump = 0x5C;
constexpr uint8_t opcodeDbgLogValidityCheck = 0x5B;
constexpr uint8_t opcodeDbgLogDumpAlt = 0x62;
constexpr uint8_t opcodeDbgLogValidityCheckAlt = 0x61;

/** @brief Error context types matching APML definitions */
constexpr size_t crashdump = 1;
constexpr size_t shutdown = 2;

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

    // D-Bus match rule for PLDM message poll events
    std::unique_ptr<sdbusplus::bus::match_t> pldmEventMatch;

    // Alert reception mode for sysMgmtCtrlErr (UEVENT or GPIO)
    std::string alertHandleMode;
    std::vector<std::string> socketNames;
    std::vector<gpiod::line> gpioLines;
    std::vector<boost::asio::posix::stream_descriptor> gpioEventDescriptors;
    std::vector<apml_udev_monitor> udevMonitors;
    std::vector<std::unique_ptr<boost::asio::deadline_timer>> udevPollTimers;

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

    /** @brief Handles incoming PLDM RAS event signals.
     *
     *  @details Processes the PldmMessagePollEvent signal, extracts
     *  the event ID and data transfer handle, reads error data from
     *  the file descriptor, and dispatches appropriate error handling
     *  based on the RAS event type.
     *
     *  @param[in] msg - The D-Bus message containing the PLDM event.
     */
    void handlePldmRasEvent(sdbusplus::message_t& msg);

    /** @brief Read GPIO/UEVENT alert config for sysMgmtCtrlErr reception. */
    void configureSysMgmtCtrlErrAlertHandling();

    /** @brief Register GPIO/UEVENT handlers for sysMgmtCtrlErr reception. */
    void registerSysMgmtCtrlErrAlertHandler();

    /** @brief Poll UEVENT source for sysMgmtCtrlErr alerts. */
    void pollSysMgmtCtrlErrUevent(size_t socketIdx);

    /** @brief Configure one GPIO line watcher for sysMgmtCtrlErr alerts. */
    void requestSysMgmtCtrlErrGPIOEvents(
        const std::string& name, const std::function<void()>& handler,
        gpiod::line& gpioLine,
        boost::asio::posix::stream_descriptor& gpioEventDescriptor);

    /** @brief Handle GPIO edge events for sysMgmtCtrlErr alerts. */
    void handleSysMgmtCtrlErrGPIOEvent(
        boost::asio::posix::stream_descriptor& alertEvent,
        const gpiod::line& alertLine, size_t socketIdx);

    /** @brief Clear SBRMI alert mask bits needed for alert delivery. */
    void clearSbrmiAlertMask(uint8_t socNum);

    /** @brief Reads event data from a file descriptor.
     *
     *  @details Performs a complete read of eventDataSize bytes from
     *  the given file descriptor, handling partial reads and EINTR.
     *
     *  @param[in] fd - File descriptor to read from.
     *  @param[in] eventDataSize - Number of bytes to read.
     *  @param[out] eventData - Buffer populated with the read data.
     *  @return true on success, false on read failure.
     */
    bool readEventDataFromFd(int fd, uint16_t eventDataSize,
                             std::vector<uint8_t>& eventData);

    /** @brief Handles fatal error or MCA core shutdown events via PLDM.
     *
     *  @details Processes the error event data from PMFW,
     *  populates the CPER record with MCA bank data and debug log
     *  dumps, generates the CPER file, exports to D-Bus, and
     *  triggers the configured recovery action.
     *
     *  @param[in] eventData - Raw event data from PMFW containing
     *                         MCA banks and debug log dump data.
     *  @param[in] socNum - Socket number derived from terminus info.
     *  @param[in] contextType - Error context (crashdump or shutdown).
     */
    void handleFatalOrShutdownError(const std::vector<uint8_t>& eventData,
                                    uint8_t socNum, size_t contextType);

    /** @brief Handles PLDM sysMgmtCtrlErr (control fabric) errors.
     *
     *  @details Generates a fatal CPER record for control fabric errors,
     *  updates error counters, exports the record, and applies the configured
     *  recovery action.
     *
     *  @param[in] socNum - Socket number derived from terminus info.
     */
    void handleSysMgmtCtrlError(uint8_t socNum);

    /** @brief Extracts socket number from PLDM terminus name.
     *
     *  @param[in] terminusName - The terminus name string.
     *  @return Socket number (0-based).
     */
    uint8_t getSocketFromTerminus(const std::string& terminusName);

    /** @brief Harvests the CPER fatal error record from PLDM event data.
     *
     *  @details Parses the event data payload from PMFW and fills in
     *  the FatalCperRecord structures including MCA bank data and
     *  debug log ID data.
     *
     *  @param[in] eventData - Raw event data payload.
     *  @param[in] socNum - Socket number.
     *  @param[in] contextType - Context type (crashdump or shutdown).
     */
    void harvestMcaDataBanksOverPldm(const std::vector<uint8_t>& eventData,
                                     uint8_t socNum, size_t contextType);
};

} // namespace pldm
} // namespace ras
} // namespace amd
