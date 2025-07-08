#pragma once

#include "base_manager.hpp"

extern "C"
{
#include "esmi_mailbox.h"
}

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <gpiod.hpp>

namespace amd
{
namespace ras
{
namespace apml
{
/** @brief Manages RAS (Reliability, Availability, and Serviceability)
 * operations for APML.
 *
 *  @details This class is responsible for initializing and configuring RAS
 * operations specific to APML. It inherits from the base `amd::ras::Manager`
 * class and provides additional functionality tailored to APML.
 *
 *  @param[in] manager - Reference to the configuration manager.
 *  @param[in] objectServer - The D-Bus object server.
 *  @param[in] systemBus - Shared pointer to the D-Bus system bus connection.
 *  @param[in] io - Boost ASIO I/O context for asynchronous operations.
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
            boost::asio::io_context&);

    /** @brief Perform initilization for the error monitoring.
     *
     *  @details It initializes the APML RAS Manager by repeatedly attempting to
     *  get the BMC RAS OOB configuration and setting up platform and watchdog
     *  state monitoring for bios post complete. It also reads CPU IDs,
     *  configures PCIE settings, and clears the SbrmiAlertMask register for
     *  crashdump readiness.
     */
    virtual void init();

    /** @brief Request GPIO events for APML alert handling.
     *
     *  @details This function sets up GPIO event handling for APML alerts. It
     *  requests GPIO events for  alert handling by binding the alert
     * event handler to the specified GPIO line and event. The number of GPIO
     * lines to be monitored is read from the amd_ras_gpio_config.json file
     */

    virtual void configure();

  private:
    sdbusplus::asio::object_server& objectServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;

    size_t whFamilyId;
    size_t whModel;
    uint8_t progId;
    size_t contextType;
    uint64_t recordId;
    size_t watchdogTimerCounter;
    boost::asio::io_context& io;
    std::vector<uint8_t> blockId;
    bool apmlInitialized;
    bool platformInitialized;
    bool runtimeErrPollingSupported;
    bool p0AlertProcessed;
    bool p1AlertProcessed;
    boost::asio::deadline_timer* McaErrorPollingEvent;
    boost::asio::deadline_timer* DramCeccErrorPollingEvent;
    boost::asio::deadline_timer* PcieAerErrorPollingEvent;
    std::mutex harvestMutex;
    std::mutex mcaErrorHarvestMtx;
    std::mutex dramErrorHarvestMtx;
    std::mutex pcieErrorHarvestMtx;
    std::vector<gpiod::line> gpioLines;

    /**
     * @brief Requests GPIO events for hardware alert handling.
     *
     * @details This function configures a GPIO line and stream descriptor to
     * listen for events. It triggers the provided callback function upon event
     * detection.
     *
     * @param[in] gpioPin The GPIO pin to monitor.
     * @param[in] callback The function to call when an event is detected.
     * @param[in] line The GPIO line to use for event detection.
     * @param[in] stream The stream descriptor used to listen for events.
     */
    void requestGPIOEvents(const std::string&, const std::function<void()>&,
                           gpiod::line&,
                           boost::asio::posix::stream_descriptor&);

    /**
     * @brief Handler for alert events.
     *
     * @details This function is invoked when an alert event occurs on P0 or P1.
     * The function handles the event by processing the necessary response.
     *
     *  @param[in] apmlAlertEvent - Stream descriptor for the APML alert event.
     *  @param[in] alertLine - GPIO line for the alert.
     *  @param[in] socket - Socket number associated with the alert.
     */
    void alertEventHandler(boost::asio::posix::stream_descriptor&,
                           const gpiod::line&, size_t);

    /** @brief Stream descriptor for handling  APML alert events.
     *
     *  @details This stream descriptor listens for alert events related to the
     *  processor and triggers actions upon detection.
     */
    std::vector<boost::asio::posix::stream_descriptor> gpioEventDescriptors;

    /** @brief Update processor OOB configuration.
     *
     *  @details This API updates processor OOB configuration
     *  for MCA, DRAM and PCIe with the user input.
     *
     *  @param[in] oob_config_d_in - oob configuration data containing
     *  mca_oob_misc0_ec_enable, dram_cecc_oob_ec_mode,
     *  dram_cecc_leak_rate, pcie_err_reporting_en,
     *  pcie_ue_oob_counter_en and core_mca_err_reporting_en.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t setRasOobConfig(struct oob_config_d_in);

    /** @brief Get processor OOB configuration.
     *
     *  @details This API reads processor OOB configuration
     *  for MCA, DRAM and PCIe.
     *
     *  @param[out] oob_config_d_in - oob configuration data containing
     *  mca_oob_misc0_ec_enable, dram_cecc_oob_ec_mode,
     *  dram_cecc_leak_rate, pcie_err_reporting_en,
     *  pcie_ue_oob_counter_en and core_mca_err_reporting_en.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t getRasOobConfig(struct oob_config_d_in*);

    /** @brief Set PCIe OOB error reporting.
     *
     *  @details This API enables OOB configuration for PCIe
     *  based on PcieAerPollingEn attribute in rasConfigTable.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t setPcieOobConfig();

    /** @brief Update PCIe OOB configuration.
     *
     *  @details This API updates PCIe OOB registers and enables
     *  PCIe OOB error reporting.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t setPcieOobRegisters();

    /** @brief Set RAS error threshold configuration.
     *
     *  @details This API updates RAS error thresholds for
     *  MCA, DRAM and PCIe with the user input.
     *
     *  @param[in] run_time_threshold - runtime threshold configuration
     *  containing error type [00(MCA), 01(DRAM CECC), 10(PCIE_UE),
     *  11(PCIE_CE)], error count threshold and max interrupt rate.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t setRasErrThreshold(struct run_time_threshold);

    /** @brief Set PCIe error threshold configuration.
     *
     *  @details This API enables PCIe error thresholds
     *  based on PcieAerThresholdEn attribute in rasConfigTable.
     *
     *  @return OOB_SUCCESS is returned upon successful call.
     *  @return APML_ERR error code is returned upon failure.
     */
    oob_status_t setPcieErrThreshold();

    /** @brief Clear the SBRMI alert mask bit.
     *
     *  @details Clears alert mask bit in SBRMI control register
     *  for the given SOC socket number.
     *
     *  @param[in] socNum - Socket number of the processor.
     */
    void clearSbrmiAlertMask(uint8_t socNum);

    /** @brief Monitors the current host power state.
     *
     *  @details This API monitors the current host power state using
     *  xyz.openbmc_project.State.Host D-bus Interface.
     */
    void currentHostStateMonitor();

    /** @brief Initializes platform-specific settings.
     *
     *  @details It initializes the platform based on the family ID.
     *  Block ID's are selected based on the platform that needs to be
     *  harvested during a crashdump. It also invokes
     *  clearSbrmiAlertMask() API to clear Sbrmi::AlertMask bit
     */
    void platformInitialize();

    /** @brief decodes the APML_ALERT_L assertion cause by checking
     *  RAS status register.
     *
     * @details It reads RAS status register and check if the APML assertion is
     * due to Fatal error or runtime error overflow and takes the necessary
     * actions.
     *
     *  @param[in] socNum - Socket number of the processor.
     */
    bool decodeInterrupt(uint8_t);

    /** @brief Check the validity of MCA banks.
     *
     * @details This function performs a validity check on the MCA banks.
     *
     *  @param[in] socNum - SoC number.
     *  @param[in] errorCheck - Pointer to the RAS df err validity check.
     *
     * @return Returns a boolean indicating whether the MCA banks are valid.
     */
    bool harvestMcaValidityCheck(uint8_t, struct ras_df_err_chk*);

    /** @brief Check the validity of runtime errors.
     *
     * @details This function performs a validity check on runtime errors.
     *
     *  @param[in] socNum - SoC number.
     *  @param[in] rt_err_category - Structure containing the runtime error
     * category.
     *  @param[in] inst - Pointer to the structure containing valid error
     * instances.
     *
     * @return Returns the status of the APML runtime validity check command.
     */
    oob_status_t runTimeErrValidityCheck(uint8_t, struct ras_rt_err_req_type,
                                         struct ras_rt_valid_err_inst*);

    /** @brief Harvest runtime errors.
     *
     * @details This function collects runtime errors based on the specified
     * error polling type
     *
     * @param[in] errorPollingType - The type of error polling.
     * @param[in] p0Inst - Structure representing a valid RAS error instance for
     * processor 0.
     * @param[in] p1Inst - Structure representing a valid RAS error instance for
     * processor 1.
     *
     */
    void harvestRuntimeErrors(uint8_t, struct ras_rt_valid_err_inst,
                              struct ras_rt_valid_err_inst);

    /** @brief Check runtime error information.
     *
     * @details This function checks the validity of runtime error information
     * for the specified error type and request type.
     */
    void runTimeErrorInfoCheck(uint8_t, uint8_t);

    /** @brief Harvest MCA data banks.
     *
     * @details This function collects data from the MCA banks.
     * It takes the socket number, the number of banks, and
     * the number of bytes per MCA bank as parameters.
     *
     **
     * @param[in] errType - The type of error to check.
     * @param[in] reqType - errorCheck - Pointer to the RAS df err validity
     *check.
     *
     */
    void harvestMcaDataBanks(uint8_t, struct ras_df_err_chk);

    /** @brief Retrieves the last transaction address.
     *
     * @details This function retrieves the last transaction address
     * of the system via APML when the syncflood occuered
     *
     * @param[in] fatalPtr - Shared pointer to a FatalCperRecord object.
     * @param[in] socNum - The SoC number.
     *
     */
    void getLastTransAddr(const std::shared_ptr<FatalCperRecord>&, uint8_t);

    /** @brief Harvests debug log ID dump data
     *
     * @details This function harvests the debug log ID data for the list
     * of the block ID's provided to the function
     *
     * @param[in] fatalPtr - Shared pointer to a FatalCperRecord object.
     * @param[in] socNum - The SoC number.
     * @param[in] blkId - The block ID.
     * @param[in] apmlRetryCount - Pointer to the APML retry count.
     * @param[out] debugLogIdOffset - Reference to the debug log ID offset.
     *
     */
    void harvestDebugLogDump(const std::shared_ptr<FatalCperRecord>&, uint8_t,
                             uint8_t, int64_t*, uint16_t&);

    /** @brief Dumps the processor error section of the CPER record
     *
     * @details This function dumps the processor error section for
     * fatal and runtime errors cper record.
     *
     * @param[in] data - Shared pointer to a PtrType object containing the data.
     * @param[in] socNum - The SoC (System on Chip) number.
     * @param[in] inst - Structure representing a valid RAS error instance.
     * @param[in] category - The error category.
     * @param[in] section - The error section.
     * @param[in] Severity - Pointer to the severity level of the error.
     * @param[in] CheckInfo - Pointer to the check information related to the
     * error.
     *
     */
    template <typename T>
    void dumpProcErrorSection(const std::shared_ptr<T>&, uint8_t,
                              struct ras_rt_valid_err_inst, uint8_t, uint16_t,
                              uint32_t*, uint64_t*);

    /** @brief Harvest DRAM CECC error counters.
     *
     * @details This function collects (CECC) error counters from DRAM.
     * It takes a structure for valid error instances and the
     * socket number as parameters.
     *
     * @param[in] inst - Structure representing a valid RAS error instance.
     * @param[in] socNum - The SoC (System on Chip) number.
     *
     */
    void harvestDramCeccErrorCounters(struct ras_rt_valid_err_inst, uint8_t);

    /** @brief Set MCA OOB configuration.
     *
     * @details This function configures the MCA and DRAM CECC settings for OOB
     * error reporting.
     */
    oob_status_t setMcaOobConfig();

    /** @brief Poll for runtime errors.
     *
     * @details This function continuously polls for runtime errors and handles
     * their configuration and processing. It sets the MCA and DRAM OOB
     * configurations, and if supported, starts separate threads for polling
     * MCA, DRAM CECC, and PCIe AER errors based on user settings.
     */
    void runTimeErrorPolling();

    /** @brief Handle MCA error polling.
     *
     * @details This function manages the polling of runtime MCA errors.
     * It checks if MCA polling is enabled, performs the runtime error
     * information check, and sets up a timer for periodic polling.
     *
     * @param[in] pollingPeriod - Pointer to the polling period in seconds.
     */
    void mcaErrorPollingHandler(int64_t*);

    /** @brief Handle DRAM CECC error polling.
     *
     * @details This function manages the polling of runtime MCA errors.
     * It checks if DRAM CECC polling is enabled, performs the runtime error
     * information check, and sets up a timer for periodic polling.
     *
     * @param[in] pollingPeriod - Pointer to the polling period in seconds.
     */
    void dramCeccErrorPollingHandler(int64_t*);

    /** @brief Handle PCIE AER error polling.
     *
     * @details This function manages the polling of runtime PCIE AER errors.
     * It checks if PCIE AER polling is enabled, performs the runtime error
     * information check, and sets up a timer for periodic polling.
     *
     * @param[in] pollingPeriod - Pointer to the polling period in seconds.
     */
    void pcieAerErrorPollingHandler(int64_t*);

    /** @brief Set MCA error threshold.
     *
     * @details This function configures the error threshold settings for MCA
     * errors.
     */
    oob_status_t setMcaErrThreshold();

    /** @brief Get OOB registers configuration.
     *
     * @details This function retrieves the OOB runtime error settings
     *
     *  @param[in] oob_config_d_in - oob configuration data containing
     *  mca_oob_misc0_ec_enable, dram_cecc_oob_ec_mode,
     *  dram_cecc_leak_rate, pcie_err_reporting_en,
     */
    oob_status_t getOobRegisters(struct oob_config_d_in*);
};

} // namespace apml
} // namespace ras
} // namespace amd
