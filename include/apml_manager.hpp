#pragma once

#include "base_manager.hpp"

extern "C"
{
#include "apml_alertl_uevent.h"
#include "esmi_mailbox.h"
#include "linux/amd-apml.h"
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

    /** @brief Perform initilization for the error monitoring.
     *
     *  @details It initializes the APML RAS Manager by repeatedly attempting to
     *  get the BMC RAS OOB configuration and setting up platform and watchdog
     *  state monitoring for bios post complete. It also reads CPU IDs,
     *  configures PCIE settings, and clears the SbrmiAlertMask register for
     *  crashdump readiness.
     */
    void init() override;

    /** @brief Configure APML RAS settings.
     *
     *  @details This function reads the gpio configuration from the
     *  amd_ras_gpio_config.json file including alert handle mode and
     *  GPIO alert line names.
     */
    void configure() override;

    /** @brief Register udev or request GPIO event for APML alert handling.
     *
     *  @details This function registers for udev events from Alertl_L driver on
     *  RAS alerts or sets up GPIO event handling for APML alerts based on
     *  apmlAlertFlag. If APML Alert_L is enabled, it uses the APML API to
     *  register for udev events. Otherwise, it requests GPIO events for alert
     *  handling by binding the alert event handler to the respective GPIO
     *  lines.
     */
    void registerEventHandler() override;

    /** @brief Unregister the APML Alert_L udev events.
     *
     *  @details This function invokes APML API to unregister for udev events on
     *  RAS alerts.
     */
    void releaseUdevReSrc();

    /** @brief apmlAlertlFlag getter function
     *
     *  @details This function returns the alertHandleMode. The value
     *  is read from the amd_ras_gpio_config.json file
     */
    const std::string& getAlertHandleMode() const
    {
        return alertHandleMode;
    }

  private:
    sdbusplus::asio::object_server& objectServer;

    size_t contextType;
    size_t watchdogTimerCounter;
    boost::asio::io_context& io;
    bool pmfwRuntimeReady;
    bool platformInitialized;
    bool runtimeErrPollingSupported;
    /** @brief Set once a control fabric error (RasStatus[reset_ctrl_err]) is
     *  detected. While set, incoming RAS error alerts are ignored until the
     *  host is rebooted, since the system is expected to be reset by policy.
     */
    bool cfErrorReceived;
    std::vector<bool> cpuAlertProcessed;
    boost::asio::deadline_timer* McaErrorPollingEvent;
    boost::asio::deadline_timer* DramCeccErrorPollingEvent;
    boost::asio::deadline_timer* PcieAerErrorPollingEvent;
    boost::asio::deadline_timer* ApmlAlertEvent;
    std::mutex mcaErrorHarvestMtx;
    std::mutex dramErrorHarvestMtx;
    std::mutex pcieErrorHarvestMtx;
    std::vector<gpiod::line> gpioLines;
    std::vector<apml_udev_monitor> ud;
    std::string alertHandleMode;
    std::vector<std::string> socketNames;

    /**
     * @brief Handler for alert events.
     *
     * @details This function is invoked when an alert event occurs on P0 or P1.
     * The function handles the event by processing the necessary response.
     *
     * @param[in] udev_mon - Udev monitor for monitoring event source from APML
     * Alert_L driver.
     */
    void alertSrcHandler(struct apml_udev_monitor* udev_mon, uint8_t socket);

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

    /** @brief Handle the transition to the PMFW-ready state.
     *
     *  @details Performs the platform initialization that requires PMFW
     *  (processor info, thresholds, runtime error polling) and reads CPUIDs.
     *  Deferred until PMFW is ready.
     */
    void pmfwReadyHandler() override;

    /** @brief Handle the transition to the PMFW-not-ready state.
     *
     *  @details Tears down platform initialization by stopping runtime error
     *  polling and clearing pmfwRuntimeReady so runtime validity checks are
     *  skipped until PMFW is ready again.
     */
    void pmfwNotReadyHandler() override;

    /** @brief Deactivate runtime error polling.
     *
     *  @details Cancels the MCA, DRAM CECC and PCIe AER runtime error polling
     *  timers. Invoked when a control fabric error (RasStatus[reset_ctrl_err])
     *  is detected, since the system is expected to be reset based on policy
     *  and further runtime polling is no longer meaningful.
     */
    void deactivateRuntimeErrorPolling();

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

    /** @brief Called when the host power state changes.
     *
     *  @details Performs APML-specific actions on host state transitions,
     *  such as waiting for OOB config readiness and triggering platform
     *  initialization.
     *
     *  @param[in] hostOff - true if the host transitioned to Off state.
     */
    void onHostStateChanged(bool hostOff) override;

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
     *  @param[in] src - Source of the APML Alert_L events.
     */
    bool decodeInterrupt(uint8_t, uint32_t);
    bool decodeInterrupt(uint8_t);

    /** @brief Merge autonomous MP trace data from amd-traces service into CPER.
     *
     *  @param[in] fullPath - Full path to the CPER file to merge into.
     */
    void mergeAutonomousTraceData(const std::string& fullPath);

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
     * @param[in] instVec - Vector of valid RAS error instances, one per
     *            socket in socIndex order.
     *
     */
    void harvestRuntimeErrors(uint8_t,
                              std::vector<struct ras_rt_valid_err_inst>&);

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

    /** @brief Decode MCA IPID register to identify the logical core.
     *
     * @details Decodes the MCA_IPID 64-bit register to extract hardware ID,
     * MCA type, and instance IDs. If the bank belongs to a core MCA unit
     * (LS, IF, L2, DE, EX, FP), the logical core index is computed and
     * inserted into the provided set.
     *
     * @param[in] socNum - Socket number of the processor.
     * @param[in] mcaIpidHi - Upper 32 bits of MCA_IPID register.
     * @param[in] mcaIpidLo - Lower 32 bits of MCA_IPID register.
     * @param[out] errorCores - Set of logical core indices with errors.
     */
    void decodeIpidForCore(uint8_t socNum, uint32_t mcaIpidHi,
                           uint32_t mcaIpidLo, std::set<size_t>& errorCores);

    /** @brief Count per-core MCA errors from runtime error info and update
     *         error counters.
     *
     * @details Scans MCA error info entries in the given index range,
     *          decodes IPID to identify affected cores, and increments
     *          the appropriate correctable/non-correctable CPU or Other
     *          error counters.
     *
     * @param[in] socNum - Socket number of the processor.
     * @param[in] startIdx - Start index into McaErrorInfo array.
     * @param[in] endIdx - End index (exclusive) into McaErrorInfo array.
     */
    void countRuntimeMcaErrors(uint8_t socNum, uint16_t startIdx,
                               uint16_t endIdx);

    /** @brief Update per-core error counters based on decoded error cores.
     *
     * @details Increments correctable or non-correctable CPU error counts
     *          for each identified core, or increments the Other error
     *          count if no per-core bank was identified.
     *
     * @param[in] socNum - Socket number of the processor.
     * @param[in] uncorrectableError - Whether an uncorrectable error was found.
     * @param[in] errorCores - Set of logical core indices with errors.
     */
    void updatePerCoreErrorCounts(uint8_t socNum, bool uncorrectableError,
                                  const std::set<size_t>& errorCores);

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

    /** @brief Harvests uncore IFT dump data
     *
     * @details This function harvests the dump data for debug log ID 25
     *
     * @param[in] fatalPtr - Shared pointer to a FatalCperRecord object.
     * @param[in] socNum - The SoC number.
     * @param[in] apmlRetryCount - Pointer to the APML retry count.
     * @param[out] debugLogIdOffset - Reference to the debug log ID offset.
     *
     */
    void harvestUncoreIftDump(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                              uint8_t socNum, int64_t* apmlRetryCount,
                              uint16_t& debugLogIdOffset);

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

    /** @brief Harvest x86 exception core debug dump data.
     *
     * @details When SBRMI::RASStatus[7] (x86 exception bit) is set, this
     * function uses the BMC_RAS_DBG_LOG_VALIDITY_CHECK and
     * BMC_RAS_DBG_LOG_DUMP APML commands to harvest core debug trace data
     * from cores that encountered x86 exceptions (e.g., segmentation
     * faults). The harvested data is stored in a Core Debug Dump CPER
     * record.
     *
     * @param[in] socNum - Socket number of the processor.
     */
    void harvestX86ExceptionData(uint8_t socNum);

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

    /** @brief Check if CPU alerts have been processed.
     *
     * @details This function verifies whether all CPU alerts have been
     *          handled by the alert processing logic.
     *
     * @return true  If all CPU alerts have been processed successfully.
     * @return false If there are pending CPU alerts that have not been
     * processed.
     */
    bool checkIfCPUAlertsProcessed();
};

} // namespace apml
} // namespace ras
} // namespace amd
