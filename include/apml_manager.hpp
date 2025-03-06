#include "error_monitor.hpp"

extern "C"
{
#include "apml.h"
#include "apml_common.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
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
class Manager : public amd::ras::Manager
{
  public:
    Manager() = delete;
    ~Manager() = default;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;

    Manager(amd::ras::config::Manager& manager,
            sdbusplus::asio::object_server& objectServer,
            std::shared_ptr<sdbusplus::asio::connection>& systemBus,
            boost::asio::io_context& io);

    virtual void init();

    virtual void configure();

    /**
     * @brief Requests GPIO events for hardware alert handling.
     *
     * @details This function configures a GPIO line and stream descriptor to
     * listen for events. It triggers the provided callback function upon event
     * detection.
     */
    void requestGPIOEvents(const std::string&, const std::function<void()>&,
                           gpiod::line&,
                           boost::asio::posix::stream_descriptor&);

    /**
     * @brief Handler for alert events.
     *
     * @details This function is invoked when an alert event occurs on P0 or P1.
     * The function handles the event by processing the necessary response.
     */
    void alertEventHandler(boost::asio::posix::stream_descriptor&,
                           const gpiod::line&, size_t);

    /** @brief Stream descriptor for handling  APML alert events.
     *
     *  @details This stream descriptor listens for alert events related to the
     *  processor and triggers actions upon detection.
     */
    std::vector<boost::asio::posix::stream_descriptor> gpioEventDescriptors;

  private:
    sdbusplus::asio::object_server& objectServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;

    uint8_t progId;
    uint64_t recordId;
    size_t watchdogTimerCounter;
    boost::asio::io_context& io;
    std::mutex harvestMutex;
    std::vector<uint8_t> blockId;
    bool apmlInitialized;
    bool platformInitialized;
    bool runtimeErrPollingSupported;
    bool p0AlertProcessed;
    bool p1AlertProcessed;
    boost::asio::deadline_timer* McaErrorPollingEvent;
    boost::asio::deadline_timer* DramCeccErrorPollingEvent;
    boost::asio::deadline_timer* PcieAerErrorPollingEvent;
    std::mutex mcaErrorHarvestMtx;
    std::mutex dramErrorHarvestMtx;
    std::mutex pcieErrorHarvestMtx;

    /** @brief Update processor OOB configuration.
     *
     *  @details This API updates processor OOB configuration
     *  for MCA, DRAM and PCIe with the user input.
     */
    oob_status_t setRasOobConfig(struct oob_config_d_in);

    /** @brief Get processor OOB configuration.
     *
     *  @details This API reads processor OOB configuration
     *  for MCA, DRAM and PCIe.
     */
    oob_status_t getRasOobConfig(struct oob_config_d_in*);

    /** @brief Set PCIe OOB error reporting.
     *
     *  @details This API enables OOB configuration for PCIe
     *  based on PcieAerPollingEn attribute in rasConfigTable.
     */
    oob_status_t setPcieOobConfig();

    /** @brief Update PCIe OOB configuration.
     *
     *  @details This API updates PCIe OOB registers and enables
     *  PCIe OOB error reporting.
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
     */
    oob_status_t setPcieErrThreshold();

    /** @brief Clear the SBRMI alert mask bit.
     *
     *  @details Clears alert mask bit in SBRMI control register
     *  for the given SOC socket number.
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
     */
    bool decodeInterrupt(uint8_t);

    /** @brief Check the validity of MCA banks.
     *
     * @details This function performs a validity check on the MCA banks.
     * returns a boolean indicating whether the MCA banks are valid.
     */
    bool harvestMcaValidityCheck(uint8_t, uint16_t*, uint16_t*);

    /** @brief Check the validity of runtime errors.
     *
     * @details This function performs a validity check on runtime errors.
     * Returns the status of the APML runtime validity check command.
     */
    oob_status_t runTimeErrValidityCheck(uint8_t, struct ras_rt_err_req_type,
                                         struct ras_rt_valid_err_inst*);

    /** @brief Harvest runtime errors.
     *
     * @details This function collects runtime errors based on the specified
     * error polling type
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
     */
    void harvestMcaDataBanks(uint8_t, uint16_t, uint16_t);

    /** @brief Retrieves the last transaction address.
     *
     * @details This function retrieves the last transaction address
     * of the system via APML when the syncflood occuered
     */
    void getLastTransAddr(const std::shared_ptr<FatalCperRecord>&, uint8_t);

    /** @brief Harvests debug log ID dump data
     *
     * @details This function harvests the debug log ID data for the list
     * of the block ID's provided to the function
     */
    void harvestDebugLogDump(const std::shared_ptr<FatalCperRecord>&, uint8_t,
                             uint8_t, int64_t*, uint16_t&);

    /** @brief Dumps the processor error section of the CPER record
     *
     * @details This function dumps the processor error section for
     * fatal and runtime errors cper record.
     */
    template <typename T>
    void dumpProcErrorSection(const std::shared_ptr<T>& data, uint8_t soc_num,
                              struct ras_rt_valid_err_inst inst,
                              uint8_t category, uint16_t Section,
                              uint32_t* Severity, uint64_t* CheckInfo);

    /** @brief Harvest DRAM CECC error counters.
     *
     * @details This function collects (CECC) error counters from DRAM.
     * It takes a structure for valid error instances and the
     * socket number as parameters.
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
     */
    void mcaErrorPollingHandler(int64_t*);

    /** @brief Handle DRAM CECC error polling.
     *
     * @details This function manages the polling of runtime MCA errors.
     * It checks if DRAM CECC polling is enabled, performs the runtime error
     * information check, and sets up a timer for periodic polling.
     *
     */
    void dramCeccErrorPollingHandler(int64_t*);

    /** @brief Handle PCIE AER error polling.
     *
     * @details This function manages the polling of runtime PCIE AER errors.
     * It checks if PCIE AER polling is enabled, performs the runtime error
     * information check, and sets up a timer for periodic polling.
     *
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
     */
    oob_status_t getOobRegisters(struct oob_config_d_in*);
};

} // namespace apml
} // namespace ras
} // namespace amd
