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

namespace ras
{
namespace apml
{
class Manager : public ras::Manager
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
            boost::asio::io_context& io) :
        ras::Manager(manager), p0apmlAlertEvent(io), p1apmlAlertEvent(io),
        objectServer(objectServer), systemBus(systemBus), io(io)
    {}

    virtual void init();

    virtual void configure();

    /**
     * @brief Requests GPIO events for hardware alert handling.
     *
     * This function configures a GPIO line and stream descriptor to listen for
     * events. It triggers the provided callback function upon event detection.
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
     * @brief Handler for P0 alert events.
     *
     * This function is invoked when an alert event occurs on P0. The function
     * handles the event by processing the necessary response.
     */
    void p0AlertEventHandler();

    /**
     * @brief Handler for P1 alert events.
     *
     * This function is invoked when an alert event occurs on P1. The function
     * handles the event by processing the necessary response.
     */
    void p1AlertEventHandler();

    /**
     * @brief GPIO line for handling P0 alert events.
     *
     * This GPIO line is used to detect hardware alerts for P0 and trigger
     * events for processing.
     */
    gpiod::line p0apmlAlertLine;

    /**
     * @brief GPIO line for handling P1 alert events.
     *
     * This GPIO line is used to detect hardware alerts for P1 and trigger
     * events for processing.
     */
    gpiod::line p1apmlAlertLine;

    /**
     * @brief Stream descriptor for handling P0 APML alert events.
     *
     * This stream descriptor listens for alert events related to the P0 sensor
     * and triggers actions upon detection.
     */
    boost::asio::posix::stream_descriptor p0apmlAlertEvent;

    /**
     * @brief Stream descriptor for handling P1 APML alert events.
     *
     * This stream descriptor listens for alert events related to the P1 sensor
     * and triggers actions upon detection.
     */
    boost::asio::posix::stream_descriptor p1apmlAlertEvent;

  private:
    sdbusplus::asio::object_server& objectServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    std::vector<uint8_t> blockId;
    boost::asio::io_context& io;
    uint8_t progId = 1;
    uint64_t recordId = 1;
    std::mutex harvestMutex; // Mutex for synchronization
    bool p0AlertProcessed = false;
    bool p1AlertProcessed = false;
    bool apmlInitialized = false;
    bool platformInitialized = false;
    uint8_t watchdogTimerCounter = 0;
    bool runtimeErrPollingSupported = false;
    bool decodeInterrupt(uint8_t);
    bool harvestMcaValidityCheck(uint8_t, uint16_t*, uint16_t*);
    void getLastTransAddr(const std::shared_ptr<FatalCperRecord>&, uint8_t);
    void harvestDebugLogDump(const std::shared_ptr<FatalCperRecord>&, uint8_t,
                             uint8_t, int64_t*, uint16_t&);
    boost::asio::deadline_timer* McaErrorPollingEvent = nullptr;
    boost::asio::deadline_timer* DramCeccErrorPollingEvent = nullptr;
    boost::asio::deadline_timer* PcieAerErrorPollingEvent = nullptr;
    std::mutex mcaErrorHarvestMtx;
    std::mutex dramErrorHarvestMtx;
    std::mutex pcieErrorHarvestMtx;

    template <typename T>
    void dumpProcErrorSection(const std::shared_ptr<T>& data, uint8_t soc_num,
                              struct ras_rt_valid_err_inst inst,
                              uint8_t category, uint16_t Section,
                              uint32_t* Severity, uint64_t* CheckInfo);

    oob_status_t bmcRasOobConfig(struct oob_config_d_in);

    oob_status_t setMcaOobConfig();

    void mcaErrorPollingHandler(int64_t*);

    void dramCeccErrorPollingHandler(int64_t*);

    void pcieAerErrorPollingHandler(int64_t*);

    oob_status_t mcaErrThresholdEnable();

    oob_status_t rasErrThresholdSet(struct run_time_threshold);

    oob_status_t setPcieOobConfig();

    oob_status_t getOobRegisters(struct oob_config_d_in*);

    oob_status_t setPcieOobRegisters();

    oob_status_t pcieErrThresholdEnable();

    void runTimeErrorPolling();

    void harvestMcaDataBanks(uint8_t, uint16_t, uint16_t);

    void clearSbrmiAlertMask(uint8_t);

    void currentHostStateMonitor();

    void platformInitialize();

    oob_status_t runTimeErrValidityCheck(uint8_t, struct ras_rt_err_req_type,
                                         struct ras_rt_valid_err_inst*);

    void harvestRuntimeErrors(uint8_t, struct ras_rt_valid_err_inst,
                              struct ras_rt_valid_err_inst);

    void runTimeErrorInfoCheck(uint8_t, uint8_t);

    void harvestDramCeccErrorCounters(struct ras_rt_valid_err_inst,
                                      uint8_t );

};

} // namespace apml

} // namespace ras
