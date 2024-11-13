#include "config_manager.hpp"
#include "ras.hpp"

#include <boost/asio/io_service.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <gpiod.hpp>
#include <nlohmann/json.hpp>

/* Base class for managing Ras (Reliability, Availability, and
   Serviceability) configurations.*/
class RasManagerBase : public RasConfiguration
{
  public:
    /**
     * @brief Constructs a RasManagerBase object.
     *
     * This constructor initializes the base class RasConfiguration and sets up
     * the object with the provided parameters, including the IO service and
     * alert event objects.
     *
     * @param[in] objectServer Reference to the object server for DBus
     * integration.
     * @param[in] systemBus Shared pointer to the system bus for DBus
     * communication.
     * @param[in] io Reference to the boost::asio::io_service used for
     * asynchronous operations.
     */
    RasManagerBase(sdbusplus::asio::object_server& objectServer,
                   std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                   boost::asio::io_service& io) :
        RasConfiguration(objectServer, systemBus), io(io),
        p0_apmlAlertEvent(io), p1_apmlAlertEvent(io)
    {}

    /**
     * @brief Initializes the RasManagerBase object.
     *
     * This is a pure virtual function, intended to be implemented by derived
     * classes to perform any necessary initialization specific to the subclass.
     */
    virtual void init() = 0;

    /**
     * @brief Configures the RasManagerBase object.
     *
     * This is a pure virtual function, intended to be implemented by derived
     * classes to configure the RasManagerBase object for specific use cases.
     */
    virtual void configure() = 0;

    /**
     * @brief Destructor for RasManagerBase.
     *
     * Virtual destructor ensures proper cleanup of derived class objects.
     */
    virtual ~RasManagerBase();

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
     * This function is invoked when an alert event occurs on P0. The function
     * handles the event by processing the necessary response.
     */
    void p1AlertEventHandler();

  protected:
    boost::asio::io_service& io;
    uint8_t numOfCpu;
    CpuId* cpuId;
    uint32_t* uCode;
    uint64_t* ppin;
    std::string* inventoryPath;
    unsigned int boardId;
    uint8_t progId;
    int errCount = 0;
    std::shared_ptr<FatalCperRecord> rcd = NULL;

    /**
     * @brief Stream descriptor for handling P0 APML alert events.
     *
     * This stream descriptor listens for alert events related to the P0 sensor
     * and triggers actions upon detection.
     */
    boost::asio::posix::stream_descriptor p0_apmlAlertEvent;

    /**
     * @brief Stream descriptor for handling P1 APML alert events.
     *
     * This stream descriptor listens for alert events related to the P1 sensor
     * and triggers actions upon detection.
     */
    boost::asio::posix::stream_descriptor p1_apmlAlertEvent;

    /**
     * @brief GPIO line for handling P0 alert events.
     *
     * This GPIO line is used to detect hardware alerts for P0 and trigger
     * events for processing.
     */
    gpiod::line p0_apmlAlertLine;

    /**
     * @brief GPIO line for handling P1 alert events.
     *
     * This GPIO line is used to detect hardware alerts for P1 and trigger
     * events for processing.
     */
    gpiod::line p1_apmlAlertLine;

    /**
     * @brief Retrieves the number of CPUs in the system.
     *
     * This function queries the system to obtain the number of CPUs and stores
     * the result in the numOfCpu member variable.
     */
    void getNumberOfCpu();

    /**
     * @brief Retrieves the board ID.
     *
     * This function queries the system to obtain the board ID and stores the
     * result in the boardId member variable.
     */
    void getBoardId();

    /**
     * @brief Creates an index file.
     *
     * This function generates an index file for CPER record tracking
     */
    void createIndexFile();

    /**
     * @brief Creates a configuration file.
     *
     * This function generates a RAS configuration file.
     */
    void createConfigFile();

    /**
     * @brief Retrieves the CPU microcode revision.
     *
     * This function queries the CPU for its microcode revision and stores it in
     * the uCode member variable.
     */
    void getMicrocodeRev();

    /**
     * @brief Retrieves the PPIN fuse value.
     *
     * This function queries the system for the PPIN fuse value and stores it in
     * the ppin member variable.
     */
    void getPpinFuse();

    /**
     * @brief Fetches a property from DBus.
     *
     * This template function retrieves a property from DBus based on the given
     * object path, interface, and property name.
     *
     * @param[in] bus The DBus connection to query.
     * @param[in] path The object path of the DBus object.
     * @param[in] interface The interface of the DBus object.
     * @param[in] property The name of the property to retrieve.
     * @param[in] dbusMethod The DBus method to call to fetch the property.
     *
     * @return The property value of type T, if found.
     */
    template <typename T>
    T getProperty(sdbusplus::bus::bus&, const char*, const char*, const char*,
                  const char*);

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

    void rasRecoveryAction(uint8_t);

    /**
     * @brief Triggers a cold reset of the system.
     *
     * This function triggers a cold reset.
     */
    void triggerColdReset();

    /**
     * @brief Triggers a reset through the RSMRST signal.
     *
     * This function triggers a reset using the RSMRST signal.
     */
    void triggerRsmrstReset();

    /**
     * @brief Triggers a reset through the SYS RST signal.
     *
     * This function triggers a reset using the SYS_RST signal (system reset).
     */
    void triggerSysReset();

    /**
     * @brief Requests a system transition.
     *
     * This function requests a transition for the host system,
     * such as a change in state or mode (e.g., shutdown, reboot).
     *
     * @param[in] transitionType A string that specifies the type
     * of transition to request.
     */
    void requestHostTransition(std::string);

    virtual void triggerWarmReset() = 0;

    virtual void interfaceActiveMonitor() = 0;

    virtual void getCpuId() = 0;

    virtual void findProgramId() = 0;

    virtual void harvestFatalError(uint8_t) = 0;
};
