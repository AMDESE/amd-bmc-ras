#pragma once

#include "config_manager.hpp"
#include "cper.hpp"
#include "cper_generator.hpp"
#include "ras.hpp"

#include <cstdint>

extern "C" {
#include "apml.h"
#include "apml_common.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

class InterfaceManager : public RasConfiguration
{

  private:
    uint8_t numOfCpu;
    CpuId* cpuId;
    bool apmlInitialized;
    std::vector<uint8_t> blockId;
    uint32_t familyId;
    unsigned int boardId;
    uint8_t progId;
    uint32_t* uCode;
    uint64_t* ppin;
    int errCount;
    std::shared_ptr<CperRecord> rcd;
    boost::asio::io_service& io;
    gpiod::line p0_apmlAlertLine;
    gpiod::line p1_apmlAlertLine;
    boost::asio::posix::stream_descriptor p0_apmlAlertEvent;
    boost::asio::posix::stream_descriptor p1_apmlAlertEvent;
    void p0AlertEventHandler();
    void p1AlertEventHandler();
    std::string* inventoryPath;
    bool p0AlertProcessed;
    bool p1AlertProcessed;
    std::mutex harvest_in_progress_mtx;

    /**
     * @brief Retrieves the CPU ID.
     *
     * This function obtains the CPU ID of the system.
     */
    void getCpuId();

    /**
     * @brief Retrieves the microcode revision.
     *
     * This function retrieves the version of microcode currently loaded on the
     * CPU.
     */
    void getMicrocodeRev();

    /**
     * @brief Retrieves the PPIN (Platform Processor Identification Number)
     * fuse.
     *
     * This function obtains the PPIN fuse value associated with the hardware
     * platform.
     */
    void getPpinFuse();

    /**
     * @brief Retrieves the board ID.
     *
     * This function retrieves the Board ID of the motherboard.
     */
    void getBoardId();

    /**
     * @brief Retrieves the number of sockets
     *
     * This function determines the total number of sockets in the system.
     */
    void getNumberOfCpu();

    /**
     * @brief Finds the program ID.
     */
    void findProgramId();

    /**
     * @brief Creates an index file.
     *
     * This function generates an index file to keep track of error count.
     */
    void createIndexFile();

    /**
     * @brief Creates a configuration file.
     *
     * This function generates a configuration file with default settings and
     * parameters. The configuration file can ve modified by the user in
     * runtime.
     */
    void createConfigFile();

    /**
     * @brief Harvests information related to a fatal error.
     *
     * @param info The error code or information related to the fatal error.
     */
    void harvestFatalError(uint8_t);

    /**
     * @brief Clears SBRMI alert status register.
     *
     * @param info The socket number.
     */
    void clearSbrmiAlertMask(uint8_t);

    /**
     * @brief Checks if the APML interface is initialized or not.
     */
    void apmlInitializeCheck();

    /**
     * @brief Reads the value from a specified register.
     *
     * @param info The Socket Number.
     * @param reg The register address.
     * @param value Pointer to store the read value.
     * @return The status of the read operation (e.g., success, failure).
     */
    oob_status_t readRegister(uint8_t, uint32_t, uint8_t*);

    /**
     * @brief Writes a value to the specified register.
     *
     * @param info The Socket Number.
     * @param reg The register address.
     * @param value The value to write to the register.
     */
    void writeRegister(uint8_t, uint32_t, uint32_t);

    /**
     * @brief Retrieves a property value from a D-Bus interface.
     *
     * @tparam T The type of the property value to retrieve.
     * @param bus Reference to the D-Bus connection.
     * @param service The D-Bus service name.
     * @param path The D-Bus object path.
     * @param interface The D-Bus interface name.
     * @param propertyName The name of the property to retrieve.
     * @return The value of the requested property (of type T).
     */
    template <typename T>
    T getProperty(sdbusplus::bus::bus&, const char*, const char*, const char*,
                  const char*);

    /**
     * @brief Request GPIO events for a specific GPIO line.
     *
     * @param[in] name - The name of the GPIO line.
     * @param[in] handler - A function to be called when GPIO events occur.
     * @param[in,out] gpioLine - The GPIO line to configure for events.
     * @param[in,out] gpioEventDescriptor - A stream descriptor associated with
     * the GPIO line's events.
     */
    void requestGPIOEvents(const std::string&, const std::function<void()>&,
                           gpiod::line&,
                           boost::asio::posix::stream_descriptor&);

    /**
     * @brief Monitors the current host state.
     */
    void currentHostStateMonitor();

    /**
     *
     *@brief This function checks the validity of MCA data.
     *
     * @param The socket number.
     * @param numbanks Pointer to the number of MCA banks.
     * @param bytespermca Pointer to the size (in bytes) of each MCA entry.
     * @return True if the MCA data is valid; otherwise, false.
     */
    bool harvestMcaValidityCheck(uint8_t, uint16_t*, uint16_t*);

    /**
     * @brief Harvests Machine Check Architecture (MCA) data banks.
     *
     * @param info he socket number.
     * @param numbanks The number of MCA banks.
     * @param bytespermca The size (in bytes) of each MCA entry.
     * @param Shared pointer to the CPER record object.
     */
    template <typename T>
    void harvestMcaDataBanks(uint8_t, uint16_t, uint16_t, CperGenerator<T>&);

    /**
     * @brief Requests a host transition based on the specified command.
     *
     * @param command The command indicating the desired host transition.
     */
    void requestHostTransition(std::string);

    /**
     * @brief Initiates a cold reset.
     *
     * This function triggers a cold reset, which involves a complete system
     * restart. It performs a full power cycle, resetting all components and
     * clearing any volatile state.
     */
    void triggerColdReset();

  public:
    /**
     * @brief Constructor for the InterfaceManager class.
     *
     * Initializes an instance of InterfaceManager with the given parameters.
     *
     * @param objectServer Reference to the object server.
     * @param systemBus Reference to the system D-Bus connection.
     * @param io Reference to the boost::asio::io_service.
     */
    InterfaceManager(sdbusplus::asio::object_server& objectServer,
                     std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                     boost::asio::io_service& io) :
        RasConfiguration(objectServer, systemBus),
        io(io), apmlInitialized(false), rcd(nullptr), p0_apmlAlertEvent(io),
        p1_apmlAlertEvent(io), p0AlertProcessed(false), p1AlertProcessed(false)
    {

        init();

        configure();

        harvestDumps(ERROR_TYPE_FATAL);
    }

    ~InterfaceManager()
    {
        delete[] cpuId;
        delete[] uCode;
        delete[] ppin;
    }

    /**
     * @brief Initializes the RAS module.
     *
     * This function performs necessary initialization steps for the module.
     * It checks for number of CPU's, check if apml is initialized,
     * find the program ID and board ID.
     */
    void init();

    /**
     * @brief Configures the RAS module.
     *
     * This function creates the error index file , RAS configuration file
     * reads info such as PPIN and microcode.
     */
    void configure();

    /**
     * @brief Harvests dumps related to Fatal/Runtime error type
     *
     * This function collects relevant dump data associated with the given error
     * type.
     *
     * @param errorType The type of error for which to harvest dumps.
     */
    void harvestDumps(ErrorType);

    /**
     * @brief Performs recovery actions.
     *
     * This function executes recovery actions based on the current user
     * configuration. It may perfomr wam reset or cold reset or no reset.
     *
     * @param Value of RAS status register.
     */
    void rasRecoveryAction(uint8_t);
};
