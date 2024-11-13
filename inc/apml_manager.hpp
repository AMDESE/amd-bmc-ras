#include "cper_generator.hpp"
#include "interface_manager_base.hpp"

class ApmlInterfaceManager : public RasManagerBase
{
  public:
    /**
     * @brief Initializes the APML interface manager.
     *
     * This function performs any necessary initialization for the APML
     * interface manager.
     */
    virtual void init();

    /**
     * @brief Configures the APML interface manager.
     *
     * This function configures the settings for the ADDC enablement.
     */
    virtual void configure();

    /**
     * @brief Constructor for ApmlInterfaceManager.
     *
     * Initializes the ApmlInterfaceManager with the given object server,
     * system bus connection, and I/O service.
     *
     * @param[in] objectServer Reference to an object server for managing
     * D-Bus objects.
     * @param[in] systemBus Shared pointer to a D-Bus connection.
     * @param[in] io Reference to an I/O service for asynchronous operations.
     */
    ApmlInterfaceManager(
        sdbusplus::asio::object_server& objectServer,
        std::shared_ptr<sdbusplus::asio::connection>& systemBus,
        boost::asio::io_service& io) :
        RasManagerBase(objectServer, systemBus, io)
    {}

  protected:
    std::vector<uint8_t> blockId;       // Vector to hold block IDs
    uint32_t familyId;                  // Family ID
    std::mutex harvest_in_progress_mtx; // Mutex for synchronization
    bool p0AlertProcessed = false;      // Flag for P0 alert processing
    bool p1AlertProcessed = false;      // Flag for P1 alert processing
    uint64_t recordId = 1;              // Record ID
    uint16_t debugLogIdOffset;          // Offset for debug log ID
    uint32_t SignatureID[8];            // Array to hold signature IDs

    /**
     * @brief Monitors if APML interface is up
     *
     * This function monitors the status of the APML interface.
     */
    virtual void interfaceActiveMonitor();

    /**
     * @brief Retrieves the CPU ID.
     *
     * This function retrieves the CPU ID from the system.
     */
    virtual void getCpuId();

    /**
     * @brief Finds the program ID.
     *
     * This function locates the program ID associated with the system.
     */
    virtual void findProgramId();

    /**
     * @brief Harvests fatal error information.
     *
     * This function processes a fatal error based on its type.
     *
     * @param[in] errorType The type of fatal error to harvest.
     */
    virtual void harvestFatalError(uint8_t);

    /**
     * @brief Triggers a warm reset of the system.
     *
     * This function initiates a warm reset operation.
     */
    void triggerWarmReset() override;

    /**
     * @brief Clears the SBRMI alert mask.
     *
     * Requests de-assertion of APML_ALERT_L signal by clearing
     * SBRMI::Status[SwAlertSts]
     *
     * @param[in] soc_num - The socket number.
     */
    void clearSbrmiAlertMask(uint8_t soc_num);

    /**
     * @brief Performs platform initialization tasks.
     *
     * This function executes necessary initialization tasks specific to
     * the platform.
     */
    void performPlatformInitialization();

    /**
     * @brief Reads a register from the specified address.
     *
     * This function reads a value from a register at a given address.
     */
    oob_status_t readRegister(uint8_t, uint32_t, uint8_t*);

    /**
     * @brief Writes a value to a register at a specified address.
     *
     * This function writes a value to a register at a given address.
     *
     */
    void writeRegister(uint8_t, uint32_t, uint32_t);

    /**
     * @brief Compares values using bitwise AND operation with expected values.
     *
     * This function checks if there is a match between values and expected
     * results using bitwise AND operation.
     *
     * @param[in] values Pointer to an array of values.
     * @param[in] expected The expected string representation of values.
     *
     * @return True if there is a match, false otherwise.
     */
    bool compare_with_bitwise_AND(const uint32_t* values,
                                  const std::string& expected);

    /**
     * @brief Checks if the signature ID matches expected values.
     *
     * This function verifies if the stored signature ID matches expected
     * values.
     *
     * @return True if there is a match, false otherwise.
     */
    bool checkSignatureIdMatch();

    /**
     * @brief Converts a hexadecimal string to a vector of uint32_t.
     *
     * This function takes a hexadecimal string and converts it into a
     * vector of unsigned 32-bit integers.
     *
     * @param[in] hexString The hexadecimal string to convert.
     *
     * @return A vector containing converted values.
     */
    std::vector<uint32_t> hexstring_to_vector(const std::string& hexString);

    /**
     * @brief MCA data harvesting.
     *
     */
    bool harvestMcaValidityCheck(uint8_t type, uint16_t* param1,
                                 uint16_t* param2);

    /**
     * @brief Harvests MCA data banks.
     *
     */
    template <typename T>
    void harvestMcaDataBanks(uint8_t bank, uint16_t, uint16_t,
                             CperGenerator<T>&);

    /**
     * @brief Harvests last transaction address using command 5Ch
     *
     */
    void getLastTransAddr(EFI_AMD_FATAL_ERROR_DATA* errorData, uint8_t type);

    void dumpContextInfo(EFI_AMD_FATAL_ERROR_DATA* errorData, uint8_t type);

    void harvestDebugLogDump(EFI_AMD_FATAL_ERROR_DATA* errorData, uint8_t,
                             uint8_t);
};
