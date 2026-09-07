#pragma once

#include "config_manager.hpp"
#include "oem_cper.hpp"

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>

#include <algorithm>
#include <mutex>

constexpr size_t socket1 = 1;
constexpr size_t socket2 = 2;
constexpr size_t socket3 = 3;
constexpr size_t socket4 = 4;

namespace amd
{
namespace ras
{
// PMFW readiness notification contract (single D-Bus signal emitted by
// amd-host-manager). Shared by the APML and PLDM managers to defer the
// PMFW-dependent platform initialization until PMFW is ready, and to tear it
// down when PMFW is not ready. The signal carries the readiness state as a
// boolean argument (true = ready, false = not ready).
constexpr auto pmfwStatusInterface = "com.amd.PmfwStatus";
constexpr auto pmfwStatusPathPrefix = "/com/amd/pmfw/host";
constexpr auto pmfwStatusSignal = "PmfwStatus";

struct CpuId
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

/** @brief Manages RAS (Reliability, Availability, and Serviceability)
 * operations.
 *
 *  @details This class is responsible for managing RAS operations, including
 * initialization, configuration, and handling of various RAS-related tasks. It
 * provides a foundation for derived classes to implement specific RAS
 * functionalities.
 *
 *  @param[in] manager - Reference to the configuration manager.
 *  @param[in] node - host node number to determine single or multi host.
 */
class Manager
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    Manager(amd::ras::config::Manager&,
            std::shared_ptr<sdbusplus::asio::connection>&, std::string&);
    ~Manager() = default;

    /** @brief Initializes the RAS manager class.

     * @details This pure virtual function must be overridden by any derived
     class. It is intended to perform any necessary initialization specific to
     the derived class.
     *
     */
    virtual void init() = 0;

    /** @brief Configures the RAS manager class.

     * @details This pure virtual function must be overridden by any derived
     class. It is intended to perform any necessary configuration specific to
     the derived class such as setting thresholds from a JSON file.
     *
     */
    virtual void configure() = 0;

    /** @brief Registers event handlers for RAS alert handling.

     * @details This pure virtual function must be overridden by any derived
     class. It is intended to set up the event handling mechanism for
     receiving RAS notifications.
     *
     */
    virtual void registerEventHandler() = 0;

  protected:
    size_t errCount;
    size_t cpuCount;
    uint32_t boardId;
    uint32_t familyId;
    uint8_t progId;
    uint64_t recordId;
    std::unique_ptr<CpuId[]> cpuId;
    std::unique_ptr<uint32_t[]> uCode;
    std::unique_ptr<uint64_t[]> ppin;
    std::unique_ptr<std::string[]> inventoryPath;
    amd::ras::config::Manager& configMgr;
    std::shared_ptr<FatalCperRecord> rcd;
    std::shared_ptr<McaRuntimeCperRecord> mcaPtr;
    std::shared_ptr<McaRuntimeCperRecord> dramPtr;
    std::shared_ptr<PcieRuntimeCperRecord> pciePtr;
    std::shared_ptr<CoreDebugDumpCperRecord> coreDebugDumpPtr;
    std::string node;
    std::vector<size_t> socIndex;
    size_t whFamilyId;
    std::vector<size_t> whModels;
    std::vector<uint8_t> blockId;
    std::mutex harvestMutex;
    bool fatalDescriptorsInitialized = false;

    /** @brief Shared D-Bus system bus connection.
     *
     *  @details Used by the common PMFW status signal subscription and by
     *  derived transports for their D-Bus interactions.
     */
    std::shared_ptr<sdbusplus::asio::connection> systemBus;

    /** @brief Current PMFW readiness state.
     *
     *  @details False until the PMFW ready notification is received. Used to
     *  gate PMFW-dependent handling and to reflect a single source of truth
     *  for the PMFW state shared by the APML and PLDM managers.
     */
    bool pmfwReady = false;

    /** @brief D-Bus match rule for the PMFW status notification signal. */
    std::unique_ptr<sdbusplus::bus::match_t> pmfwStatusMatch;

    /** @brief D-Bus match rule for the host state PropertiesChanged signal. */
    std::unique_ptr<sdbusplus::bus::match_t> hostStateMatch;

    /** @brief Subscribe to the PMFW status signal from amd-host-manager.
     *
     *  @details Registers a single D-Bus signal match for the per-node PMFW
     *  status object. The signal carries the readiness state as a boolean
     *  argument; on notification it updates pmfwReady and dispatches to the
     *  transport-specific handlers via applyPmfwStatus(). Shared by the APML
     *  and PLDM managers.
     */
    void subscribePmfwSignals();

    /** @brief Apply a PMFW readiness state change.
     *
     *  @details Common handling shared by the APML and PLDM managers: records
     *  the new pmfwReady state and dispatches to the transport-specific
     *  pmfwReadyHandler() or pmfwNotReadyHandler().
     *
     *  @param[in] ready - true if PMFW is ready; false otherwise.
     */
    void applyPmfwStatus(bool ready);

    /** @brief Reconcile PMFW state when the host is already powered on.
     *
     *  @details The PMFW status signal is transient. If the host is already
     *  powered on when this service starts (e.g. a RAS restart while the host
     *  is running), the ready notification may have been missed. This common
     *  helper applies the ready state now so platform initialization is not
     *  skipped. Shared by the APML and PLDM managers.
     */
    void reconcilePmfwState();

    /** @brief Handle the transition to the PMFW-ready state.
     *
     *  @details Derived classes override this to perform the transport-specific
     *  platform initialization that requires PMFW.
     */
    virtual void pmfwReadyHandler() = 0;

    /** @brief Handle the transition to the PMFW-not-ready state.
     *
     *  @details Derived classes override this to tear down the
     *  transport-specific platform initialization while keeping the alert
     *  handlers armed to service system management control errors.
     */
    virtual void pmfwNotReadyHandler() = 0;

    /** @brief Get the CPU socket information.
     *
     *  @details This API reads the CPU socket information such as processor
     *  count, board ID, microcode versions, and platform PPINs.
     *
     */
    void getCpuSocketInfo();

    /** @brief Load platform configuration from JSON.
     *
     *  @details This API reads the platform configuration JSON file
     *  and populates Model, FamilyID, and DebugLogID fields.
     */
    void loadPlatformConfig();

    /** @brief Monitors the current host power state.
     *
     *  @details This API monitors the current host power state using
     *  xyz.openbmc_project.State.Host D-bus Interface. When the host
     *  state changes, it calls onHostStateChanged() which derived
     *  classes override for transport-specific behavior.
     */
    void currentHostStateMonitor();

    /** @brief Query whether the host is currently powered on.
     *
     *  @details Reads the CurrentHostState property of the per-node
     *  xyz.openbmc_project.State.Host object. Used to avoid blocking SBRMI
     *  access while the host is off and to reconcile PMFW state on a RAS
     *  restart (the PMFW ready/off signals are transient).
     *
     *  @return true if the host is not in the Off state; false on Off or on
     *  query failure.
     */
    bool isHostPoweredOn();

    /** @brief Called when the host power state changes.
     *
     *  @details Derived classes override this to perform
     *  transport-specific actions on host state transitions.
     *
     *  @param[in] hostOff - true if the host transitioned to Off state.
     */
    virtual void onHostStateChanged(bool hostOff) = 0;

    /** @brief Handle FCH error.
     *
     *  @details Logs the FCH error to the journal and Redfish,
     *  increments the noncorrectable other error count, and saves.
     *
     *  @param[in] socNum - Socket number where the error occurred.
     */
    void handleFchError(uint8_t socNum);

    /** @brief Initialize the fatal CPER record structures.
     *
     *  @details Allocates section descriptors and error records if not
     *  already allocated, and populates the CPER header and error
     *  descriptor with fatal error information.
     *
     *  @param[in] sectionCount - Number of CPER sections.
     */
    void initFatalCperRecord(uint16_t sectionCount);

    /** @brief Process MCA bank signature IDs and PSP syndromes.
     *
     *  @details For each MCA bank, extracts signature ID fields
     *  (MCA_STATUS, MCA_IPID, MCA_SYND) and PSP syndrome values
     *  from the CrashDumpData, then populates the CPER record
     *  with signature ID and FRU string information.
     *
     *  @param[in] socNum - Socket number.
     *  @param[in] numBanks - Number of MCA banks to process.
     */
    void processMcaBankSignatures(uint8_t socNum, uint16_t numBanks);

    /** @brief Harvest break-event data from OOB registers.
     *
     *  @details Builds a fatal CPER break-event section by reading
     *  SBRMI OOB registers `0x80-0x87` for the specified socket.
     *
     *  @param[in] socNum - Socket number.
     */
    void harvestBreakEvent(uint8_t socNum);

    /** @brief Clean up the fatal CPER record.
     *
     *  @details Frees the SectionDescriptor and ErrorRecord arrays
     *  and resets the shared pointer to nullptr.
     */
    void cleanupFatalCperRecord();
};

} // namespace ras
} // namespace amd
