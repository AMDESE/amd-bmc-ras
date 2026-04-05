#pragma once

#include "config_manager.hpp"
#include "oem_cper.hpp"

constexpr size_t socket1 = 1;
constexpr size_t socket2 = 2;

namespace amd
{
namespace ras
{
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
 *  @details Base for the **strategy** in a factory + strategy + template-method
 *  layout: derived types (APML, PLDM, …) supply transport-specific event
 *  handling, host I/O, and **platform / runtime OOB hooks** (processor identity,
 *  host power monitoring, alert mask, `runTimeErrorPolling`, MCA/PCIe OOB and
 *  thresholds—each virtual with APML vs PLDM implementations); this type holds
 *  shared state and flows toward
 *  CPER and related processing. `createRasManager` is the **factory** that picks
 *  the concrete strategy (`resolveRasTransportForNode` / `createRasManager`).
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
    Manager(amd::ras::config::Manager&, std::string&);
    virtual ~Manager() = default;

    /** @brief Called after the I/O loop exits (e.g. service shutdown).
     *
     *  @details Derived classes release transport-specific resources. The default
     *  implementation is a no-op.
     */
    virtual void finalize() {}

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
     the derived class.
     *
     */
    virtual void configure() = 0;

  protected:
    size_t errCount;
    size_t cpuCount;
    uint32_t boardId;
    uint32_t familyId;
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
    /** @brief Processor socket indices (SoC / P0..Pn) for this RAS instance.
     *
     *  @details libapml and related OOB APIs use this as `socNum` (socket
     *  number). For a **multi-host** image (`node` 1, 2, …), each instance
     *  usually manages one socket and that index **is** the logical **host**
     *  number in that deployment. For `node == "0"`, multiple entries mean
     *  multiple sockets under one aggregated service.
     */
    std::vector<size_t> socIndex;

    /** @brief Get the CPU socket information.
     *
     *  @details This API reads the CPU socket information such as processor
     *  count, board ID, microcode versions, and platform PPINs.
     *
     */
    void getCpuSocketInfo();

    /** @brief Transport-specific platform OOB bring-up after shared init.
     *
     *  @details APML: processor family/model check, alert mask, runtime
     *  polling, host/watchdog monitors. PLDM: MCTP/PLDM platform setup when
     *  implemented. Default is a no-op.
     */
    virtual void platformInitialize() {}

    /** @brief Transport-specific MCA/DRAM runtime error threshold programming.
     *
     *  @details APML implements this via mailbox (`setMcaErrThreshold` and
     *  related). PLDM should use the appropriate PLDM path. Return value is
     *  strategy-defined; APML uses the same encoding as `oob_status_t` for
     *  compatibility with existing polling orchestration. Default returns 0.
     *
     *  @return 0 when thresholds were applied or are not applicable; non-zero
     *  for strategy-specific errors (e.g. APML `OOB_MAILBOX_CMD_UNKNOWN`).
     */
    virtual int applyRuntimeMcaErrorThresholds()
    {
        return 0;
    }

    /** @brief One attempt to read processor family/model over the transport OOB.
     *
     *  @return 0 on success; non-zero transport-specific error (APML uses
     *  `oob_status_t` as `int`). On success, implementers should set `familyId`
     *  on the manager when appropriate.
     */
    virtual int readOobProcessorFamilyModel(uint32_t& familyOut,
                                            uint32_t& modelOut)
    {
        familyOut = 0;
        modelOut = 0;
        return -1;
    }

    /** @brief Subscribe to host power / lifecycle for transport follow-up (APML: D-Bus). */
    virtual void startHostPowerTransitionMonitoring() {}

    /** @brief Clear platform RAS alert indication for all managed sockets. */
    virtual void clearPlatformRasAlertMask() {}

    /** @brief Start runtime error polling and related OOB setup for this transport. */
    virtual void runTimeErrorPolling() {}

    /** @brief Apply MCA/DRAM OOB runtime configuration (APML: `setMcaOobConfig`). */
    virtual int applyRuntimeMcaDramOobConfig()
    {
        return 0;
    }

    /** @brief Apply PCIe OOB runtime configuration (APML: `setPcieOobConfig`). */
    virtual int applyRuntimePcieOobConfig()
    {
        return 0;
    }

    /** @brief Apply PCIe runtime error thresholds (APML: `setPcieErrThreshold`). */
    virtual int applyRuntimePcieErrThreshold()
    {
        return 0;
    }
};

} // namespace ras
} // namespace amd
