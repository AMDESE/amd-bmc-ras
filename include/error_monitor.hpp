#pragma once

#include "config_manager.hpp"
#include "oem_cper.hpp"

#include <boost/asio/io_context.hpp>

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

class Manager
{
  public:
    Manager() = delete;
    ~Manager() = default;
    Manager(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    Manager(amd::ras::config::Manager&);

    /** @brief Perform initilization for the error monitoring.
     *
     *  @details It initializes the APML RAS Manager by repeatedly attempting to
     *  get the BMC RAS OOB configuration and setting up platform and watchdog
     *  state monitoring for bios post complete. It also reads CPU IDs,
     *  configures PCIE settings, and clears the SbrmiAlertMask register for
     *  crashdump readiness.
     */
    virtual void init() = 0;

    /** @brief Request GPIO events for APML alert handling.
     *
     *  @details This function sets up GPIO event handling for APML alerts. It
     * first requests GPIO events for P0 alert handling by binding the P0 alert
     * event handler to the specified GPIO line and event. If the system has two
     * CPUs, it also requests GPIO events for P1 alert handling by binding the
     * P1 alert event handler to the respective GPIO line and event.
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

  private:
    /** @brief Get the CPU socket information.
     *
     *  @details This API reads the CPU socket information such as processor
     *  count, board ID, microcode versions, and platform PPINs.
     *
     */
    void getSocketInfo();
};

} // namespace ras
} // namespace amd
