#pragma once

#include "config_manager.hpp"
#include "oem_cper.hpp"

#include <map>

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
    Manager(amd::ras::config::Manager&, std::string&);
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
    std::vector<std::pair<std::string, int>> mpToIndexMap;
    std::string node;
    std::vector<size_t> socIndex;

    /** @brief Get the CPU socket information.
     *
     *  @details This API reads the CPU socket information such as processor
     *  count, board ID, microcode versions, and platform PPINs.
     *
     */
    void getCpuSocketInfo();
};

} // namespace ras
} // namespace amd
