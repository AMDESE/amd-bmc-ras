#pragma once

#include <memory>
#include <string>

namespace boost
{
namespace asio
{
class io_context;
}
} // namespace boost

namespace sdbusplus
{
namespace asio
{
class connection;
class object_server;
}
} // namespace sdbusplus

namespace amd
{
namespace ras
{
class Manager;

namespace config
{
class Manager;
}

/** @brief OOB transport used for RAS events and host access. */
enum class RasTransport
{
    Apml,
    Pldm,
};

/** @brief Resolve OOB transport from the **global** on-disk config at startup.
 *
 *  @details Reads `OOB_MODE_FILE` (Meson `oob_mode_file`, default
 *  `/var/lib/oob_mode.json`). Same file may be read by other BMC
 *  services. JSON key is **`oob_mode`** (fixed). The **value** is matched
 *  case-insensitively and must contain `apml` or `pldm` as a substring. Read
 *  **once** per process
 *  start; **restart**
 *  `com.amd.RAS@*` after changing the file. The `node` argument is reserved for
 *  future use and ignored. Missing or invalid file logs a warning and falls
 *  back to APML.
 */
[[nodiscard]] RasTransport resolveRasTransportForNode(const std::string& node);

/** @brief Factory: constructs the transport-specific RAS `Manager` (strategy).
 *
 *  @details Overall shape: **factory** (this function) selects the concrete
 *  backend; **strategy** (`amd::ras::apml::Manager`, `amd::ras::pldm::Manager`)
 *  implements event I/O and host access; **template method** lives on
 *  `amd::ras::Manager` and shared helpers—fixed CPER / processing steps with
 *  transport-specific hooks. Uses the same `amd::ras::config::Manager` and
 *  ras_config JSON for every transport. Transport is chosen via
 *  `resolveRasTransportForNode(node)` from the global OOB mode JSON.
 *
 *  @return Non-null for APML and PLDM; PLDM registers CPER objects and shared
 *  setup while PLDM-specific event intake may still be extended in
 *  `pldm::Manager`.
 */
[[nodiscard]] std::unique_ptr<Manager> createRasManager(
    config::Manager& configMgr,
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus,
    boost::asio::io_context& io, std::string& node, RasTransport transport);

} // namespace ras
} // namespace amd
