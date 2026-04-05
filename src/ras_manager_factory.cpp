#include "ras_manager_factory.hpp"

#include "apml_manager.hpp"
#include "base_manager.hpp"
#include "pldm_manager.hpp"

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <cctype>
#include <fstream>
#include <string>
#include <string_view>

namespace amd
{
namespace ras
{

namespace
{
std::string toLowerCopy(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
    {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

constexpr const char* kOobModeJsonKey = "oob_mode";
} // namespace

RasTransport resolveRasTransportForNode(const std::string& node)
{
    (void)node;
    const std::string path(OOB_MODE_FILE);
    std::ifstream f(path);
    if (!f.is_open())
    {
        lg2::warning(
            "OOB mode file {PATH} not readable; falling back to apml",
            "PATH", path);
        return RasTransport::Apml;
    }

    try
    {
        nlohmann::json j;
        f >> j;

        if (!j.contains(kOobModeJsonKey) || !j[kOobModeJsonKey].is_string())
        {
            lg2::warning(
                "Missing or non-string oob_mode in {PATH}; falling back to apml",
                "PATH", path);
            return RasTransport::Apml;
        }

        const std::string mode = j[kOobModeJsonKey].get<std::string>();
        const std::string lower = toLowerCopy(mode);

        if (lower.find("apml") != std::string::npos)
        {
            return RasTransport::Apml;
        }
        if (lower.find("pldm") != std::string::npos)
        {
            return RasTransport::Pldm;
        }

        lg2::warning(
            "Unrecognized oob_mode value={MODE} in {PATH}; falling back to apml",
            "MODE", mode, "PATH", path);
        return RasTransport::Apml;
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to parse {PATH}: {ERR}; falling back to apml",
            "PATH", path, "ERR", e.what());
        return RasTransport::Apml;
    }
}

std::unique_ptr<Manager> createRasManager(
    config::Manager& configMgr,
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus,
    boost::asio::io_context& io, std::string& node, RasTransport transport)
{
    switch (transport)
    {
        case RasTransport::Apml:
            return std::make_unique<apml::Manager>(configMgr, objectServer,
                                                   systemBus, io, node);
        case RasTransport::Pldm:
            return std::make_unique<pldm::Manager>(configMgr, objectServer,
                                                     systemBus, io, node);
    }
    return nullptr;
}

} // namespace ras
} // namespace amd
