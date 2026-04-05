#include "pldm_manager.hpp"

#include "pldm_event_monitor.hpp"
#include "utils/cper.hpp"

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <fstream>
#include <string>

namespace amd
{
namespace ras
{
namespace pldm
{

Manager::Manager(amd::ras::config::Manager& manager,
                 sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io, std::string& node) :
    amd::ras::Manager(manager, node), io_(io), objectServer(objectServer),
    systemBus(systemBus)
{}

Manager::~Manager() = default;

void Manager::init()
{
    lg2::info("PLDM RAS manager init for node {NODE}", "NODE", node);

    getCpuSocketInfo();

    if (!pldmEventMonitor_)
    {
        pldmEventMonitor_ = std::make_unique<PldmEventMonitor>(
            io_, static_cast<sdbusplus::bus::bus&>(*systemBus),
            [this](std::vector<uint8_t> buf) {
                onPldmEventBuffer(std::move(buf));
            });
    }

    platformInitialize();
}

void Manager::platformInitialize()
{
    lg2::info(
        "PLDM platformInitialize: transport-specific OOB bring-up (replace with MCTP/PLDM platform setup)");
}

int Manager::readOobProcessorFamilyModel(uint32_t& familyOut, uint32_t& modelOut)
{
    try
    {
        std::ifstream file("/var/lib/platform-config/platform.json");
        if (!file.is_open())
        {
            file.open(PLATFORM_DEFAULT_FILE);
        }
        if (!file.is_open())
        {
            lg2::warning(
                "PLDM readOobProcessorFamilyModel: platform.json not available");
            return -1;
        }

        const nlohmann::json j = nlohmann::json::parse(file);
        if (!j.contains("FamilyID") || !j.contains("Model"))
        {
            return -1;
        }

        familyId = static_cast<uint32_t>(
            std::stoul(j["FamilyID"].get<std::string>(), nullptr, 16));
        familyOut = familyId;
        modelOut = static_cast<uint32_t>(
            std::stoul(j["Model"].get<std::string>(), nullptr, 16));
        return 0;
    }
    catch (const std::exception& e)
    {
        lg2::warning("PLDM readOobProcessorFamilyModel: {ERR}", "ERR", e.what());
        return -1;
    }
}

void Manager::startHostPowerTransitionMonitoring()
{
    lg2::info(
        "PLDM startHostPowerTransitionMonitoring: hook for host lifecycle via PLDM when defined");
}

void Manager::clearPlatformRasAlertMask()
{
    lg2::info(
        "PLDM clearPlatformRasAlertMask: hook for alert clear via PLDM when defined");
}

void Manager::runTimeErrorPolling()
{
    lg2::info(
        "PLDM runTimeErrorPolling: hook for runtime polling via PLDM when defined");
}

int Manager::applyRuntimeMcaDramOobConfig()
{
    lg2::info(
        "PLDM applyRuntimeMcaDramOobConfig: hook for MCA/DRAM OOB via PLDM when defined");
    return 0;
}

int Manager::applyRuntimePcieOobConfig()
{
    lg2::info(
        "PLDM applyRuntimePcieOobConfig: hook for PCIe OOB via PLDM when defined");
    return 0;
}

int Manager::applyRuntimePcieErrThreshold()
{
    lg2::info(
        "PLDM applyRuntimePcieErrThreshold: hook for PCIe thresholds via PLDM when defined");
    return 0;
}

int Manager::applyRuntimeMcaErrorThresholds()
{
    lg2::info(
        "PLDM applyRuntimeMcaErrorThresholds: program MCA/DRAM thresholds via PLDM when defined");
    return 0;
}

void Manager::configure()
{
    lg2::info("PLDM RAS manager configure for node {NODE}", "NODE", node);

    amd::ras::util::cper::createRecord(objectServer, systemBus, node);

    lg2::info("PLDM transport active: CPER D-Bus objects registered");
}

void Manager::finalize()
{
    pldmEventMonitor_.reset();
}

void Manager::onPldmEventBuffer(std::vector<uint8_t>&& payload)
{
    lg2::info(
        "PLDM RAS: event buffer ready, {BYTES} bytes (harvest / CPER TBD)",
        "BYTES", payload.size());
}

} // namespace pldm
} // namespace ras
} // namespace amd
