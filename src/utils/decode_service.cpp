#include "utils/decode_service.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Logging/CPER/Types/common.hpp>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <unistd.h>

namespace amd
{
namespace ras
{
namespace util
{
namespace decode_service
{

constexpr auto cperObjPath = "/xyz/openbmc_project/logging/cper";
constexpr auto cperInterface = "xyz.openbmc_project.Logging.CPER.Processor";
constexpr auto cperServiceName = "xyz.openbmc_project.Logging.CPER";

using ContentType =
    sdbusplus::common::xyz::openbmc_project::logging::cper::Types::ContentType;

std::string getCpuInventoryPath(uint8_t socNum)
{
    return std::format(
        "/xyz/openbmc_project/inventory/system/chassis/motherboard/cpu{}",
        socNum);
}

int submitCperForProcessing(sdbusplus::bus_t& bus,
                            const std::string& cperFilePath, uint8_t socNum)
{
    auto cperFd = open(cperFilePath.c_str(), O_RDONLY);
    if (cperFd < 0)
    {
        lg2::error("Failed to open CPER file {FILE}, errno={ERR}", "FILE",
                   cperFilePath, "ERR", std::strerror(errno));
        return -errno;
    }

    auto inventoryPath = getCpuInventoryPath(socNum);

    try
    {
        auto method = bus.new_method_call(cperServiceName, cperObjPath,
                                          cperInterface, "Process");

        method.append(sdbusplus::object_path(inventoryPath),
                      ContentType::CPER, sdbusplus::message::unix_fd(cperFd));

        bus.call_noreply(method);

        lg2::info("CPER submitted to decode-service: socket={SOC}, path={PATH}",
                  "SOC", socNum, "PATH", cperFilePath);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Decode-service D-Bus call failed: {ERROR}", "ERROR",
                   e.what());
        close(cperFd);
        return -ECOMM;
    }
    catch (const std::exception& e)
    {
        lg2::error("Unexpected error calling decode-service: {ERROR}", "ERROR",
                   e.what());
        close(cperFd);
        return -EIO;
    }

    close(cperFd);
    return 0;
}

bool isDecodeServiceAvailable(sdbusplus::bus_t& bus)
{
    try
    {
        auto method = bus.new_method_call("org.freedesktop.DBus",
                                          "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "NameHasOwner");
        method.append(cperServiceName);

        auto reply = bus.call(method);
        bool hasOwner = false;
        reply.read(hasOwner);
        return hasOwner;
    }
    catch (...)
    {
        return false;
    }
}

} // namespace decode_service
} // namespace util
} // namespace ras
} // namespace amd
