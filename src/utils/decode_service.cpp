#include "utils/decode_service.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <xyz/openbmc_project/Logging/CPER/Types/common.hpp>

#include <cerrno>
#include <cstring>
#include <exception>
#include <filesystem>
#include <system_error>

namespace amd
{
namespace ras
{
namespace util
{
namespace decode_service
{

constexpr auto cperProcessorService =
    "xyz.openbmc_project.Logging.CPER.Processor";
constexpr auto cperProcessorPath = "/xyz/openbmc_project/logging/cper";
constexpr auto cperProcessorInterface =
    "xyz.openbmc_project.Logging.CPER.Processor";

using ContentType =
    sdbusplus::common::xyz::openbmc_project::logging::cper::Types::ContentType;

void submitCper(const std::shared_ptr<sdbusplus::asio::connection>& bus,
                const std::string& cperFilePath, uint8_t socNum)
{
    // The CPER filename lookup returns an empty name when the file was not
    // created, which would leave only the RAS directory in the path.
    std::error_code fsEc;
    if (!std::filesystem::is_regular_file(cperFilePath, fsEc))
    {
        lg2::error("CPER file {FILE} not found, skipping decode", "FILE",
                   cperFilePath);
        return;
    }

    int fd = open(cperFilePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        lg2::error("Failed to open CPER file {FILE} for decode: {ERR}", "FILE",
                   cperFilePath, "ERR", std::strerror(errno));
        return;
    }

    const std::string inventoryPath =
        std::string(CPER_INVENTORY_PREFIX) + std::to_string(socNum);

    try
    {
        // sd-bus duplicates the descriptor while appending it to the
        // message, so our copy can be closed once the call is queued.
        bus->async_method_call(
            [cperFilePath](boost::system::error_code ec) {
                if (ec)
                {
                    lg2::error("CPER processor failed for {FILE}: {ERR}",
                               "FILE", cperFilePath, "ERR", ec.message());
                }
            },
            cperProcessorService, cperProcessorPath, cperProcessorInterface,
            "Process", sdbusplus::message::object_path(inventoryPath),
            ContentType::CPER, sdbusplus::message::unix_fd(fd));

        lg2::info("Submitted CPER file {FILE} to CPER processor for {INV}",
                  "FILE", cperFilePath, "INV", inventoryPath);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to submit CPER file {FILE} to CPER processor: {ERR}",
                   "FILE", cperFilePath, "ERR", e.what());
    }

    close(fd);
}

} // namespace decode_service
} // namespace util
} // namespace ras
} // namespace amd
