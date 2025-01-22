#include "dbus_util.hpp"

namespace amd
{
namespace ras
{
namespace dbus
{
namespace util
{

constexpr std::string_view inventoryService =
    "xyz.openbmc_project.Inventory.Manager";
constexpr std::string_view inventoryInterface =
    "xyz.openbmc_project.Inventory.Item.Cpu";
constexpr std::string_view mapperBusName = "xyz.openbmc_project.ObjectMapper";
constexpr std::string_view mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr std::string_view mapperIntf = "xyz.openbmc_project.ObjectMapper";

template std::string getProperty(sdbusplus::bus::bus& bus, const char* service,
                                 const char* path, const char* interface,
                                 const char* propertyName);

template <typename ReturnType>
ReturnType getProperty(sdbusplus::bus::bus& bus, const char* service,
                       const char* path, const char* interface,
                       const char* propertyName)
{
    auto method = bus.new_method_call(service, path,
                                      "org.freedesktop.DBus.Properties", "Get");
    method.append(interface, propertyName);
    std::variant<ReturnType> value{};

    try
    {
        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        lg2::info("GetProperty call failed");
    }
    return std::get<ReturnType>(value);
}

bool checkObjPath(std::string dbusPath)
{
    bool filePathExist = false;

    boost::asio::io_context Dbus;
    auto dbusconn = std::make_shared<sdbusplus::asio::connection>(Dbus);
    std::vector<std::string> crashDumpPaths;

    auto mesg =
        dbusconn->new_method_call(mapperBusName.data(), mapperPath.data(),
                                  mapperIntf.data(), "GetSubTreePaths");

    static const std::vector<std::string> interfaces = {"com.amd.crashdump"};
    mesg.append("/", 0, interfaces);

    try
    {
        auto mapperReply = dbusconn->call(mesg);
        mapperReply.read(crashDumpPaths);
    }
    catch (sdbusplus::exception_t& e)
    {
        lg2::info("Failed to get D-BUS info {WHAT}", "WHAT", e.what());
    }

    for (const auto& objPath : crashDumpPaths)
    {
        if (dbusPath == objPath)
            filePathExist = true;
    }

    return filePathExist;
}

} // namespace util
} // namespace dbus
} // namespace ras
} // namespace amd
