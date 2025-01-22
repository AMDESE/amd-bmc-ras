#pragma once

#include "crashdump_manager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

namespace amd
{
namespace ras
{
namespace dbus
{
namespace util
{

/** @brief Gets value from D-Bus property.
 *
 *  @details Reads D-Bus property value within the given interface.
 *  Returns the property value as the specified type.
 *
 *  @param[in] bus - D-Bus connection.
 *  @param[in] service - D-Bus service name.
 *  @param[in] path - Object path of the property.
 *  @param[in] interface - Interface of the property.
 *  @param[in] propertyName - Name of the property to retrieve.
 *
 *  @return Returns the value of the property as type ReturnType.
 *  @return Throws sdbusplus::exception::SdBusError on failure.
 */

template <typename ReturnType>
ReturnType getProperty(sdbusplus::bus::bus& bus, const char* service,
                       const char* path, const char* interface,
                       const char* propertyName);

/** @brief Gets value from D-Bus property.
 *
 *  @details Reads D-Bus property value within the given interface.
 *  Returns the property value as the specified type.
 *
 *  @param[in] bus - D-Bus connection.
 *  @param[in] service - D-Bus service name.
 *  @param[in] path - Object path of the property.
 *  @param[in] interface - Interface of the property.
 *  @param[in] propertyName - Name of the property to retrieve.
 *
 *  @return Returns the value of the property as type T.
 *  @return Throws sdbusplus::exception::SdBusError on failure.
 */

bool checkObjPath(std::string dbusPath);

} // namespace util
} // namespace dbus
} // namespace ras
} // namespace amd
