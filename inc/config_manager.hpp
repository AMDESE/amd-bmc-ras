#pragma once

#include <com/amd/RAS/Configuration/common.hpp>
#include <com/amd/RAS/Configuration/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

#include <filesystem>
#include <string>
static constexpr auto objectPath = "/com/amd/RAS";

using AttributeType =
    sdbusplus::common::com::amd::ras::Configuration::AttributeType;
using Base = sdbusplus::com::amd::RAS::server::Configuration;

using AttributeName = std::string;
using AttributeValue =
    std::variant<bool, std::string, int64_t, std::vector<std::string>,
                 std::map<std::string, std::string>>;
using ConfigTable =
    std::map<std::string,
             std::tuple<AttributeType, std::string,
                        std::variant<bool, std::string, int64_t,
                                     std::vector<std::string>,
                                     std::map<std::string, std::string>>,
                        int64_t>>;

struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        event = sd_event_unref(event);
    }
};
using EventPtr = std::unique_ptr<sd_event, EventDeleter>;

/**
 * @brief Definition of the RasConfiguration class.
 *
 * @tparam AttributeName The type for attribute names (usually std::string).
 * @tparam AttributeValue The variant type for attribute values.
 * @tparam ConfigTable The map type for storing attribute information.
 */

class RasConfiguration : public Base
{
  public:
    /**
     * Constructor for Configuration.
     *
     * @param objectServer Reference to the object server.
     * @param systemBus Reference to the system D-Bus connection.
     */
    RasConfiguration(sdbusplus::asio::object_server& objectServer,
                     std::shared_ptr<sdbusplus::asio::connection>& systemBus);

    /**
     * Set the value of an attribute.
     *
     * @param attribute The name of the attribute.
     * @param value The value to set.
     */
    void setAttribute(AttributeName attribute, AttributeValue value) override;

    /**
     * Get the value of an attribute.
     *
     * @param attribute The name of the attribute.
     * @return The value of the attribute.
     */
    AttributeValue getAttribute(AttributeName attribute) override;

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
};
