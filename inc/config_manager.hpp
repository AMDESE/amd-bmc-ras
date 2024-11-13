#pragma once

#include <com/amd/RAS/Configuration/common.hpp>
#include <com/amd/RAS/Configuration/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>
static constexpr auto objectPath = "/com/amd/RAS";

// Type alias for attribute type from the D-Bus configuration.
using AttributeType =
    sdbusplus::common::com::amd::ras::Configuration::AttributeType;

// Type alias for attribute type from the D-Bus configuration.
using Base = sdbusplus::com::amd::RAS::server::Configuration;

// Type alias for attribute name and value.
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

// Type alias for the configuration table structure.
struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        event = sd_event_unref(event);
    }
};

// Unique pointer type for sd_event with custom deleter.
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
    RasConfiguration(sdbusplus::asio::object_server& objectServer,
                     std::shared_ptr<sdbusplus::asio::connection>& systemBus);

    void setAttribute(AttributeName attribute, AttributeValue value) override;

    AttributeValue getAttribute(AttributeName attribute) override;

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
};
