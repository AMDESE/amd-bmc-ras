#pragma once

#include <com/amd/RAS/Configuration/common.hpp>
#include <com/amd/RAS/Configuration/server.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

#include <fstream>

namespace amd
{
namespace ras
{
namespace config
{
static constexpr auto service = "com.amd.RAS";
static constexpr auto objectPath = "/com/amd/RAS";

using Configuration = sdbusplus::com::amd::RAS::server::Configuration;

/**
 * @brief Manager class which adds the RAS configuration
 * parameter values to the D-Bus interface.
 *
 * @details The class pulls the default values of ras_config.json file
 * into the D-Bus interface and overrides the getAttribute()
 * and setAttribute() of the RAS configuration interface.
 */
class Manager : public Configuration
{
  public:
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

    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    ~Manager() = default;

    /** @brief Constructs Manager object.
     *
     *  @param[in] objectServer  - object server
     *  @param[in] systemBus - bus connection
     */
    Manager(sdbusplus::asio::object_server& objectServer,
            std::shared_ptr<sdbusplus::asio::connection>& systemBus);

    /** @brief Updates the rasConfigTable with the user input.
     *
     *  @details Updates the Attribute value in the rasConfigTable and
     *   ras_config.json with user input and the ras_config.json.
     *
     *  @param[in] attribute - attribute name
     *  @param[in] value - new value for the attribute
     *
     *  @return On failure of accessing the config file, log InvalidArgument
     *  D-Bus error.
     */
    void setAttribute(AttributeName attribute, AttributeValue value) override;

    /** @brief Get the values of the Ras Config attribute
     *
     *  @details The API reads the value from the RasConfigTable
     *   and returns the value of the attribute.
     *
     *  @param[in] attribute - attribute name
     *
     *  @return returns the current value of the attribute.
     *  On failure , throw ResourceNotFound D-Bus error.
     */
    AttributeValue getAttribute(AttributeName attribute) override;

    /** @brief Update RAS configuration parameters to D-Bus interface
     *
     * @details Creates Config File in /var/lib/amd-bmc-ras and the
     * config file values are uploaded to the D-Bus interface.
     *
     * @return On failure of accessing the config file, throw
     * std::runtime_error exception.
     */
    void updateConfigToDbus();

  private:
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
};

} // namespace config
} // namespace ras
} // namespace amd
