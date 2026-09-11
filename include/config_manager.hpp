#pragma once

#include <fstream>
#include <map>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

namespace amd
{
namespace ras
{
namespace config
{

/** @brief Attribute types supported by the RAS configuration. */
enum class AttributeType
{
    Boolean,
    String,
    Integer,
    ArrayOfStrings,
    KeyValueMap,
};

/**
 * @brief Manager class which handles the RAS configuration parameters.
 *
 * @details The class loads the default values from ras_config.json and
 * provides getAttribute() for in-process access.
 */
class Manager
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
     *  @param[in] node - host node number to determine single or multi host.
     */
    explicit Manager(std::string& node);

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
    AttributeValue getAttribute(AttributeName attribute);

    /** @brief Initialize RAS configuration parameters
     *
     * @details Creates Config File in /var/lib/bmc-ras and the
     * config file values are uploaded to the D-Bus interface.
     *
     * @return On failure of accessing the config file, throw
     * std::runtime_error exception.
     */
    void initConfig();

    /** @brief Get the in-memory configuration table. */
    ConfigTable rasConfigTable() const
    {
        return configTable_;
    }

    /** @brief Set the in-memory configuration table. */
    void rasConfigTable(ConfigTable val)
    {
        configTable_ = std::move(val);
    }

  private:
    std::string node;
    ConfigTable configTable_;
};

} // namespace config
} // namespace ras
} // namespace amd
