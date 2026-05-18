#pragma once

#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"

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

using ConfigIface = sdbusplus::server::object_t<
    sdbusplus::com::amd::RAS::server::Configuration,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;
/**
 * @brief Manager class which adds the RAS configuration
 * parameter values to the D-Bus interface.
 *
 * @details The class pulls the default values of ras_config.json file
 * into the D-Bus interface and overrides the getAttribute()
 * and setAttribute() of the RAS configuration interface.
 */
class Manager : public amd::ras::config::ConfigIface
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
     *  @param[in] node - host node number to determine single or multi host.
     */
    Manager(sdbusplus::asio::object_server& objectServer,
            std::shared_ptr<sdbusplus::asio::connection>& systemBus,
            std::string& node);

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

    /** @brief  Erase all entries
     */
    void deleteAll() override;

    /** @brief Load error counts from the persistent JSON file.
     *
     *  @details Reads error count arrays from the JSON file at
     *  errorCountFile. If the file does not exist or fails to parse,
     *  creates a new file with default (zero) values.
     */
    void loadErrorCounts();

    /** @brief Save current error counts to the persistent JSON file.
     *
     *  @details Writes all four error count arrays (correctable/
     *  noncorrectable CPU and other errors) to the JSON file at
     *  errorCountFile and updates the D-Bus properties.
     */
    void saveErrorCounts();

    /** @brief Update error count properties on the D-Bus interface.
     *
     *  @details Publishes the current in-memory error count arrays
     *  to the com.amd.RAS.ErrorCount D-Bus interface properties.
     */
    void updateErrorCountDbus();

    /** @brief Increment the correctable CPU error count for a given index.
     *  @param[in] socNum - socket number (0-3).
     *  @param[in] index - CPU error index to increment.
     */
    void incrementCorrectableCPUError(size_t socNum, size_t index)
    {
        correctableCPUErrors.at(socNum).at(index)++;
    }

    /** @brief Increment the noncorrectable CPU error count for a given index.
     *  @param[in] socNum - socket number (0-3).
     *  @param[in] index - CPU error index to increment.
     */
    void incrementNoncorrectableCPUError(size_t socNum, size_t index)
    {
        noncorrectableCPUErrors.at(socNum).at(index)++;
    }

    /** @brief Get the threshold count for a given error category.
     *
     *  @details Checks whether thresholding is enabled for the given
     *  category by reading the enable attribute from the config table.
     *  If enabled, returns the configured threshold count; otherwise
     *  returns 1.
     *
     *  @param[in] thresholdEnKey  - config attribute name for threshold enable
     *  @param[in] thresholdCntKey - config attribute name for threshold count
     *
     *  @return threshold count if enabled, 1 otherwise.
     */
    uint64_t getThresholdCount(const std::string& thresholdEnKey,
                               const std::string& thresholdCntKey);

    /** @brief Increment the correctable other error count.
     *  @param[in] socNum - socket number (0-3).
     *  @param[in] thresholdCount - threshold count to increment by.
     */
    void incrementCorrectableOtherError(size_t socNum, uint64_t thresholdCount)
    {
        correctableOtherErrors.at(socNum) += thresholdCount;
    }

    /** @brief Increment the noncorrectable other error count.
     *  @param[in] socNum - socket number (0-3).
     */
    void incrementNoncorrectableOtherError(size_t socNum)
    {
        noncorrectableOtherErrors.at(socNum)++;
    }

  private:
    static constexpr size_t maxErrorIndex = 256;
    static constexpr size_t maxSockets = 4;
    inline static std::array<std::array<uint64_t, maxErrorIndex>, maxSockets>
        correctableCPUErrors{};
    inline static std::array<std::array<uint64_t, maxErrorIndex>, maxSockets>
        noncorrectableCPUErrors{};
    inline static std::array<uint64_t, maxSockets> correctableOtherErrors{};
    inline static std::array<uint64_t, maxSockets> noncorrectableOtherErrors{};
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection>& systemBus;
    std::string node;

    std::string errorCountFile;
    static constexpr auto errorCountPath = "/com/amd/RAS/ErrorCount";
    static constexpr auto errorCountInterface = "com.amd.RAS.ErrorCount";

    std::shared_ptr<sdbusplus::asio::dbus_interface> errorCountIface;
};

} // namespace config
} // namespace ras
} // namespace amd
