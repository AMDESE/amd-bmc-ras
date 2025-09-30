#include "config_manager.hpp"

#include "utils/cper.hpp"
#include "xyz/openbmc_project/Common/File/error.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

namespace amd
{
namespace ras
{
namespace config
{
namespace fs = std::filesystem;

void Manager::setAttribute(AttributeName attribute, AttributeValue value)
{
    nlohmann::json data;

    auto configMap = rasConfigTable();

    std::string configFile = CONFIG_FILE + node + ".json";

    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    jsonFile >> data;
    jsonFile.close();

    bool attributeFound = false;
    for (auto& configItem : data["Configuration"])
    {
        if (auto it = configItem.find(attribute); it != configItem.end())
        {
            bool isValidValue = false;

            if (it.value().contains("MaxBoundLimit"))
            {
                auto maxBoundLimit = it.value()["MaxBoundLimit"];

                std::visit(
                    [&](auto&& arg) {
                        if constexpr (std::is_same_v<
                                          std::decay_t<decltype(arg)>, int64_t>)
                        {
                            if (maxBoundLimit.is_number_integer())
                            {
                                isValidValue =
                                    (arg > maxBoundLimit.get<int64_t>());

                                if (isValidValue)
                                {
                                    lg2::error(
                                        "Attribute {ATTRIBUTE} : Value {VALUE} is greater than max bound limit",
                                        "ATTRIBUTE", attribute, "VALUE", arg);
                                    throw sdbusplus::xyz::openbmc_project::
                                        Common::Error::InvalidArgument();
                                }
                            }
                        }
                    },
                    value);
            }

            if (it.value().contains("ValidOptions"))
            {
                auto validOptions = it.value()["ValidOptions"];

                for (const auto& validOption : validOptions)
                {
                    if (validOption.is_string())
                    {
                        if (std::holds_alternative<std::string>(value) &&
                            std::get<std::string>(value) ==
                                validOption.get<std::string>())
                        {
                            isValidValue = true;
                            break;
                        }
                    }
                }
                if (isValidValue == false)
                {
                    lg2::error(
                        "{VALUE} is not a valid option for the attribute {ATTRIBUTE}",
                        "ATTRIBUTE", attribute, "VALUE",
                        std::get<std::string>(value));
                    throw sdbusplus::xyz::openbmc_project::Common::Error::
                        InvalidArgument();
                }
            }

            std::visit([&](auto&& arg) { it.value()["Value"] = arg; }, value);
            attributeFound = true;
            break;
        }
    }
    if (attributeFound)
    {
        for (auto& [key, tuple] : configMap)
        {
            if (key == attribute)
            {
                std::get<2>(tuple) = value;
                break;
            }
        }

        std::ofstream jsonFileOut(configFile);

        if (!jsonFileOut.is_open())
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        jsonFileOut << data.dump(4);
        jsonFileOut.close();
        rasConfigTable(configMap);

        lg2::debug("Attribute {{ATTRIBUTE} updated successfully", "ATTRIBUTE",
                   attribute);
    }
    else
    {
        lg2::error("Attribute {ATTRIBUTE} not found", "ATTRIBUTE", attribute);
        throw sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument();
    }
}

Manager::AttributeValue Manager::getAttribute(AttributeName attribute)
{
    const auto configMap = rasConfigTable();
    AttributeValue value;
    bool found = false;

    for (const auto& [key, tuple] : configMap)
    {
        if (key == attribute)
        {
            value = std::get<2>(tuple);
            found = true;
            break;
        }
    }

    if (!found)
    {
        lg2::error(
            "The given attribute {ATTRIBUTE} is not found in the config table",
            "ATTRIBUTE", attribute);
        throw sdbusplus::xyz::openbmc_project::Common::Error::
            ResourceNotFound();
    }
    return value;
}

void Manager::updateConfigToDbus()
{
    std::string configFile = CONFIG_FILE + node + ".json";

    if (!fs::exists(configFile))
    { // Check if the config file exists
        fs::path destDir = fs::path(configFile).parent_path();
        if (!fs::exists(destDir))
        {
            if (!fs::create_directories(destDir))
            {
                lg2::error("Failed to create directory: {ERROR}", "ERROR",
                           strerror(errno));
                throw std::runtime_error(
                    "Failed to create directory: " + destDir.string());
            }
        }

        // Try to copy the config file, throw exception if it fails
        try
        {
            fs::copy_file(SRC_CONFIG_FILE, configFile,
                          fs::copy_options::overwrite_existing);
        }
        catch (const fs::filesystem_error& e)
        {
            lg2::error("Failed to copy config file : {ERROR}", "ERROR",
                       strerror(errno));
            throw std::runtime_error("Failed to copy config file");
        }
    }

    std::ifstream jsonRead(configFile);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    if (!jsonRead.is_open())
    {
        lg2::error("Could not read config file Error : {ERROR}", "ERROR",
                   strerror(errno));
        throw std::runtime_error("Error: Could not read config file");
    }

    ConfigTable configMap;

    lg2::info("PARSE CONFIGURATION");
    for (const auto& item : data["Configuration"])
    {
        AttributeType attributeType;
        std::string key;
        std::string description;
        std::variant<bool, std::string, int64_t, std::vector<std::string>,
                     std::map<std::string, std::string>>
            value;
        int64_t maxBoundValue = 0;

        if (item.is_object() && item.size() == 1)
        {
            key = item.begin().key();

            const auto& obj = item[key];

            if (obj.contains("Description") && obj["Description"].is_string())
            {
                description = obj["Description"].get<std::string>();
            }
            else
            {
                description = "Default";
            }

            // Determine the type of the value and construct the std::variant
            // accordingly
            if (obj["Value"].is_boolean())
            {
                value = obj["Value"].get<bool>();
            }
            else if (obj["Value"].is_string())
            {
                value = obj["Value"].get<std::string>();
            }
            else if (obj["Value"].is_number_integer())
            {
                value = obj["Value"].get<int64_t>();
            }
            else if (obj["Value"].is_array())
            {
                value = obj["Value"].get<std::vector<std::string>>();
            }
            else if (obj["Value"].is_object())
            {
                value = obj["Value"].get<std::map<std::string, std::string>>();
            }
            else
            {
                value = {};
            }

            if (obj.contains("MaxBoundLimit"))
            {
                maxBoundValue = obj["MaxBoundLimit"];
            }

            if (value.index() == 0)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::Boolean;
            }
            else if (value.index() == 1)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::String;
            }
            else if (value.index() == 2)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::Integer;
            }
            else if (value.index() == 3)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::ArrayOfStrings;
            }
            else if (value.index() == 4)
            {
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::KeyValueMap;
            }
            else
            {
                lg2::debug(
                    "Unsupported attribute type. Adding default attribute type as boolean");
                attributeType = sdbusplus::common::com::amd::ras::
                    Configuration::AttributeType::Boolean;
            }
        }

        configMap[key] =
            std::make_tuple(attributeType, description, value, maxBoundValue);
    }

    rasConfigTable(configMap);

    jsonRead.close();
}

void Manager::deleteAll()
{
    for (const auto& entry : std::filesystem::directory_iterator(RAS_DIR))
    {
        std::string filename = entry.path().filename().string();

        if (node == "1" || node == "2")
        {
            if (filename.starts_with("node" + node) &&
                filename.starts_with("node" + node))
            {
                lg2::info("{FILE} deleted", "FILE", filename);
                fs::remove(entry.path());
            }
        }
        else
        {
            if (filename.ends_with(".cper"))
            {
                lg2::info("{FILE} deleted", "FILE", filename);
                fs::remove(entry.path());
            }
        }
    }
    amd::ras::util::cper::deleteCrashdumpInterface();
}

Manager::Manager(sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 std::string& node) :
    amd::ras::config::ConfigIface(*systemBus, objectPath),
    objServer(objectServer), systemBus(systemBus), node(node)
{
    updateConfigToDbus();
}

} // namespace config
} // namespace ras
} // namespace amd
