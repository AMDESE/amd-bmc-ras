#include "config_manager.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <stdexcept>

namespace amd
{
namespace ras
{
namespace config
{
namespace fs = std::filesystem;

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
        throw std::runtime_error("Attribute not found: " + attribute);
    }
    return value;
}

void Manager::initConfig()
{
    std::string configFile = CONFIG_FILE + node + ".json";

    if (!fs::exists(configFile))
    { // Check if the config file exists
        fs::path destDir = fs::path(configFile).parent_path();
        std::error_code ec;
        fs::create_directories(destDir, ec);
        if (ec)
        {
            if (ec == std::errc::file_exists)
            {
                ec.clear();
            }
            else
            {
                lg2::error("Failed to create directory: {DIR}, ec={EC}", "DIR",
                           destDir.string(), "EC", ec.message());
                throw std::runtime_error("Failed to create directory: " +
                                         destDir.string() + " (" +
                                         ec.message() + ")");
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
        AttributeType attributeType = AttributeType::Boolean;
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
                attributeType = AttributeType::Boolean;
            }
            else if (value.index() == 1)
            {
                attributeType = AttributeType::String;
            }
            else if (value.index() == 2)
            {
                attributeType = AttributeType::Integer;
            }
            else if (value.index() == 3)
            {
                attributeType = AttributeType::ArrayOfStrings;
            }
            else if (value.index() == 4)
            {
                attributeType = AttributeType::KeyValueMap;
            }
            else
            {
                lg2::debug(
                    "Unsupported attribute type. Adding default attribute type as boolean");
            }
        }

        configMap[key] =
            std::make_tuple(attributeType, description, value, maxBoundValue);
    }

    rasConfigTable(configMap);

    jsonRead.close();
}

Manager::Manager(std::string& node) : node(node)
{
    initConfig();
}

} // namespace config
} // namespace ras
} // namespace amd
