/*
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http:www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "config_manager.hpp"

#include "xyz/openbmc_project/Common/error.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>

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

    std::ifstream jsonFile(CONFIG_FILE);
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

            if (it.value().contains("ValidOptions"))
            {
                auto ValidOptions = it.value()["ValidOptions"];

                for (const auto& ValidOption : ValidOptions)
                {
                    if (ValidOption.is_string())
                    {
                        if (std::holds_alternative<std::string>(value) &&
                            std::get<std::string>(value) ==
                                ValidOption.get<std::string>())
                        {
                            isValidValue = true;
                            break;
                        }
                    }
                }
            }
            else
            {
                isValidValue = true;
            }

            if (isValidValue == true)
            {
                std::visit([&](auto&& arg) { it.value()["Value"] = arg; },
                           value);
                attributeFound = true;
                break;
            }
            else
            {
                lg2::error("Valid option not provided");
                throw sdbusplus::xyz::openbmc_project::Common::Error::
                    InvalidArgument();
            }
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

        std::ofstream jsonFileOut(CONFIG_FILE);

        if (!jsonFileOut.is_open())
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        jsonFileOut << data.dump(4);
        jsonFileOut.close();
        rasConfigTable(configMap);

        lg2::debug("Attribute updated successfully");
    }
    else
    {
        lg2::error("Attribute not found");
        throw sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument();
    }
}

Manager::AttributeValue Manager::getAttribute(AttributeName attribute)
{
    auto configMap = rasConfigTable();
    AttributeValue value;
    bool found = false;

    for (auto& [key, tuple] : configMap)
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
        throw sdbusplus::xyz::openbmc_project::Common::Error::
            ResourceNotFound();
    }
    return value;
}

void Manager::updateConfigToDbus()
{
    if (!fs::exists(CONFIG_FILE))
    { // Check if the config file exists
        fs::path destDir = fs::path(CONFIG_FILE).parent_path();
        if (!fs::exists(destDir))
        {
            if (!fs::create_directories(destDir))
            {
                throw std::runtime_error(
                    "Failed to create directory: " + destDir.string());
            }
        }

        // Try to copy the config file, throw exception if it fails
        try
        {
            fs::copy_file(SRC_CONFIG_FILE, CONFIG_FILE,
                          fs::copy_options::overwrite_existing);
        }
        catch (const fs::filesystem_error& e)
        {
            throw std::runtime_error("Failed to copy config file");
        }
    }

    std::ifstream jsonRead(CONFIG_FILE);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    if (!jsonRead.is_open())
    {
        lg2::error("Error: Could not read config file");
        throw std::runtime_error("Error: Could not read config file");
    }

    ConfigTable configMap;

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
            description = obj["Description"];
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
        }

        configMap[key] =
            std::make_tuple(attributeType, description, value, maxBoundValue);
    }

    rasConfigTable(configMap);

    jsonRead.close();
}

Manager::Manager(sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus) :
    sdbusplus::com::amd::RAS::server::Configuration(*systemBus, objectPath),
    objServer(objectServer), systemBus(systemBus)
{
    updateConfigToDbus();
}

} // namespace config
} // namespace ras
} // namespace amd
