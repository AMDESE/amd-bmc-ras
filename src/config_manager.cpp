#include "config_manager.hpp"

#include "ras.hpp"

#include <nlohmann/json.hpp>

#include <fstream>

/**
 * @brief Sets the attribute in the configuration
 *
 * This function updates the specified attribute in configuration JSON file.
 * If the attribute
 * is found, its value is updated and saved back to the file.
 *
 * @param[in] attribute The name of the attribute to set.
 * @param[in] value The value to set for the specified attribute.
 */
void RasConfiguration::setAttribute(AttributeName attribute,
                                    AttributeValue value)
{
    nlohmann::json j;

    auto configMap = rasConfigTable();

    try
    {
        std::ifstream jsonFile(CONFIG_FILE);
        if (!jsonFile.is_open())
        {
            throw std::runtime_error("Could not open JSON file");
        }

        jsonFile >> j;
        jsonFile.close();

        bool attributeFound = false;
        for (auto& configItem : j["Configuration"])
        {
            auto it = configItem.find(attribute);
            if (it != configItem.end())
            {
                std::visit([&](auto&& arg) { it.value()["Value"] = arg; },
                           value);
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
            lg2::info("Attribute updated successfully");
        }
        else
        {
            lg2::error("Attribute not found");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Error : {ERROR}", "ERROR", e.what());
    }

    rasConfigTable(configMap);

    std::ofstream jsonFileOut(CONFIG_FILE);
    jsonFileOut << j.dump(4);
    jsonFileOut.close();
}

/**
 * @brief Retrieves the value of a specified attribute from the configuration.
 *
 * This function searches for the specified attribute in the configuration
 * map and returns its value.
 *
 * @param[in] attribute The name of the attribute to retrieve.
 * @return The value of the specified attribute, or a default-constructed
 * AttributeValue if not found.
 */
AttributeValue RasConfiguration::getAttribute(AttributeName attribute)
{
    auto configMap = rasConfigTable();
    AttributeValue value;

    for (auto& [key, tuple] : configMap)
    {
        if (key == attribute)
        {
            value = std::get<2>(tuple);
            break;
        }
    }
    return value;
}

/**
 * @brief Constructor for RasConfiguration
 *
 * This constructor initializes a RasConfiguration object with a given object
 * server and system bus connection.
 *
 * @param[in] objectServer Reference to an object server for managing D-Bus
 * objects.
 * @param[in] systemBus Shared pointer to a D-Bus connection.
 */
RasConfiguration::RasConfiguration(
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus) :
    sdbusplus::com::amd::RAS::server::Configuration(*systemBus, objectPath),
    objServer(objectServer), systemBus(systemBus)
{}
