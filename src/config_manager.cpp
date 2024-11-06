#include "config_manager.hpp"

#include "ras.hpp"

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

RasConfiguration::RasConfiguration(
    sdbusplus::asio::object_server& objectServer,
    std::shared_ptr<sdbusplus::asio::connection>& systemBus) :
    sdbusplus::com::amd::RAS::server::Configuration(*systemBus, objectPath),
    objServer(objectServer), systemBus(systemBus)
{}
