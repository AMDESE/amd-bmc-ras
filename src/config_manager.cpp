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

    if (jsonFile.peek() == std::ifstream::traits_type::eof())
    {
        jsonFile.close();
        lg2::error("Config file is empty: {FILE}, restoring from source",
                   "FILE", configFile);
        fs::copy_file(SRC_CONFIG_FILE, configFile,
                      fs::copy_options::overwrite_existing);
        jsonFile.open(configFile);
        if (!jsonFile.is_open())
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }
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

        std::string tmpFile = configFile + ".tmp";
        std::ofstream jsonFileOut(tmpFile);

        if (!jsonFileOut.is_open())
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        jsonFileOut << data.dump(4);
        jsonFileOut.flush();
        jsonFileOut.close();

        try
        {
            fs::rename(tmpFile, configFile);
        }
        catch (const fs::filesystem_error& e)
        {
            lg2::error("Failed to rename temp file {TMP} to {CFG}: {ERR}",
                       "TMP", tmpFile, "CFG", configFile, "ERR", e.what());
            fs::remove(tmpFile);
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }
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
                throw std::runtime_error(
                    "Failed to create directory: " + destDir.string() + " (" +
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

    if (!jsonRead.is_open())
    {
        lg2::error("Could not read config file Error : {ERROR}", "ERROR",
                   strerror(errno));
        throw std::runtime_error("Error: Could not read config file");
    }

    if (jsonRead.peek() == std::ifstream::traits_type::eof())
    {
        jsonRead.close();
        lg2::error("Config file is empty: {FILE}, restoring from source",
                   "FILE", configFile);
        fs::copy_file(SRC_CONFIG_FILE, configFile,
                      fs::copy_options::overwrite_existing);
        jsonRead.open(configFile);
        if (!jsonRead.is_open())
        {
            lg2::error("Could not read config file after restore: {ERROR}",
                       "ERROR", strerror(errno));
            throw std::runtime_error("Error: Could not read config file");
        }
    }

    nlohmann::json data = nlohmann::json::parse(jsonRead);

    ConfigTable configMap;

    lg2::info("PARSE CONFIGURATION");
    for (const auto& item : data["Configuration"])
    {
        AttributeType attributeType = sdbusplus::common::com::amd::ras::
            Configuration::AttributeType::Boolean;
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

        if (node != "0")
        {
            if (filename.starts_with("node" + node))
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

uint64_t Manager::getThresholdCount(const std::string& thresholdEnKey,
                                    const std::string& thresholdCntKey)
{
    const auto configMap = rasConfigTable();

    // Check if thresholding is enabled
    auto enIt = configMap.find(thresholdEnKey);
    if (enIt != configMap.end())
    {
        const auto& enValue = std::get<2>(enIt->second);
        if (std::holds_alternative<bool>(enValue) && std::get<bool>(enValue))
        {
            // Threshold enabled, return the configured count
            auto cntIt = configMap.find(thresholdCntKey);
            if (cntIt != configMap.end())
            {
                const auto& cntValue = std::get<2>(cntIt->second);
                if (std::holds_alternative<int64_t>(cntValue))
                {
                    auto count = std::get<int64_t>(cntValue);
                    return (count > 0) ? static_cast<uint64_t>(count) : 1;
                }
            }
        }
    }

    return 1;
}

void Manager::loadErrorCounts()
{
    std::ifstream file(errorCountFile);
    if (file.is_open())
    {
        try
        {
            nlohmann::json data = nlohmann::json::parse(file);
            for (size_t s = 0; s < maxSockets; ++s)
            {
                std::string prefix = "p" + std::to_string(s);
                for (size_t i = 0; i < maxErrorIndex; ++i)
                {
                    correctableCPUErrors[s][i] =
                        data[prefix + "CorrectableCPUErrors"][i]
                            .get<uint64_t>();
                    noncorrectableCPUErrors[s][i] =
                        data[prefix + "NoncorrectableCPUErrors"][i]
                            .get<uint64_t>();
                }
                correctableOtherErrors[s] =
                    data[prefix + "CorrectableOtherErrors"].get<uint64_t>();
                noncorrectableOtherErrors[s] =
                    data[prefix + "NoncorrectableOtherErrors"].get<uint64_t>();
            }
            lg2::info("Error counts loaded from {FILE}", "FILE",
                      errorCountFile);
            updateErrorCountDbus();
        }
        catch (const nlohmann::json::exception& e)
        {
            lg2::error("Failed to parse {FILE}: {ERR}", "FILE", errorCountFile,
                       "ERR", e.what());
            saveErrorCounts();
        }
    }
    else
    {
        lg2::info("{FILE} not found, creating with defaults", "FILE",
                  errorCountFile);
        saveErrorCounts();
    }
}

void Manager::saveErrorCounts()
{
    std::filesystem::create_directories(
        std::filesystem::path(errorCountFile).parent_path());

    nlohmann::json data;
    for (size_t s = 0; s < maxSockets; ++s)
    {
        std::string prefix = "p" + std::to_string(s);
        data[prefix + "CorrectableCPUErrors"] = correctableCPUErrors[s];
        data[prefix + "NoncorrectableCPUErrors"] = noncorrectableCPUErrors[s];
        data[prefix + "CorrectableOtherErrors"] = correctableOtherErrors[s];
        data[prefix + "NoncorrectableOtherErrors"] =
            noncorrectableOtherErrors[s];
    }

    std::string tmpFile = errorCountFile + ".tmp";
    std::ofstream file(tmpFile);
    if (!file.is_open())
    {
        lg2::error("Failed to open {FILE} for writing", "FILE", tmpFile);
        return;
    }
    file << data.dump(4);
    file.flush();
    file.close();

    try
    {
        fs::rename(tmpFile, errorCountFile);
    }
    catch (const fs::filesystem_error& e)
    {
        lg2::error("Failed to rename temp file {TMP} to {DST}: {ERR}", "TMP",
                   tmpFile, "DST", errorCountFile, "ERR", e.what());
        fs::remove(tmpFile);
        return;
    }
    updateErrorCountDbus();
}

void Manager::updateErrorCountDbus()
{
    if (!errorCountIface)
    {
        return;
    }

    for (size_t s = 0; s < maxSockets; ++s)
    {
        std::string prefix = "P" + std::to_string(s);
        errorCountIface->set_property(
            prefix + "CorrectableCPUErrors",
            std::vector<uint64_t>(correctableCPUErrors[s].begin(),
                                  correctableCPUErrors[s].end()));
        errorCountIface->set_property(
            prefix + "NoncorrectableCPUErrors",
            std::vector<uint64_t>(noncorrectableCPUErrors[s].begin(),
                                  noncorrectableCPUErrors[s].end()));
        errorCountIface->set_property(prefix + "CorrectableOtherErrors",
                                      correctableOtherErrors[s]);
        errorCountIface->set_property(prefix + "NoncorrectableOtherErrors",
                                      noncorrectableOtherErrors[s]);
    }
}

Manager::Manager(sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 std::string& node) :
    amd::ras::config::ConfigIface(*systemBus, objectPath),
    objServer(objectServer), systemBus(systemBus), node(node),
    errorCountFile("/var/lib/amd-bmc-ras/error_count" + node + ".json")
{
    updateConfigToDbus();
    loadErrorCounts();

    errorCountIface =
        objServer.add_interface(errorCountPath, errorCountInterface);

    for (size_t s = 0; s < maxSockets; ++s)
    {
        std::string prefix = "P" + std::to_string(s);
        std::vector<uint64_t> corCPU(correctableCPUErrors[s].begin(),
                                     correctableCPUErrors[s].end());
        std::vector<uint64_t> noncorCPU(noncorrectableCPUErrors[s].begin(),
                                        noncorrectableCPUErrors[s].end());

        errorCountIface->register_property(prefix + "CorrectableCPUErrors",
                                           corCPU);
        errorCountIface->register_property(prefix + "NoncorrectableCPUErrors",
                                           noncorCPU);
        errorCountIface->register_property(prefix + "CorrectableOtherErrors",
                                           correctableOtherErrors[s]);
        errorCountIface->register_property(prefix + "NoncorrectableOtherErrors",
                                           noncorrectableOtherErrors[s]);
    }

    errorCountIface->initialize();
}

} // namespace config
} // namespace ras
} // namespace amd
