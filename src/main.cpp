#include "Config.hpp"
#include "cper.hpp"
#include "cper_runtime.hpp"
#include "ras.hpp"

//#undef LOG_DEBUG
//#define LOG_DEBUG LOG_ERR

boost::asio::io_service io;
static std::shared_ptr<sdbusplus::asio::object_server> server;
static std::array<
    std::pair<std::string, std::shared_ptr<sdbusplus::asio::dbus_interface>>,
    MAX_ERROR_FILE>
    crashdumpInterfaces;

boost::asio::deadline_timer* McaErrorPollingEvent = nullptr;
boost::asio::deadline_timer* DramCeccErrorPollingEvent = nullptr;
boost::asio::deadline_timer* PcieAerErrorPollingEvent = nullptr;

std::string InventoryService = "xyz.openbmc_project.Inventory.Manager";
std::string P0_InventoryPath =
    "/xyz/openbmc_project/inventory/system/processor/P0";
std::string P1_InventoryPath =
    "/xyz/openbmc_project/inventory/system/processor/P1";
constexpr auto CpuInventoryInterface = "xyz.openbmc_project.Inventory.Item.Cpu";

constexpr int kCrashdumpTimeInSec = 300;

uint8_t watchdogTimerCounter = 0;
static std::string BoardName;
uint32_t err_count = 0;
uint32_t FamilyId = 0;
gpiod::line P0_apmlAlertLine;
gpiod::line P1_apmlAlertLine;
gpiod::line P0_pmicAfAlertLine;
gpiod::line P0_pmicGlAlertLine;
gpiod::line P1_pmicAfAlertLine;
gpiod::line P1_pmicGlAlertLine;
gpiod::line HPMFPGALockoutAlertLine;

boost::asio::posix::stream_descriptor P0_apmlAlertEvent(io);
boost::asio::posix::stream_descriptor P1_apmlAlertEvent(io);
boost::asio::posix::stream_descriptor P0_pmicAfAlertEvent(io);
boost::asio::posix::stream_descriptor P0_pmicGlAlertEvent(io);
boost::asio::posix::stream_descriptor P1_pmicAfAlertEvent(io);
boost::asio::posix::stream_descriptor P1_pmicGlAlertEvent(io);
boost::asio::posix::stream_descriptor HPMFPGALockoutAlertEvent(io);

uint8_t p0_info = 0;
uint8_t p1_info = 1;

int num_of_proc = 0;

const static constexpr int resetPulseTimeMs = 100;

uint64_t RecordId = 1;
unsigned int board_id = 0;
uint32_t p0_eax = 0, p0_ebx = 0, p0_ecx = 0, p0_edx = 0;
uint32_t p1_eax = 0, p1_ebx = 0, p1_ecx = 0, p1_edx = 0;
uint32_t p0_ucode = 0;
uint32_t p1_ucode = 0;
uint64_t p0_ppin = 0;
uint64_t p1_ppin = 0;

uint64_t p0_last_transact_addr = 0;
uint64_t p1_last_transact_addr = 0;

std::vector<uint8_t> BlockId;
uint8_t ProgId = 0;
bool apmlInitialized = false;
bool platformInitialized = false;
bool runtimeErrPollingSupported = false;

/**
 * Check number of CPU's of the current platform.
 *
 * @return false if the number of CPU's is not found, otherwise true
 */
bool getNumberOfCpu()
{
    FILE* pf;
    bool ret = false;
    std::stringstream ss;

    // Setup pipe for reading and execute to get u-boot environment
    // variable num_of_cpu.
    pf = popen(COMMAND_NUM_OF_CPU, "r");
    // Error handling
    if (pf)
    {
        char data[COMMAND_LEN];
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> num_of_proc;
            ret = true;
            sd_journal_print(LOG_DEBUG, "Number of Cpu %d\n", num_of_proc);
        }

        // the data is now in 'data'
        pclose(pf);
    }

    return ret;
}

void getCpuID()
{
    uint32_t core_id = 0;
    oob_status_t ret;
    p0_eax = 1;
    p0_ebx = 0;
    p0_ecx = 0;
    p0_edx = 0;

    ret = esmi_oob_cpuid(p0_info, core_id, &p0_eax, &p0_ebx, &p0_ecx, &p0_edx);

    if (ret)
    {
        sd_journal_print(LOG_ERR, "Failed to get the CPUID for socket 0\n");
    }

    if (num_of_proc == TWO_SOCKET)
    {
        p1_eax = 1;
        p1_ebx = 0;
        p1_ecx = 0;
        p1_edx = 0;

        ret = esmi_oob_cpuid(p1_info, core_id, &p1_eax, &p1_ebx, &p1_ecx,
                             &p1_edx);

        if (ret)
        {
            sd_journal_print(LOG_ERR, "Failed to get the CPUID for socket 1\n");
        }
    }
}

void getBoardID()
{
    FILE* pf;
    std::stringstream ss;

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID, "r");
    // Error handling
    if (pf)
    {
        char data[COMMAND_LEN];
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> board_id;
            sd_journal_print(LOG_DEBUG, "Board ID: 0x%x, Board ID String: %s\n",
                             board_id, data);
        }
        // the data is now in 'data'
        pclose(pf);
    }
}

template <typename T>
T getProperty(sdbusplus::bus::bus& bus, const char* service, const char* path,
              const char* interface, const char* propertyName)
{
    auto method = bus.new_method_call(service, path,
                                      "org.freedesktop.DBus.Properties", "Get");
    method.append(interface, propertyName);
    std::variant<T> value{};
    try
    {
        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        sd_journal_print(LOG_ERR, "GetProperty call failed \n");
    }
    return std::get<T>(value);
}

void getMicrocodeRev()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string P0_MicroCode = getProperty<std::string>(
        bus, InventoryService.c_str(), P0_InventoryPath.c_str(),
        CpuInventoryInterface, "Microcode");

    if (P0_MicroCode.empty())
    {
        sd_journal_print(LOG_ERR,
                         "Failed to read ucode revision for Processor P0\n");
    }
    else
    {
        p0_ucode = std::stoul(P0_MicroCode, nullptr, BASE_16);
    }

    if (num_of_proc == TWO_SOCKET)
    {
        std::string p1_MicroCode = getProperty<std::string>(
            bus, InventoryService.c_str(), P1_InventoryPath.c_str(),
            CpuInventoryInterface, "Microcode");

        if (p1_MicroCode.empty())
        {
            sd_journal_print(
                LOG_ERR, "Failed to read ucode revision for Processor P1\n");
        }
        else
        {
            p1_ucode = std::stoul(p1_MicroCode, nullptr, BASE_16);
        }
    }
}

void getPpinFuse()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string P0_Ppin = getProperty<std::string>(
        bus, InventoryService.c_str(), P0_InventoryPath.c_str(),
        CpuInventoryInterface, "PPIN");
    if (P0_Ppin.empty())
    {
        sd_journal_print(LOG_ERR, "Failed to read PPIN for Processor P0\n");
    }
    else
    {
        p0_ppin = std::stoull(P0_Ppin, nullptr, BASE_16);
    }

    if (num_of_proc == TWO_SOCKET)
    {
        std::string P1_Ppin = getProperty<std::string>(
            bus, InventoryService.c_str(), P1_InventoryPath.c_str(),
            CpuInventoryInterface, "PPIN");
        if (P1_Ppin.empty())
        {
            sd_journal_print(LOG_ERR, "Failed to read Ppin for Processor P1\n");
        }
        else
        {
            p1_ppin = std::stoull(P1_Ppin, nullptr, BASE_16);
        }
    }
}

/**
 * Create Index file in /var/lib/amd-ras location
 * to store the index of the CPER file
 */
void CreateIndexFile()
{
    struct stat buffer;
    FILE* file;

    if (stat(kRasDir.data(), &buffer) != 0)
    {
        int dir;
        dir = mkdir(kRasDir.data(), 0777);

        if (dir != 0)
        {
            sd_journal_print(LOG_ERR,
                             "ras-errror-logging directory not created\n");
        }
    }

    memset(&buffer, 0, sizeof(buffer));
    /*Create index file to store error file count */
    if (stat(index_file, &buffer) != 0)
    {
        file = fopen(index_file, "w");

        if (file != NULL)
        {
            fprintf(file, "0");
            fclose(file);
        }
    }
    else
    {
        file = fopen(index_file, "r");

        if (file != NULL)
        {
            if (fscanf(file, "%u", &err_count) < INDEX_0)
            {
                sd_journal_print(LOG_ERR, "Failed to read CPER index number\n");
            }
            fclose(file);
        }
    }
}

void CreateDramEccErrorFile()
{
    if (!std::filesystem::exists(dramCeccErrorFile.data()))
    {
        nlohmann::json j;

        for (const auto& pair : P0_DimmEccCount)
        {
            j[pair.first] = pair.second;
        }
        for (const auto& pair : P1_DimmEccCount)
        {
            j[pair.first] = pair.second;
        }

        std::ofstream file(dramCeccErrorFile.data());
        file << std::setw(INDEX_4) << j << std::endl;
    }
    else
    {
        nlohmann::json j;
        std::ifstream file(dramCeccErrorFile.data());
        file >> j;

        for (auto& pair : P0_DimmEccCount)
        {
            if (j.contains(pair.first))
            {
                pair.second = j[pair.first];
            }
        }

        for (auto& pair : P1_DimmEccCount)
        {
            if (j.contains(pair.first))
            {
                pair.second = j[pair.first];
            }
        }
    }
}

void CreateConfigFile()
{

    struct stat buffer;

    /*Create Cdump Config file to store the system recovery*/
    if (stat(config_file, &buffer) != 0)
    {
        nlohmann::json jsonConfig = {
            {"apmlRetries", MAX_RETRIES},  {"systemRecovery", NO_RESET},
            {"harvestuCodeVersion", true}, {"harvestPpin", true},
            {"ResetSignal", SYS_RESET},
        };

        jsonConfig["sigIDOffset"] = Configuration::getSigIDOffset();

        std::vector<std::pair<std::string, std::string>> P0_DimmLabels =
            Configuration::getAllP0_DimmLabels();

        std::vector<std::pair<std::string, std::string>> P1_DimmLabels =
            Configuration::getAllP1_DimmLabels();

        std::vector<std::pair<std::string, std::string>> AifsSignatureId =
            Configuration::getAllAifsSignatureId();

        nlohmann::json jsonP0_DimmLabel;

        for (const auto& pair : P0_DimmLabels)
        {
            jsonP0_DimmLabel[pair.first] = pair.second;
        }
        jsonConfig["P0_DIMM_LABELS"] = jsonP0_DimmLabel;

        nlohmann::json jsonP1_DimmLabel;

        for (const auto& pair : P1_DimmLabels)
        {
            jsonP1_DimmLabel[pair.first] = pair.second;
        }
        jsonConfig["P1_DIMM_LABELS"] = jsonP1_DimmLabel;

        nlohmann::json jsonAifsSignatureId;

        for (const auto& pair : AifsSignatureId)
        {
            jsonAifsSignatureId[pair.first] = pair.second;
        }
        jsonConfig["AifsSignatureId"] = jsonAifsSignatureId;

        jsonConfig["McaPollingEn"] = true;
        jsonConfig["McaPollingPeriod"] = MCA_POLLING_PERIOD;
        jsonConfig["DramCeccPollingEn"] = false;
        jsonConfig["DramCeccPollingPeriod"] = DRAM_CECC_POLLING_PERIOD;
        jsonConfig["PcieAerPollingEn"] = false;
        jsonConfig["PcieAerPollingPeriod"] = PCIE_AER_POLLING_PERIOD;

        jsonConfig["McaThresholdEn"] = false;
        jsonConfig["McaErrThresholdCnt"] = ERROR_THRESHOLD_VAL;
        jsonConfig["DramCeccThresholdEn"] = false;
        jsonConfig["DramCeccErrThresholdCnt"] = ERROR_THRESHOLD_VAL;
        jsonConfig["PcieAerThresholdEn"] = false;
        jsonConfig["PcieAerErrThresholdCnt"] = ERROR_THRESHOLD_VAL;
        jsonConfig["AifsArmed"] = false;
        jsonConfig["DisableAifsResetOnSyncfloodCounter"] = true;

        std::ofstream jsonWrite(config_file);
        jsonWrite << jsonConfig;
        jsonWrite.close();
    }

    std::ifstream jsonRead(config_file);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

    Configuration::setApmlRetryCount(data["apmlRetries"]);
    Configuration::setSystemRecovery(data["systemRecovery"]);
    Configuration::setHarvestuCodeVersionFlag(data["harvestuCodeVersion"]);
    Configuration::setHarvestPpinFlag(data["harvestPpin"]);
    Configuration::setResetSignal(data["ResetSignal"]);
    Configuration::setSigIDOffset(
        data.at("sigIDOffset").get<std::vector<std::string>>());

    Configuration::setMcaPollingEn(data["McaPollingEn"]);
    Configuration::setMcaPollingPeriod(data["McaPollingPeriod"]);
    Configuration::setDramCeccPollingEn(data["DramCeccPollingEn"]);
    Configuration::setDramCeccPollingPeriod(data["DramCeccPollingPeriod"]);
    Configuration::setPcieAerPollingEn(data["PcieAerPollingEn"]);
    Configuration::setPcieAerPollingPeriod(data["PcieAerPollingPeriod"]);

    Configuration::setMcaThresholdEn(data["McaThresholdEn"]);
    Configuration::setMcaErrThresholdCnt(data["McaErrThresholdCnt"]);
    Configuration::setDramCeccThresholdEn(data["DramCeccThresholdEn"]);
    Configuration::setDramCeccErrThresholdCnt(data["DramCeccErrThresholdCnt"]);
    Configuration::setPcieAerThresholdEn(data["PcieAerThresholdEn"]);
    Configuration::setPcieAerErrThresholdCnt(data["PcieAerErrThresholdCnt"]);
    Configuration::setAifsArmed(data["AifsArmed"]);
    Configuration::setDisableResetCounter(
        data["DisableAifsResetOnSyncfloodCounter"]);

    if (data.contains("P0_DIMM_LABELS"))
    {
        nlohmann::json P0_DimmlabelsData = data["P0_DIMM_LABELS"];
        for (nlohmann::json::iterator it = P0_DimmlabelsData.begin();
             it != P0_DimmlabelsData.end(); ++it)
        {
            std::string key = it.key();
            std::string value = it.value();
            Configuration::setP0_DimmLabels(key, value);
        }
    }

    if (data.contains("P1_DIMM_LABELS"))
    {
        nlohmann::json P1_DimmlabelsData = data["P1_DIMM_LABELS"];
        for (nlohmann::json::iterator it = P1_DimmlabelsData.begin();
             it != P1_DimmlabelsData.end(); ++it)
        {
            std::string key = it.key();
            std::string value = it.value();
            Configuration::setP1_DimmLabels(key, value);
        }
    }

    if (data.contains("AifsSignatureId"))
    {

        nlohmann::json AifsSignatureIdData = data["AifsSignatureId"];
        Configuration::setAifsSignatureId(AifsSignatureIdData);
    }

    jsonRead.close();
}

oob_status_t read_register(uint8_t info, uint32_t reg, uint8_t* value)
{
    oob_status_t ret;
    uint16_t retryCount = 10;

    while (retryCount > 0)
    {
        ret = esmi_oob_read_byte(info, reg, SBRMI, value);
        if (ret == OOB_SUCCESS)
        {
            break;
        }
        sd_journal_print(LOG_ERR, "Failed to read register:0x%x Retrying\n",
                         reg);

        sleep(INDEX_1);
        retryCount--;
    }
    if (ret != OOB_SUCCESS)
    {
        sd_journal_print(LOG_ERR, "Failed to read register: 0x%x\n", reg);
    }

    return ret;
}

void clearSbrmiAlertMask()
{

    oob_status_t ret;

    for (uint8_t socNum = 0; socNum < num_of_proc; socNum++)
    {
        sd_journal_print(
            LOG_INFO,
            "Clear Alert Mask bit of SBRMI Control register for socket %d\n",
            socNum);

        uint8_t buffer;

        ret = read_register(socNum, SBRMI_CONTROL_REGISTER, &buffer);

        if (ret == OOB_SUCCESS)
        {
            buffer = buffer & 0xFE;
            write_register(socNum, SBRMI_CONTROL_REGISTER,
                           static_cast<uint32_t>(buffer));
        }

        for (uint8_t i = 0; i < sizeof(alert_status); i++)
        {
            ret = read_register(socNum, alert_status[i], &buffer);

            if (ret == OOB_SUCCESS)
            {
                if ((buffer & BITMASK_FF) != 0)
                {
                    sd_journal_print(
                        LOG_INFO,
                        "Socket%d: MCE Stat of SBRMIx[0x%x] is set to 0x%x\n",
                        socNum, alert_status[i], buffer);

                    buffer = buffer & BITMASK_FF;
                    write_register(socNum, alert_status[i],
                                   static_cast<uint32_t>(buffer));
                }
            }
            else
            {
                sd_journal_print(LOG_ERR,
                                 "Socket%d: Failed to read SBRMIx[0x%x]",
                                 socNum, alert_status[i]);
            }
        }
    }
}

static void currentHostStateMonitor()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    boost::system::error_code ec;

    static auto match = sdbusplus::bus::match::match(
        bus,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Host'",
        [](sdbusplus::message::message& message) {
            oob_status_t ret;
            std::string intfName;
            std::map<std::string, std::variant<std::string>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (std::exception& e)
            {
                sd_journal_print(LOG_ERR, "Unable to read host state\n");
                return;
            }
            if (properties.empty())
            {
                sd_journal_print(
                    LOG_ERR,
                    "ERROR: Empty PropertiesChanged signal received\n");
                return;
            }

            // We only want to check for CurrentHostState
            if (properties.begin()->first != "CurrentHostState")
            {
                return;
            }
            std::string* currentHostState =
                std::get_if<std::string>(&(properties.begin()->second));
            if (currentHostState == nullptr)
            {
                sd_journal_print(LOG_ERR, "property invalid\n");
                return;
            }

            apmlInitialized = false;

            if (std::filesystem::exists(dramCeccErrorFile.data()))
            {
                nlohmann::json j;
                std::ifstream file(dramCeccErrorFile.data());
                file >> j;

                for (auto& pair : P0_DimmEccCount)
                {
                    pair.second = 0;
                    j[pair.first] = pair.second;
                }

                for (auto& pair : P1_DimmEccCount)
                {
                    pair.second = 0;
                    j[pair.first] = pair.second;
                }

                std::ofstream outFile(dramCeccErrorFile.data());
                outFile << std::setw(INDEX_4) << j << std::endl;
            }

            if (*currentHostState !=
                "xyz.openbmc_project.State.Host.HostState.Off")
            {
                sd_journal_print(LOG_INFO,
                                 "Current host state monitor changed\n");
                uint32_t d_out = 0;

                while (ret != OOB_SUCCESS)
                {
                    ret = get_bmc_ras_oob_config(INDEX_0, &d_out);

                    if (ret == OOB_SUCCESS)
                    {
                        performPlatformInitialization();
                        watchdogTimerCounter = 0;
                        break;
                    }
                    sleep(INDEX_1);
                }
            }
        });
}

void performPlatformInitialization()
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    struct processor_info platInfo[INDEX_1];

    if (platformInitialized == false)
    {
        while (ret != OOB_SUCCESS)
        {
            uint8_t soc_num = 0;
            ret = esmi_get_processor_info(soc_num, platInfo);

            if (ret == OOB_SUCCESS)
            {
                FamilyId = platInfo->family;
                break;
            }
            sleep(INDEX_1);
        }

        if (ret == OOB_SUCCESS)
        {
            if (platInfo->family == GENOA_FAMILY_ID)
            {
                if ((platInfo->model != MI300A_MODEL_NUMBER) &&
                    (platInfo->model != MI300C_MODEL_NUMBER))
                {
                    BlockId = {BLOCK_ID_33};
                }
            }
            else if (platInfo->family == TURIN_FAMILY_ID)
            {
                currentHostStateMonitor();

                clearSbrmiAlertMask();

                BlockId = {BLOCK_ID_1,  BLOCK_ID_2,  BLOCK_ID_3,  BLOCK_ID_23,
                           BLOCK_ID_24, BLOCK_ID_33, BLOCK_ID_36, BLOCK_ID_37,
                           BLOCK_ID_38, BLOCK_ID_40};

                RunTimeErrorPolling();

                runtimeErrPollingSupported = true;
            }
            else
            {
                throw std::runtime_error(
                    "This program is not supported for the platform 0x%x\n" +
                    platInfo->family);
            }
            platformInitialized = true;
            apmlInitialized = true;
        }
        else
        {
            sd_journal_print(LOG_ERR,
                             "Failed to perform platform initialization\n");
        }
    }
    else
    {
        apmlInitialized = true;
        clearSbrmiAlertMask();

        if (runtimeErrPollingSupported == true)
        {
            sd_journal_print(LOG_INFO, "Setting MCA and DRAM OOB Config\n");
            SetMcaOobConfig();
            sd_journal_print(LOG_INFO,
                             "Setting MCA and DRAM Error threshold\n");
            McaErrThresholdEnable();
        }
    }
}

void apmlActiveMonitor()
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    uint32_t d_out = 0;

    while (ret != OOB_SUCCESS)
    {
        ret = get_bmc_ras_oob_config(INDEX_0, &d_out);

        if (ret == OOB_MAILBOX_CMD_UNKNOWN)
        {
            ret = esmi_get_processor_info(INDEX_0, plat_info);
        }
        sleep(INDEX_1);
    }

    performPlatformInitialization();

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    boost::system::error_code ec;

    static auto match = sdbusplus::bus::match::match(
        bus,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Watchdog'",
        [](sdbusplus::message::message& message) {
            std::string intfName;
            std::map<std::string, std::variant<bool>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (std::exception& e)
            {
                sd_journal_print(LOG_ERR, "Unable to read Watchdog state\n");
                return;
            }
            if (properties.empty())
            {
                sd_journal_print(
                    LOG_ERR,
                    "ERROR: Empty PropertiesChanged signal received\n");
                return;
            }

            // We only want to check for CurrentHostState
            if (properties.begin()->first != "Enabled")
            {
                return;
            }

            bool* currentTimerEnable =
                std::get_if<bool>(&(properties.begin()->second));

            if (*currentTimerEnable == false)
            {

                sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
                std::string CurrentTimerUse = getProperty<std::string>(
                    bus, "xyz.openbmc_project.Watchdog",
                    "/xyz/openbmc_project/watchdog/host0",
                    "xyz.openbmc_project.State.Watchdog", "CurrentTimerUse");

                if (CurrentTimerUse ==
                    "xyz.openbmc_project.State.Watchdog.TimerUse.BIOSFRB2")
                {
                    watchdogTimerCounter++;

                    /*Watchdog Timer Enable property will be changed twice after
                      BIOS post complete. Platform initialization should be
                      performed only during the second property change*/
                    if (watchdogTimerCounter == INDEX_2)
                    {
                        sd_journal_print(LOG_INFO, "BIOS POST complete\n");
                        sd_journal_print(LOG_INFO, "Setting PCIE OOB Config\n");
                        SetPcieOobConfig();

                        sd_journal_print(LOG_INFO,
                                         "Setting PCIE Error threshold\n");
                        PcieErrThresholdEnable();
                    }
                }
            }
        });
}

void findProgramId()
{
    oob_status_t ret;
    uint8_t soc_num = 0;

    struct processor_info platInfo[INDEX_1];

    ret = esmi_get_processor_info(soc_num, platInfo);

    if (ret == OOB_SUCCESS)
    {
        if ((platInfo->model == MI300A_MODEL_NUMBER) ||
            (platInfo->model == MI300C_MODEL_NUMBER))
        {
            ProgId = MI_PROG_SEG_ID;
        }
        else
        {
            ProgId = EPYC_PROG_SEG_ID;
        }
    }
}

int main()
{
    if (getNumberOfCpu() == false)
    {
        sd_journal_print(LOG_ERR,
                         "Could not find number of CPU's of the platform\n");
        return false;
    }

    CreateIndexFile();

    CreateConfigFile();

    CreateDbusInterface();

    apmlActiveMonitor();

    CreateDramEccErrorFile();

    getCpuID();

    getBoardID();

    findProgramId();

    if (Configuration::getHarvestuCodeVersionFlag() == true)
    {
        getMicrocodeRev();
    }
    if (Configuration::getHarvestPpinFlag() == true)
    {
        getPpinFuse();
    }

    requestGPIOEvents("P0_I3C_APML_ALERT_L", P0AlertEventHandler,
                      P0_apmlAlertLine, P0_apmlAlertEvent);
    requestGPIOEvents("P0_DIMM_AF_ERROR", P0PmicAfEventHandler,
                      P0_pmicAfAlertLine, P0_pmicAfAlertEvent);
    requestGPIOEvents("P0_DIMM_GL_ERROR", P0PmicGlEventHandler,
                      P0_pmicGlAlertLine, P0_pmicGlAlertEvent);
    requestGPIOEvents("HPM_FPGA_LOCKOUT", HPMFPGALockoutEventHandler,
                      HPMFPGALockoutAlertLine, HPMFPGALockoutAlertEvent);

    if (num_of_proc == TWO_SOCKET)
    {
        requestGPIOEvents("P1_I3C_APML_ALERT_L", P1AlertEventHandler,
                          P1_apmlAlertLine, P1_apmlAlertEvent);
        requestGPIOEvents("P1_DIMM_AF_ERROR", P1PmicAfEventHandler,
                          P1_pmicAfAlertLine, P1_pmicAfAlertEvent);
        requestGPIOEvents("P1_DIMM_GL_ERROR", P1PmicGlEventHandler,
                          P1_pmicGlAlertLine, P1_pmicGlAlertEvent);
    }

    io.run();

    if (McaErrorPollingEvent != nullptr)
    {
        delete McaErrorPollingEvent;
    }

    if (DramCeccErrorPollingEvent != nullptr)
    {
        delete DramCeccErrorPollingEvent;
    }

    if (PcieAerErrorPollingEvent != nullptr)
    {
        delete PcieAerErrorPollingEvent;
    }

    return 0;
}
