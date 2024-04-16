#include "cper_generator.hpp"
#include "interface_manager.hpp"

void InterfaceManager::getNumberOfCpu()
{
    FILE* pf;
    char data[COMMAND_LEN];
    std::stringstream ss;

    pf = popen(COMMAND_NUM_OF_CPU.data(), "r");
    if (pf)
    {
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> numOfCpu;

            lg2::debug("Number of Cpu {CPU}", "CPU", numOfCpu);
            cpuId = new CpuId[numOfCpu];

            uCode = new uint32_t[numOfCpu];
            std::memset(uCode, 0, numOfCpu * sizeof(uint32_t));

            ppin = new uint64_t[numOfCpu];
            std::memset(ppin, 0, numOfCpu * sizeof(uint64_t));

            inventoryPath = new std::string[numOfCpu];

            for (int i = 0; i < numOfCpu; i++)
            {
                inventoryPath[i] =
                    "/xyz/openbmc_project/inventory/system/processor/P" +
                    std::to_string(i);
            }
        }
        else
        {
            throw std::runtime_error("Error reading data from the process.");
        }
        pclose(pf);
    }
    else
    {
        throw std::runtime_error("Error opening the process.");
    }
}

void InterfaceManager::p0AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = p0_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        lg2::debug("Falling Edge: P0 APML Alert received");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<CperRecord>();
        }

        harvestFatalError(SOCKET_0);
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        lg2::debug("Rising Edge: P0 APML Alert cancelled");
    }

    p0_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code ec) {
            if (ec)
            {

                lg2::error("P0 APML alert handler error: {ERROR}", "ERROR",
                           ec.message().c_str());
                return;
            }
            p0AlertEventHandler();
        });
}

bool InterfaceManager::harvestMcaValidityCheck(uint8_t info, uint16_t* numbanks,
                                               uint16_t* bytespermca)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    bool mcaValidityCheck = true;

    AttributeValue apmlRetry = getAttribute("apmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_bmc_ras_mca_validity_check(info, bytespermca, numbanks);

        if (retries > *apmlRetryCount)
        {
            lg2::error(
                "Socket {SOCK}: Failed to get MCA banks with valid status",
                "SOCK", info);
            break;
        }

        if ((*numbanks == 0) || (*numbanks > MAX_MCA_BANKS))
        {
            lg2::error("Socket {SOCKET}: Invalid MCA bank validity status. "
                       "Retry Count: {RETRY_COUNT}",
                       "SOCKET", info, "RETRY_COUNT", retries);
            ret = OOB_MAILBOX_CMD_UNKNOWN;
            usleep(1000 * 1000);
            continue;
        }
    }

    if ((*numbanks <= 0) || (*numbanks > MAX_MCA_BANKS))
    {
        mcaValidityCheck = false;
    }

    return mcaValidityCheck;
}

template <typename T>
void InterfaceManager::harvestMcaDataBanks(uint8_t info, uint16_t numbanks,
                                           uint16_t bytespermca,
                                           CperGenerator<T>& cperGenerator)
{
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint32_t Severity;
    bool ValidSignatureID = false;

    int syndOffsetLo = 0;
    int syndOffsetHi = 0;
    int ipidOffsetLo = 0;
    int ipidOffsetHi = 0;
    int statusOffsetLo = 0;
    int statusOffsetHi = 0;

    uint32_t mcaStatusLo = 0;
    uint32_t mcaStatusHi = 0;
    uint32_t mcaIpidLo = 0;
    uint32_t mcaIpidHi = 0;
    uint32_t mcaSyndLo = 0;
    uint32_t mcaSyndHi = 0;

    AttributeValue sigIdOffsetVal = getAttribute("SigIDOffset");
    std::vector<std::string>* sigIDOffset =
        std::get_if<std::vector<std::string>>(&sigIdOffsetVal);

    AttributeValue apmlRetry = getAttribute("apmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    cperGenerator.dumpCperHeaderSection(rcd, FATAL_SECTION_COUNT,
                                        CPER_SEV_FATAL, FATAL_ERR);

    rcd->sectionDescriptor = new ErrorSectionDescriptor[FATAL_SECTION_COUNT];
    std::memset(rcd->sectionDescriptor, 0,
                FATAL_SECTION_COUNT * sizeof(ErrorSectionDescriptor));

    rcd->errorRecord = new ErrorRecord[FATAL_SECTION_COUNT];
    std::memset(rcd->errorRecord, 0, FATAL_SECTION_COUNT * sizeof(ErrorRecord));

    cperGenerator.dumpErrorDescriptorSection(rcd, FATAL_SECTION_COUNT,
                                             FATAL_ERR, &Severity);

    cperGenerator.dumpProcessorErrorSection(rcd, info, FATAL_SECTION_COUNT,
                                            cpuId);

    cperGenerator.dumpContextInfo(rcd, numbanks, bytespermca, info,
                                  FATAL_SECTION_COUNT, blockId, ppin, uCode,
                                  apmlRetryCount);

    syndOffsetLo = std::stoul((*sigIDOffset)[INDEX_0], nullptr, BASE_16);
    syndOffsetHi = std::stoul((*sigIDOffset)[INDEX_1], nullptr, BASE_16);
    ipidOffsetLo = std::stoul((*sigIDOffset)[INDEX_2], nullptr, BASE_16);
    ipidOffsetHi = std::stoul((*sigIDOffset)[INDEX_3], nullptr, BASE_16);
    statusOffsetLo = std::stoul((*sigIDOffset)[INDEX_4], nullptr, BASE_16);
    statusOffsetHi = std::stoul((*sigIDOffset)[INDEX_5], nullptr, BASE_16);

    maxOffset32 =
        ((bytespermca % BYTE_4) ? INDEX_1 : INDEX_0) + (bytespermca >> BYTE_2);
    lg2::info("Number of Valid MCA bank: {NUMBANKS}", "NUMBANKS", numbanks);
    lg2::info("Number of 32 Bit Words:{MAX_OFFSET}", "MAX_OFFSET", maxOffset32);

    while (n < numbanks)
    {
        for (int offset = 0; offset < maxOffset32; offset++)
        {
            memset(&buffer, 0, sizeof(buffer));
            memset(&mca_dump, 0, sizeof(mca_dump));
            mca_dump.index = n;
            mca_dump.offset = offset * BYTE_4;

            ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

            if (ret != OOB_SUCCESS)
            {
                while (*apmlRetryCount > 0)
                {
                    memset(&buffer, 0, sizeof(buffer));
                    memset(&mca_dump, 0, sizeof(mca_dump));
                    mca_dump.index = n;
                    mca_dump.offset = offset * BYTE_4;

                    ret = read_bmc_ras_mca_msr_dump(info, mca_dump, &buffer);

                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    (*apmlRetryCount)--;
                    usleep(1000 * 1000);
                }
                if (ret != OOB_SUCCESS)
                {
                    lg2::error("Socket {SOCKET} : Failed to get MCA bank data "
                               "from Bank:{N}, Offset:{OFFSET}",
                               "SOCKET", info, "N", n, "OFFSET", lg2::hex,
                               offset);
                    rcd->errorRecord[info]
                        .contextInfo.crashDumpData[n]
                        .mcaData[offset] = BAD_DATA;
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            rcd->errorRecord[info]
                .contextInfo.crashDumpData[n]
                .mcaData[offset] = buffer;

            if (mca_dump.offset == statusOffsetLo)
            {
                mcaStatusLo = buffer;
            }
            if (mca_dump.offset == statusOffsetHi)
            {
                mcaStatusHi = buffer;

                /*Bit 23 and bit 25 of MCA_STATUS_HI
                  should be set for a valid signature ID*/
                if ((mcaStatusHi & (INDEX_1 << SHIFT_25)) &&
                    (mcaStatusHi & (INDEX_1 << SHIFT_23)))
                {
                    ValidSignatureID = true;
                }
            }
            if (mca_dump.offset == ipidOffsetLo)
            {
                mcaIpidLo = buffer;
            }
            if (mca_dump.offset == ipidOffsetHi)
            {
                mcaIpidHi = buffer;
            }
            if (mca_dump.offset == syndOffsetLo)
            {
                mcaSyndLo = buffer;
            }
            if (mca_dump.offset == syndOffsetHi)
            {
                mcaSyndHi = buffer;
            }

        } // for loop

        if (ValidSignatureID == true)
        {
            rcd->errorRecord[info].procError.signatureID[INDEX_0] = mcaSyndLo;
            rcd->errorRecord[info].procError.signatureID[INDEX_1] = mcaSyndHi;
            rcd->errorRecord[info].procError.signatureID[INDEX_2] = mcaIpidLo;
            rcd->errorRecord[info].procError.signatureID[INDEX_3] = mcaIpidHi;
            rcd->errorRecord[info].procError.signatureID[INDEX_4] = mcaStatusLo;
            rcd->errorRecord[info].procError.signatureID[INDEX_5] = mcaStatusHi;

            rcd->errorRecord[info].procError.validBits =
                rcd->errorRecord[info].procError.validBits |
                FAILURE_SIGNATURE_ID;

            ValidSignatureID = false;
        }
        else
        {
            mcaSyndLo = 0;
            mcaSyndHi = 0;
            mcaIpidLo = 0;
            mcaIpidHi = 0;
            mcaStatusLo = 0;
            mcaStatusHi = 0;
        }
        n++;
    }
}

void InterfaceManager::harvestFatalError(uint8_t info)
{
    std::unique_lock lock(harvest_in_progress_mtx);

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;
    bool controlFabricError = false;
    bool fchHangError = false;
    uint8_t buf;
    bool resetReady = false;

    CperGenerator<CperRecord> cperGenerator(numOfCpu, progId, familyId,
                                            errCount);

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {
        lg2::debug("Read RAS status register. Value: {BUF}", "BUF", buf);

        // check RAS Status Register
        if (buf & INT_15)
        {
            lg2::error("The alert signaled is due to a RAS fatal error");

            if (buf & SYS_MGMT_CTRL_ERR)
            {
                /*if RasStatus[reset_ctrl_err] is set in any of the processors,
                  proceed to cold reset, regardless of the status of the other P
                */

                std::string ras_err_msg =
                    "Fatal error detected in the control fabric. "
                    "BMC may trigger a reset based on policy set. ";

                sd_journal_send(
                    "MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", ras_err_msg.c_str(), NULL);

                p0AlertProcessed = true;
                p1AlertProcessed = true;
                controlFabricError = true;
            }
            else if (buf & RESET_HANG_ERR)
            {
                std::string ras_err_msg =
                    "System hang while resetting in syncflood."
                    "Suggested next step is to do an additional manual "
                    "immediate reset";

                sd_journal_send(
                    "MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", ras_err_msg.c_str(), NULL);

                fchHangError = true;
            }
            else if (buf & FATAL_ERROR)
            {
                std::string ras_err_msg = "RAS FATAL Error detected. "
                                          "System may reset after harvesting "
                                          "MCA data based on policy set. ";

                sd_journal_send(
                    "MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i", LOG_ERR,
                    "REDFISH_MESSAGE_ID=%s", "OpenBMC.0.1.CPUError",
                    "REDFISH_MESSAGE_ARGS=%s", ras_err_msg.c_str(), NULL);

                if (true ==
                    harvestMcaValidityCheck(info, &numbanks, &bytespermca))
                {
                    harvestMcaDataBanks(info, numbanks, bytespermca,
                                        cperGenerator);
                }
            }

            if (info == SOCKET_0)
            {
                p0AlertProcessed = true;
            }

            if (info == SOCKET_1)
            {
                p1AlertProcessed = true;
            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in
            // implementation of SMU?

            writeRegister(info, RAS_STATUS_REGISTER, buf);

            if (fchHangError == true)
            {
                // return true;
            }

            if (numOfCpu == TWO_SOCKET)
            {
                if ((p0AlertProcessed == true) && (p1AlertProcessed == true))
                {
                    resetReady = true;
                }
            }
            else
            {
                resetReady = true;
            }

            if (resetReady == true)
            {

                if (controlFabricError == false)
                {
                    cperGenerator.cperFileWrite(rcd, FATAL_ERR,
                                                FATAL_SECTION_COUNT);
                }

                if (rcd->sectionDescriptor != nullptr)
                {
                    delete[] rcd->sectionDescriptor;
                    rcd->sectionDescriptor = nullptr;
                }
                if (rcd->errorRecord != nullptr)
                {
                    delete[] rcd->errorRecord;
                    rcd->errorRecord = nullptr;
                }

                rcd = nullptr;

                rasRecoveryAction(buf);

                p0AlertProcessed = false;
                p1AlertProcessed = false;
            }
        }
    }
    else
    {
        lg2::debug("Nothing to Harvest. Not RAS Error");
    }
}

void InterfaceManager::p1AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = p1_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        lg2::debug("Falling Edge: P1 APML Alert received");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<CperRecord>();
        }
        harvestFatalError(SOCKET_1);
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        lg2::debug("Rising Edge: P1 APML Alert cancelled");
    }

    p1_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code ec) {
            if (ec)
            {
                lg2::error("P1 APML alert handler error {ERR}", "ERR",
                           ec.message().c_str());

                return;
            }
            p1AlertEventHandler();
        });
}

void InterfaceManager::clearSbrmiAlertMask(uint8_t socNum)
{

    oob_status_t ret;

    lg2::info("Clear Alert Mask bit of SBRMI Control register");

    uint8_t buffer;

    ret = readRegister(socNum, SBRMI_CONTROL_REGISTER, &buffer);

    if (ret == OOB_SUCCESS)
    {
        buffer = buffer & 0xFE;
        writeRegister(socNum, SBRMI_CONTROL_REGISTER,
                      static_cast<uint32_t>(buffer));
    }
}

void InterfaceManager::writeRegister(uint8_t info, uint32_t reg, uint32_t value)
{
    oob_status_t ret;

    ret = esmi_oob_write_byte(info, reg, SBRMI, value);
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to write register: {REG}", "REG", lg2::hex, reg);
        return;
    }
    lg2::debug("Write to register {REGISTER} is successful", "REGISTER", reg);
}

oob_status_t InterfaceManager::readRegister(uint8_t info, uint32_t reg,
                                            uint8_t* value)
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

        lg2::error("Failed to read register: {REGISTER} Retrying\n", "REGISTER",
                   lg2::hex, reg);

        usleep(1000 * 1000);
        retryCount--;
    }
    if (ret != OOB_SUCCESS)
    {
        lg2::error("Failed to read register: {REGISTER}\n", "REGISTER",
                   lg2::hex, reg);
    }

    return ret;
}

void InterfaceManager::requestHostTransition(std::string command)
{

    boost::system::error_code ec;
    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->async_method_call(
        [](boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(
                    LOG_ERR, "Failed to trigger cold reset of the system\n");
            }
        },
        "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.State.Host", "RequestedHostTransition",
        std::variant<std::string>{command});
}

void InterfaceManager::triggerColdReset()
{
    AttributeValue ResetSignalVal = getAttribute("ResetSignal");
    std::string* ResetSignal = std::get_if<std::string>(&ResetSignalVal);

    if (*ResetSignal == "SYS_RST")
    {
        std::string command =
            "xyz.openbmc_project.State.Host.Transition.Reboot";

        requestHostTransition(command);
    }
    else if (*ResetSignal == "RSMRST")
    {
        boost::system::error_code ec;
        boost::asio::io_context io;
        auto conn = std::make_shared<sdbusplus::asio::connection>(io);

        conn->async_method_call(
            [](boost::system::error_code ec) {
                if (ec)
                {
                    sd_journal_print(
                        LOG_ERR,
                        "Failed to trigger cold reset of the system\n");
                }
            },
            "xyz.openbmc_project.State.Host",
            "/xyz/openbmc_project/control/host0/SOCReset",
            "xyz.openbmc_project.Control.Host.SOCReset", "SOCReset");

        sleep(1);
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
        std::string CurrentHostState = getProperty<std::string>(
            bus, "xyz.openbmc_project.State.Host",
            "/xyz/openbmc_project/state/host0",
            "xyz.openbmc_project.State.Host", "CurrentHostState");

        if (CurrentHostState.compare(
                "xyz.openbmc_project.State.Host.HostState.Off") == 0)
        {

            std::string command =
                "xyz.openbmc_project.State.Host.Transition.On";

            requestHostTransition(command);
        }
    }
}

void InterfaceManager::apmlInitializeCheck()
{
    oob_status_t ret;
    uint8_t socNum = 0;

    struct processor_info plat_info[INDEX_1];
    uint16_t retryCount = 10;
    struct stat buffer;

    while (INDEX_1)
    {
        if (stat(APML_INIT_DONE_FILE.data(), &buffer) == 0)
        {
            lg2::info("APML initialization done");
            break;
        }
    }

    while (retryCount > 0)
    {
        ret = esmi_get_processor_info(socNum, plat_info);

        if (ret == OOB_SUCCESS)
        {
            familyId = plat_info->family;
            break;
        }
        usleep(1000 * 1000);
        retryCount--;

        lg2::info("Reading family ID failed. Retry count = {RETRY_COUNT}",
                  "RETRY_COUNT", retryCount);
    }
    if (plat_info->family == GENOA_FAMILY_ID)
    {
        if ((plat_info->model != MI300A_MODEL_NUMBER) &&
            (plat_info->model != MI300C_MODEL_NUMBER))
        {
            blockId = {BLOCK_ID_33};
        }
    }
    else if (plat_info->family == TURIN_FAMILY_ID)
    {

        apmlInitialized = true;

        for (uint8_t i = 0; i < numOfCpu; i++)
        {
            clearSbrmiAlertMask(i);
        }

        currentHostStateMonitor();

        blockId = {BLOCK_ID_1,  BLOCK_ID_2,  BLOCK_ID_3,
                   BLOCK_ID_24, BLOCK_ID_33, BLOCK_ID_36,
                   BLOCK_ID_37, BLOCK_ID_38, BLOCK_ID_40};
    }
    else
    {
        throw std::runtime_error("ADDC is not supported for this platform");
    }
}

void InterfaceManager::currentHostStateMonitor()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    boost::system::error_code ec;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    static auto match = sdbusplus::bus::match::match(
        *conn,
        "type='signal',member='PropertiesChanged', "
        "interface='org.freedesktop.DBus.Properties', "
        "arg0='xyz.openbmc_project.State.Host'",
        [this](sdbusplus::message::message& message) {
            std::string intfName;
            std::map<std::string, std::variant<std::string>> properties;

            try
            {
                message.read(intfName, properties);
            }
            catch (std::exception& e)
            {
                lg2::error("Unable to read host state");
                return;
            }
            if (properties.empty())
            {
                lg2::error("ERROR: Empty PropertiesChanged signal received");
                return;
            }

            if (properties.begin()->first != "CurrentHostState")
            {
                return;
            }
            std::string* currentHostState =
                std::get_if<std::string>(&(properties.begin()->second));
            if (currentHostState == nullptr)
            {
                lg2::error("property invalid");
                return;
            }

            if (*currentHostState !=
                "xyz.openbmc_project.State.Host.HostState.Off")
            {

                apmlInitialized = false;
                struct stat buffer;

                while (INDEX_1)
                {
                    if (stat(APML_INIT_DONE_FILE.data(), &buffer) == 0)
                    {
                        lg2::info("APML initialization done");
                        break;
                    }
                }

                sleep(180);
                apmlInitialized = true;

                for (uint8_t i = 0; i < numOfCpu; i++)
                {
                    clearSbrmiAlertMask(i);
                }
            }
        });
}

void InterfaceManager::getCpuId()
{
    for (int i = 0; i < numOfCpu; i++)
    {
        uint32_t core_id = 0;
        oob_status_t ret;
        cpuId[i].eax = 1;
        cpuId[i].ebx = 0;
        cpuId[i].ecx = 0;
        cpuId[i].edx = 0;

        ret = esmi_oob_cpuid(i, core_id, &cpuId[i].eax, &cpuId[i].ebx,
                             &cpuId[i].ecx, &cpuId[i].edx);

        if (ret)
        {
            lg2::error("Failed to get the CPUID for socket {CPU}", "CPU", i);
        }
    }
}

void InterfaceManager::getBoardId()
{
    FILE* pf;
    char data[COMMAND_LEN];
    std::stringstream ss;

    // Setup pipe for reading and execute to get u-boot environment
    // variable board_id.
    pf = popen(COMMAND_BOARD_ID.data(), "r");
    // Error handling
    if (pf)
    {
        // Get the data from the process execution
        if (fgets(data, COMMAND_LEN, pf))
        {
            ss << std::hex << (std::string)data;
            ss >> boardId;

            lg2::debug("Board ID: {BOARD_ID}", "BOARD_ID", boardId);
        }
        // the data is now in 'data'
        pclose(pf);
    }
}

void InterfaceManager::findProgramId()
{
    oob_status_t ret;
    uint8_t socNum = 0;

    struct processor_info platInfo[INDEX_1];

    ret = esmi_get_processor_info(socNum, platInfo);

    if (ret == OOB_SUCCESS)
    {
        if ((platInfo->model == MI300A_MODEL_NUMBER) ||
            (platInfo->model == MI300C_MODEL_NUMBER))
        {
            progId = MI_PROG_SEG_ID;
        }
        else
        {
            progId = EPYC_PROG_SEG_ID;
        }
    }
}

void InterfaceManager::init()
{

    getNumberOfCpu();

    apmlInitializeCheck();

    getCpuId();

    getBoardId();

    findProgramId();
}

void InterfaceManager::createIndexFile()
{
    try
    {
        struct stat buffer;

        // Create the RAS directory if it doesn't exist
        if (stat(RAS_DIR.data(), &buffer) != 0)
        {
            if (mkdir(RAS_DIR.data(), 0777) != 0)
            {
                throw std::runtime_error(
                    "Failed to create ras-error-logging directory");
            }
        }

        memset(&buffer, 0, sizeof(buffer));

        // Create or read the index file
        if (stat(INDEX_FILE.data(), &buffer) != 0)
        {
            std::ofstream file(INDEX_FILE.data());
            if (file.is_open())
            {
                file << "0";
                file.close();
            }
            else
            {
                throw std::runtime_error("Failed to create index file");
            }
        }
        else
        {
            std::ifstream file(INDEX_FILE);
            if (file.is_open())
            {
                if (!(file >> errCount) || errCount < INDEX_0)
                {
                    throw std::runtime_error(
                        "Failed to read CPER index number");
                }
                file.close();
            }
            else
            {
                throw std::runtime_error("Failed to read from index file");
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERROR}", "ERROR", e.what());
    }
}

void InterfaceManager::createConfigFile()
{

    struct stat buffer;

    /*Create Cdump Config file to store the system recovery*/
    if (stat(CONFIG_FILE.data(), &buffer) != 0)
    {
        std::string copyCommand =
            std::string("cp ") + SRC_CONFIG_FILE + " " + CONFIG_FILE;

        int result = system(copyCommand.c_str());
        if (result != 0)
        {
            lg2::error("Error copying RAS config file.");
        }
    }

    std::ifstream jsonRead(CONFIG_FILE);
    nlohmann::json data = nlohmann::json::parse(jsonRead);

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

template <typename T>
T InterfaceManager::getProperty(sdbusplus::bus::bus& bus, const char* service,
                                const char* path, const char* interface,
                                const char* propertyName)
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
        lg2::info("GetProperty call failed");
    }
    return std::get<T>(value);
}

void InterfaceManager::getMicrocodeRev()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    for (int i = 0; i < numOfCpu; i++)
    {
        std::string microCode = getProperty<std::string>(
            bus, INVENTORY_SERVICE.data(), inventoryPath[i].c_str(),
            CPU_INVENTORY_INTERFACE.data(), "Microcode");

        if (microCode.empty())
        {
            lg2::error("Failed to read ucode revision");
        }
        else
        {
            uCode[i] = std::stoul(microCode, nullptr, BASE_16);
        }
    }
}

void InterfaceManager::getPpinFuse()
{
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    for (int i = 0; i < numOfCpu; i++)
    {
        std::string microCode = getProperty<std::string>(
            bus, INVENTORY_SERVICE.data(), inventoryPath[i].c_str(),
            CPU_INVENTORY_INTERFACE.data(), "PPIN");

        if (microCode.empty())
        {
            lg2::error("Failed to read ppin");
        }
        else
        {
            ppin[i] = std::stoul(microCode, nullptr, BASE_16);
        }
    }
}

void InterfaceManager::configure()
{
    createIndexFile();

    createConfigFile();

    AttributeValue uCodeVersion = getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    AttributeValue harvestPpin = getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    if (*uCodeVersionFlag == true)
    {
        getMicrocodeRev();
    }
    if (*harvestPpinFlag == true)
    {
        getPpinFuse();
    }
}

void InterfaceManager::requestGPIOEvents(
    const std::string& name, const std::function<void()>& handler,
    gpiod::line& gpioLine,
    boost::asio::posix::stream_descriptor& gpioEventDescriptor)
{
    try
    {
        // Find the GPIO line
        gpioLine = gpiod::find_line(name);
        if (!gpioLine)
        {
            throw std::runtime_error("Failed to find GPIO line: " + name);
        }

        // Request events for the GPIO line
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES, INDEX_0});

        // Get the GPIO line file descriptor
        int gpioLineFd = gpioLine.event_get_fd();
        if (gpioLineFd < 0)
        {
            throw std::runtime_error(
                "Failed to get GPIO line file descriptor: " + name);
        }

        // Assign the file descriptor to gpioEventDescriptor
        gpioEventDescriptor.assign(gpioLineFd);

        // Set up asynchronous wait for events
        gpioEventDescriptor.async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            [&name, handler](const boost::system::error_code ec) {
                if (ec)
                {
                    throw std::runtime_error("Error in fd handler: " +
                                             ec.message());
                }
                handler();
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERROR}", "ERROR", e.what());
    }
}

void InterfaceManager::harvestDumps(ErrorType errorType)
{

    if (errorType == ERROR_TYPE_FATAL)
    {
        requestGPIOEvents(
            "P0_I3C_APML_ALERT_L",
            std::bind(&InterfaceManager::p0AlertEventHandler, this),
            p0_apmlAlertLine, p0_apmlAlertEvent);

        if (numOfCpu == TWO_SOCKET)
        {
            requestGPIOEvents(
                "P1_I3C_APML_ALERT_L",
                std::bind(&InterfaceManager::p1AlertEventHandler, this),
                p1_apmlAlertLine, p1_apmlAlertEvent);
        }
    }
}

void InterfaceManager::rasRecoveryAction(uint8_t buf)
{
    oob_status_t ret;
    uint32_t ack_resp = 0;

    AttributeValue SystemRecoveryVal = getAttribute("SystemRecovery");
    std::string* SystemRecovery = std::get_if<std::string>(&SystemRecoveryVal);

    if (*SystemRecovery == "WARM_RESET")
    {
        if ((buf & SYS_MGMT_CTRL_ERR))
        {
            triggerColdReset();
        }
        else
        {
            /* In a 2P config, it is recommended to only send this command to P0
            Hence, sending the Signal only to socket 0*/
            ret = reset_on_sync_flood(INDEX_0, &ack_resp);
            if (ret)
            {
                lg2::error("Failed to request reset after sync flood");
            }
            else
            {
                lg2::info("Warm reset triggered");
            }
        }
    }
    else if (*SystemRecovery == "COLD_RESET")
    {
        triggerColdReset();
    }
    else if (*SystemRecovery == "NO_RESET")
    {
        lg2::info("NO RESET triggered");
    }
    else
    {
        lg2::error("CdumpResetPolicy is not valid");
    }
}
