#include "apml_manager.hpp"

#include <phosphor-logging/lg2.hpp>

#include <fstream>

constexpr int EPYC_PROG_SEG_ID = 0x01;
constexpr int FAILURE_SIGNATURE_ID = 0x04;
constexpr int FATAL_ERROR = 1;
constexpr int FATAL_SECTION_COUNT = 2;
constexpr int SYS_MGMT_CTRL_ERR = 0x04;
constexpr int RESET_HANG_ERR = 0x02;
constexpr int SBRMI_CONTROL_REGISTER = 0x1;
constexpr int SHIFT_23 = 23;
constexpr int SHIFT_25 = 25;
constexpr int TWO_SOCKET = 2;
constexpr char EVENT_SUBSCRIPTION_FILE[] =
    "/var/lib/bmcweb/eventservice_config.json";

enum BlockID : unsigned short
{
    BLOCK_ID_1 = 1,
    BLOCK_ID_2,
    BLOCK_ID_3,
    BLOCK_ID_23 = 23,
    BLOCK_ID_24,
    BLOCK_ID_33 = 33,
    BLOCK_ID_36,
    BLOCK_ID_37,
    BLOCK_ID_38,
    BLOCK_ID_39,
    BLOCK_ID_40
};

void ApmlInterfaceManager::init()
{
    getNumberOfCpu();

    interfaceActiveMonitor();

    getCpuId();

    getBoardId();

    findProgramId();
}

void ApmlInterfaceManager::configure()
{
    createIndexFile();

    createConfigFile();

    // Retrieve microcode version attribute and check if it's a boolean
    AttributeValue uCodeVersion = getAttribute("HarvestMicrocode");
    bool* uCodeVersionFlag = std::get_if<bool>(&uCodeVersion);

    // Retrieve PPIN attribute and check if it's a boolean
    AttributeValue harvestPpin = getAttribute("HarvestPPIN");
    bool* harvestPpinFlag = std::get_if<bool>(&harvestPpin);

    // If microcode harvesting is enabled, retrieve microcode revision
    if (*uCodeVersionFlag == true)
    {
        getMicrocodeRev();
    }

    // If PPIN harvesting is enabled, retrieve PPIN fuse
    if (*harvestPpinFlag == true)
    {
        getPpinFuse();
    }

    // Request GPIO events for P0 alert handling
    requestGPIOEvents("P0_I3C_APML_ALERT_L",
                      std::bind(&RasManagerBase::p0AlertEventHandler, this),
                      p0_apmlAlertLine, p0_apmlAlertEvent);

    // Request GPIO events for P1 alert handling
    if (numOfCpu == TWO_SOCKET)
    {
        requestGPIOEvents("P1_I3C_APML_ALERT_L",
                          std::bind(&RasManagerBase::p1AlertEventHandler, this),
                          p1_apmlAlertLine, p1_apmlAlertEvent);
    }
}

void ApmlInterfaceManager::interfaceActiveMonitor()
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
}

void ApmlInterfaceManager::writeRegister(uint8_t info, uint32_t reg,
                                         uint32_t value)
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

void ApmlInterfaceManager::triggerWarmReset()
{
    oob_status_t ret;
    uint32_t ack_resp = 0;
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

oob_status_t ApmlInterfaceManager::readRegister(uint8_t info, uint32_t reg,
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

void ApmlInterfaceManager::clearSbrmiAlertMask(uint8_t socNum)
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

void ApmlInterfaceManager::performPlatformInitialization()
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    struct processor_info platInfo[INDEX_1];

    while (ret != OOB_SUCCESS)
    {
        uint8_t soc_num = 0;
        ret = esmi_get_processor_info(soc_num, platInfo);

        if (ret == OOB_SUCCESS)
        {
            familyId = platInfo->family;
            break;
        }
        sleep(INDEX_1);
    }

    if (ret == OOB_SUCCESS)
    {
        if (platInfo->family == GENOA_FAMILY_ID)
        {
            blockId = {BLOCK_ID_33};
        }
        else if (platInfo->family == TURIN_FAMILY_ID)
        {
            for (uint8_t i = 0; i < numOfCpu; i++)
            {
                clearSbrmiAlertMask(i);
            }

            blockId = {BLOCK_ID_1,  BLOCK_ID_2,  BLOCK_ID_3,  BLOCK_ID_23,
                       BLOCK_ID_24, BLOCK_ID_33, BLOCK_ID_36, BLOCK_ID_37,
                       BLOCK_ID_38, BLOCK_ID_40};
        }
    }
    else
    {
        sd_journal_print(LOG_ERR,
                         "Failed to perform platform initialization\n");
    }
}

void ApmlInterfaceManager::getCpuId()
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

void ApmlInterfaceManager::findProgramId()
{
    oob_status_t ret;
    uint8_t socNum = 0;

    struct processor_info platInfo[INDEX_1];

    ret = esmi_get_processor_info(socNum, platInfo);

    if (ret == OOB_SUCCESS)
    {
        progId = EPYC_PROG_SEG_ID;
    }
}

bool ApmlInterfaceManager::harvestMcaValidityCheck(
    uint8_t info, uint16_t* numbanks, uint16_t* bytespermca)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    bool mcaValidityCheck = true;

    AttributeValue apmlRetry = getAttribute("ApmlRetries");
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

inline std::string getCperFilename(int num)
{
    return "ras-error" + std::to_string(num) + ".cper";
}

void ApmlInterfaceManager::getLastTransAddr(
    EFI_AMD_FATAL_ERROR_DATA* fatal_error_data, uint8_t info)
{
    oob_status_t ret;
    uint8_t blk_id = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    ret = read_ras_df_err_validity_check(info, blk_id, &err_chk);

    if (ret)
    {
        sd_journal_print(LOG_ERR, "Failed to read RAS DF validity check\n");
    }
    else
    {
        if (err_chk.df_block_instances != 0)
        {
            maxOffset32 = ((err_chk.err_log_len % BYTE_4) ? INDEX_1 : INDEX_0) +
                          (err_chk.err_log_len >> BYTE_2);
            while (n < err_chk.df_block_instances)
            {
                for (int offset = 0; offset < maxOffset32; offset++)
                {
                    memset(&data, 0, sizeof(data));
                    /* Offset */
                    df_err.input[INDEX_0] = offset * BYTE_4;
                    /* DF block ID */
                    df_err.input[INDEX_1] = blk_id;
                    /* DF block ID instance */
                    df_err.input[INDEX_2] = n;

                    ret = read_ras_df_err_dump(info, df_err, &data);

                    if (ret != OOB_SUCCESS)
                    {
                        // retry
                        AttributeValue apmlRetry = getAttribute("ApmlRetries");
                        int64_t* retryCount = std::get_if<int64_t>(&apmlRetry);
                        int64_t retries = 0;
                        while (ret != OOB_SUCCESS)
                        {
                            retries++;
                            memset(&data, 0, sizeof(data));
                            memset(&df_err, 0, sizeof(df_err));

                            /* Offset */
                            df_err.input[INDEX_0] = offset * BYTE_4;
                            /* DF block ID */
                            df_err.input[INDEX_1] = blk_id;
                            /* DF block ID instance */
                            df_err.input[INDEX_2] = n;

                            ret = read_ras_df_err_dump(info, df_err, &data);

                            if (retries > *retryCount)
                            {
                                break;
                            }
                            sleep(INDEX_1);
                        }

                        if (ret != OOB_SUCCESS)
                        {
                            data = 0;
                        }
                    }
                    fatal_error_data->DfDumpData.LastTransAddr[n]
                        .WdtData[offset] = data;
                }
                n++;
            }
        }
    }
}

void ApmlInterfaceManager::harvestDebugLogDump(
    EFI_AMD_FATAL_ERROR_DATA* fatal_error_data, uint8_t info, uint8_t blk_id)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    AttributeValue apmlRetry = getAttribute("ApmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_ras_df_err_validity_check(info, blk_id, &err_chk);

        if (ret == OOB_SUCCESS)
        {
            sd_journal_print(LOG_INFO,
                             "Socket : %d , Debug Log ID : %d , Block Instance "
                             "= %d, Err Log Length = %d\n",
                             info, blk_id, err_chk.df_block_instances,
                             err_chk.err_log_len);
            break;
        }

        if (retries > *apmlRetryCount)
        {
            sd_journal_print(LOG_ERR,
                             "Socket %d: Failed to get valid debug log for Dbg "
                             "Log ID %d . Error: %d\n",
                             info, blk_id, ret);

            /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE
             * dump region*/
            fatal_error_data->DebugLogIdData[debugLogIdOffset++] = blk_id;
            fatal_error_data->DebugLogIdData[debugLogIdOffset++] = BAD_DATA;
            fatal_error_data->DebugLogIdData[debugLogIdOffset++] = BAD_DATA;
            fatal_error_data->DebugLogIdData[debugLogIdOffset++] = BAD_DATA;
            break;
        }
    }

    if (ret == OOB_SUCCESS)
    {
        if (err_chk.df_block_instances != 0)
        {
            uint16_t n = 0;
            uint16_t maxOffset32;

            uint32_t DbgLogIdHeader =
                (static_cast<uint32_t>(err_chk.err_log_len) << INDEX_16) |
                (static_cast<uint32_t>(err_chk.df_block_instances) << INDEX_8) |
                static_cast<uint32_t>(blk_id);

            if (info == SOCKET_0)
            {
                fatal_error_data->DebugLogIdData[debugLogIdOffset++] =
                    DbgLogIdHeader;
            }
            else if (info == SOCKET_1)
            {
                fatal_error_data->DebugLogIdData[debugLogIdOffset++] =
                    DbgLogIdHeader;
            }

            maxOffset32 = ((err_chk.err_log_len % BYTE_4) ? INDEX_1 : INDEX_0) +
                          (err_chk.err_log_len >> BYTE_2);

            while (n < err_chk.df_block_instances)
            {
                bool apmlHang = false;

                for (int offset = 0; offset < maxOffset32; offset++)
                {
                    if (apmlHang == false)
                    {
                        memset(&data, 0, sizeof(data));
                        memset(&df_err, 0, sizeof(df_err));

                        /* Offset */
                        df_err.input[INDEX_0] = offset * BYTE_4;
                        /* DF block ID */
                        df_err.input[INDEX_1] = blk_id;
                        /* DF block ID instance */
                        df_err.input[INDEX_2] = n;

                        ret = read_ras_df_err_dump(info, df_err, &data);

                        if (ret != OOB_SUCCESS)
                        {
                            // retry
                            AttributeValue apmlRetry =
                                getAttribute("ApmlRetries");
                            int64_t* retryCount =
                                std::get_if<int64_t>(&apmlRetry);
                            int64_t retries = 0;
                            while (ret != OOB_SUCCESS)
                            {
                                retries++;
                                memset(&data, 0, sizeof(data));
                                memset(&df_err, 0, sizeof(df_err));

                                /* Offset */
                                df_err.input[INDEX_0] = offset * BYTE_4;
                                /* DF block ID */
                                df_err.input[INDEX_1] = blk_id;
                                /* DF block ID instance */
                                df_err.input[INDEX_2] = n;

                                ret = read_ras_df_err_dump(info, df_err, &data);

                                if (retries > *retryCount)
                                {
                                    break;
                                }
                                sleep(INDEX_1);
                            }

                            if (ret != OOB_SUCCESS)
                            {
                                sd_journal_print(LOG_ERR,
                                                 "Failed to read debug log "
                                                 "dump for debug log ID : %d\n",
                                                 blk_id);
                                data = BAD_DATA;
                                /*the Dump APML command fails in the middle
                                  of the iterative loop, then write BAADDA7A
                                  for the remaining iterations in the for
                                  loop*/
                                apmlHang = true;
                            }
                        }
                    }

                    if (info == SOCKET_0)
                    {
                        fatal_error_data->DebugLogIdData[debugLogIdOffset++] =
                            data;
                    }
                    else if (info == SOCKET_1)
                    {
                        fatal_error_data->DebugLogIdData[debugLogIdOffset++] =
                            data;
                    }
                }
                n++;
            }
        }
    }
}

void ApmlInterfaceManager::dumpContextInfo(
    EFI_AMD_FATAL_ERROR_DATA* fatal_error_data, uint8_t info)
{
    if ((info == SOCKET_1) && (numOfCpu != TWO_SOCKET))
    {
        return;
    }

    getLastTransAddr(fatal_error_data, info);

    uint8_t blk_id;

    debugLogIdOffset = 0;

    for (blk_id = 0; blk_id < blockId.size(); blk_id++)
    {
        harvestDebugLogDump(fatal_error_data, info, blockId[blk_id]);
    }
}

template <typename T>
void ApmlInterfaceManager::harvestMcaDataBanks(uint8_t info, uint16_t numbanks,
                                               uint16_t bytespermca,
                                               CperGenerator<T>& cperGenerator)
{
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
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

    AttributeValue sigIdOffsetVal = getAttribute("SigIdOffset");
    std::vector<std::string>* sigIDOffset =
        std::get_if<std::vector<std::string>>(&sigIdOffsetVal);

    AttributeValue apmlRetry = getAttribute("ApmlRetries");
    int64_t* apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

    cperGenerator.dumpCperHeaderSection(rcd, FATAL_SECTION_COUNT,
                                        CPER_SEV_FATAL, FATAL_ERR);

    rcd->sectionDescriptor =
        new EFI_ERROR_SECTION_DESCRIPTOR[FATAL_SECTION_COUNT];
    std::memset(rcd->sectionDescriptor, 0,
                FATAL_SECTION_COUNT * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));

    rcd->errorRecord = new EFI_AMD_FATAL_ERROR_DATA[FATAL_SECTION_COUNT];
    std::memset(rcd->errorRecord, 0,
                FATAL_SECTION_COUNT * sizeof(EFI_AMD_FATAL_ERROR_DATA));

    cperGenerator.dumpErrorDescriptorSection(rcd, FATAL_SECTION_COUNT,
                                             FATAL_ERR);

    cperGenerator.dumpProcessorErrorSection(rcd, info, cpuId);

    cperGenerator.dumpContextInfo(rcd, numbanks, bytespermca, info, blockId,
                                  ppin, uCode, apmlRetryCount);

    syndOffsetLo = std::stoul((*sigIDOffset)[INDEX_0], nullptr, BASE_16);
    syndOffsetHi = std::stoul((*sigIDOffset)[INDEX_1], nullptr, BASE_16);
    ipidOffsetLo = std::stoul((*sigIDOffset)[INDEX_2], nullptr, BASE_16);
    ipidOffsetHi = std::stoul((*sigIDOffset)[INDEX_3], nullptr, BASE_16);
    statusOffsetLo = std::stoul((*sigIDOffset)[INDEX_4], nullptr, BASE_16);
    statusOffsetHi = std::stoul((*sigIDOffset)[INDEX_5], nullptr, BASE_16);

    maxOffset32 = ((bytespermca % BYTE_4) ? INDEX_1 : INDEX_0) +
                  (bytespermca >> BYTE_2);
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
                    rcd->errorRecord[info].CrashDumpData[n].McaData[offset] =
                        BAD_DATA; // Write BAADDA7A pattern on error
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            rcd->errorRecord[info].CrashDumpData[n].McaData[offset] = buffer;

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
            rcd->errorRecord[info].SignatureID[INDEX_0] = mcaSyndLo;
            rcd->errorRecord[info].SignatureID[INDEX_1] = mcaSyndHi;
            rcd->errorRecord[info].SignatureID[INDEX_2] = mcaIpidLo;
            rcd->errorRecord[info].SignatureID[INDEX_3] = mcaIpidHi;
            rcd->errorRecord[info].SignatureID[INDEX_4] = mcaStatusLo;
            rcd->errorRecord[info].SignatureID[INDEX_5] = mcaStatusHi;

            rcd->errorRecord[info].ProcError.ValidFields =
                rcd->errorRecord[info].ProcError.ValidFields |
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

void ApmlInterfaceManager::harvestFatalError(uint8_t info)
{
    std::unique_lock lock(harvest_in_progress_mtx);

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;
    bool controlFabricError = false;
    bool fchHangError = false;
    uint8_t buf;
    bool resetReady = false;

    CperGenerator<FatalCperRecord> cperGenerator(numOfCpu, progId, familyId,
                                                 errCount);

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {
        lg2::debug("Read RAS status register. Value: {BUF}", "BUF", buf);

        // check RAS Status Register
        if (buf & INT_255)
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
                    // Create CPER file and write CPER data to the file
                    cperGenerator.cperFileWrite(rcd, FATAL_ERR,
                                                FATAL_SECTION_COUNT);
                }

                bool recoveryAction = true;

                AttributeValue aifsArmed = getAttribute("AifsArmed");
                bool* aifsArmedFlag = std::get_if<bool>(&aifsArmed);

                if ((*aifsArmedFlag == true) &&
                    (checkSignatureIdMatch() == true))
                {
                    sd_journal_print(LOG_INFO, "AIFS armed for the system\n");

                    std::ifstream inputFile(EVENT_SUBSCRIPTION_FILE);

                    /*Check if there is any active subscriptions for
                      the local AIFS flow*/
                    if (inputFile.is_open())
                    {
                        nlohmann::json jsonData;
                        inputFile >> jsonData;

                        if (jsonData.find("Subscriptions") != jsonData.end())
                        {
                            const auto& subscriptionsArray =
                                jsonData["Subscriptions"];
                            if (subscriptionsArray.is_array())
                            {
                                for (const auto& subscription :
                                     subscriptionsArray)
                                {
                                    const auto& messageIds =
                                        subscription["MessageIds"];
                                    if (messageIds.is_array())
                                    {
                                        bool messageIdFound = std::any_of(
                                            messageIds.begin(),
                                            messageIds.end(),
                                            [](const std::string& messageId) {
                                                return messageId ==
                                                       "AifsFailureMatch";
                                            });
                                        if (messageIdFound)
                                        {
                                            recoveryAction = false;

                                            struct ras_override_delay d_in = {
                                                0, 0, 0};
                                            bool ack_resp;
                                            d_in.stop_delay_counter = 1;
                                            oob_status_t ret;

                                            AttributeValue disableResetCounter =
                                                getAttribute(
                                                    "DisableAifsResetOnSyncfloodCounter");
                                            bool* disableResetCntr =
                                                std::get_if<bool>(
                                                    &disableResetCounter);

                                            if (*disableResetCntr == true)
                                            {
                                                sd_journal_print(
                                                    LOG_INFO,
                                                    "Disable Aifs Delay "
                                                    "Reset on Syncflood "
                                                    "counter is true. "
                                                    "Sending Delay Reset "
                                                    "on Syncflood override "
                                                    "APML command\n");
                                                ret =
                                                    override_delay_reset_on_sync_flood(
                                                        info, d_in, &ack_resp);

                                                if (ret)
                                                {
                                                    sd_journal_print(
                                                        LOG_ERR,
                                                        "Failed to "
                                                        "override "
                                                        "delay value reset "
                                                        "on "
                                                        "syncflood "
                                                        "Err[%d]: %s \n",
                                                        ret,
                                                        esmi_get_err_msg(ret));
                                                }
                                                else
                                                {
                                                    sd_journal_print(
                                                        LOG_INFO,
                                                        "Successfully sent "
                                                        "Reset delay on "
                                                        "Syncflood "
                                                        "command\n");
                                                }
                                            }
                                            sd_journal_send(
                                                "PRIORITY=%i", LOG_INFO,
                                                "REDFISH_MESSAGE_ID=%s",
                                                "OpenBMC.0.1."
                                                "AifsFailureMatch",
                                                NULL);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        inputFile.close();
                    }
                }
                if (recoveryAction == true)
                {
                    rasRecoveryAction(buf);
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

std::vector<uint32_t>
    ApmlInterfaceManager::hexstring_to_vector(const std::string& hexString)
{
    std::vector<uint32_t> result;

    // Skip the "0x" prefix if present
    size_t start =
        (hexString.substr(INDEX_0, INDEX_2) == "0x") ? INDEX_2 : INDEX_0;

    // Process the string in chunks of 8 characters (32 bits)
    for (size_t i = start; i < hexString.length(); i += INDEX_8)
    {
        std::string chunk = hexString.substr(i, INDEX_8);
        std::istringstream iss(chunk);
        uint32_t value = 0;
        iss >> std::hex >> value;
        if (iss)
        {
            result.push_back(value);
        }
        else
        {
            break;
        }
    }

    // Pad the result vector with leading zeros if necessary
    while (result.size() < 8)
    {
        result.insert(result.begin(), 0);
    }

    return result;
}

bool ApmlInterfaceManager::compare_with_bitwise_AND(
    const uint32_t* Var, const std::string& hexString)
{
    std::vector<uint32_t> hexVector = hexstring_to_vector(hexString);
    std::vector<uint32_t> result(8);

    // Pad the Var array with leading zeros if necessary
    std::vector<uint32_t> varVector(8);

    std::copy(Var, Var + 8, varVector.begin());

    // Reverse the order of elements in varVector
    std::reverse(varVector.begin(), varVector.end());

    // Perform the bitwise AND operation
    for (size_t i = 0; i < 8; i++)
    {
        result[i] = varVector[i] & hexVector[i];
    }

    // Compare the result with the original hexVector
    return std::equal(result.begin(), result.end(), hexVector.begin(),
                      hexVector.end());
}

bool ApmlInterfaceManager::checkSignatureIdMatch()
{
    bool ret = false;

    AttributeValue configSigId = getAttribute("AifsSignatureId");
    std::map<std::string, std::string>* configSigIdList =
        std::get_if<std::map<std::string, std::string>>(&configSigId);

    uint32_t P0_tempVar[8];
    std::memcpy(P0_tempVar, SignatureID, sizeof(P0_tempVar));

    uint32_t P1_tempVar[8];
    std::memcpy(P1_tempVar, SignatureID, sizeof(P1_tempVar));

    for (const auto& pair : *configSigIdList)
    {
        bool equal = compare_with_bitwise_AND(P0_tempVar, pair.second);

        if (equal == true)
        {
            sd_journal_print(LOG_INFO, "Signature ID matched with the config "
                                       "file signature ID list\n");
            ret = true;
            break;
        }

        equal = compare_with_bitwise_AND(P1_tempVar, pair.second);
        if (equal == true)
        {
            sd_journal_print(LOG_INFO, "Signature ID matched with the config "
                                       "file signature ID list\n");
            ret = true;
            break;
        }
    }
    return ret;
}
