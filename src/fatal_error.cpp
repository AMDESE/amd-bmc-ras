#include "Config.hpp"
#include "cper.hpp"
#include "ras.hpp"

std::shared_ptr<CPER_RECORD> rcd;

std::mutex harvest_in_progress_mtx; // mutex for critical section

static bool P0_AlertProcessed = false;
static bool P1_AlertProcessed = false;
uint16_t DebugLogIdOffset;

uint32_t mca_status_lo = 0;
uint32_t mca_status_hi = 0;
uint32_t mca_ipid_lo = 0;
uint32_t mca_ipid_hi = 0;
uint32_t mca_synd_lo = 0;
uint32_t mca_synd_hi = 0;

int synd_lo_offset = 0;
int synd_hi_offset = 0;
int ipid_lo_offset = 0;
int ipid_hi_offset = 0;
int status_lo_offset = 0;
int status_hi_offset = 0;
bool ValidSignatureID = false;

#define HPM_FPGA_REGDUMP "/usr/sbin/hpm-fpga-dump.sh"
#define HPM_FPGA_REGDUMP_FILE "/var/lib/amd-ras/fpga_dump.txt"

void getLastTransAddr(uint8_t info)
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

                    if (info == p0_info)
                    {
                        rcd->P0_ErrorRecord.ContextInfo.DfDumpData
                            .LastTransAddr[n]
                            .WdtData[offset] = data;
                    }
                    else if (info == p1_info)
                    {
                        rcd->P1_ErrorRecord.ContextInfo.DfDumpData
                            .LastTransAddr[n]
                            .WdtData[offset] = data;
                    }
                }
                n++;
            }
        }
    }
}

void harvestDebugLogDump(uint8_t info, uint8_t blk_id)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    uint16_t apmlRetryCount = Configuration::getApmlRetryCount();

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

        if (retries > apmlRetryCount)
        {
            sd_journal_print(LOG_ERR,
                             "Socket %d: Failed to get valid debug log for Dbg "
                             "Log ID %d . Error: %d\n",
                             info, blk_id, ret);

            /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE
             * dump region*/
            if (info == p0_info)
            {
                rcd->P0_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = blk_id;
                rcd->P0_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
                rcd->P0_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
                rcd->P0_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
            }
            else if (info == p1_info)
            {
                rcd->P1_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = blk_id;
                rcd->P1_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
                rcd->P1_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
                rcd->P1_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = BAD_DATA;
            }
            break;
        }
    }

    if (ret == OOB_SUCCESS)
    {
        if (err_chk.df_block_instances != 0)
        {

            uint32_t DbgLogIdHeader =
                (static_cast<uint32_t>(err_chk.err_log_len) << INDEX_16) |
                (static_cast<uint32_t>(err_chk.df_block_instances) << INDEX_8) |
                static_cast<uint32_t>(blk_id);

            if (info == p0_info)
            {
                rcd->P0_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = DbgLogIdHeader;
            }
            else if (info == p1_info)
            {
                rcd->P1_ErrorRecord.ContextInfo
                    .DebugLogIdData[DebugLogIdOffset++] = DbgLogIdHeader;
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
                            uint16_t retryCount =
                                Configuration::getApmlRetryCount();
                            while (retryCount > 0)
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

                                if (ret == OOB_SUCCESS)
                                {
                                    break;
                                }
                                retryCount--;
                                usleep(1000 * 1000);
                            }

                            if (ret != OOB_SUCCESS)
                            {
                                sd_journal_print(LOG_ERR,
                                                 "Failed to read debug log "
                                                 "dump for debug log ID : %d\n",
                                                 blk_id);
                                data = BAD_DATA;
                                /*the Dump APML command fails in the middle of
                                  the iterative loop, then write BAADDA7A for
                                  the remaining iterations in the for loop*/
                                apmlHang = true;
                            }
                        }
                    }

                    if (info == p0_info)
                    {
                        rcd->P0_ErrorRecord.ContextInfo
                            .DebugLogIdData[DebugLogIdOffset++] = data;
                    }
                    else if (info == p1_info)
                    {
                        rcd->P1_ErrorRecord.ContextInfo
                            .DebugLogIdData[DebugLogIdOffset++] = data;
                    }
                }
                n++;
            }
        }
    }
}

template <typename T>
T GetProperty(sdbusplus::bus::bus& bus, const char* service, const char* path,
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

void requestHostTransition(std::string command)
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

void triggerRsmrstReset()
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
        "xyz.openbmc_project.State.Host",
        "/xyz/openbmc_project/control/host0/SOCReset",
        "xyz.openbmc_project.Control.Host.SOCReset", "SOCReset");

    sleep(1);
    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
    std::string CurrentHostState = GetProperty<std::string>(
        bus, "xyz.openbmc_project.State.Host",
        "/xyz/openbmc_project/state/host0", "xyz.openbmc_project.State.Host",
        "CurrentHostState");

    if (CurrentHostState.compare(
            "xyz.openbmc_project.State.Host.HostState.Off") == 0)
    {

        std::cout << "Doing host power on" << std::endl;
        std::string command = "xyz.openbmc_project.State.Host.Transition.On";

        requestHostTransition(command);
    }
}

void triggerSysReset()
{
    std::string command = "xyz.openbmc_project.State.Host.Transition.Reboot";

    requestHostTransition(command);
}

void triggerColdReset()
{
    if (Configuration::getResetSignal() == RSMRST)
    {
        sd_journal_print(LOG_INFO, "RSMRST RESET triggered\n");
        triggerRsmrstReset();
    }
    else if (Configuration::getResetSignal() == SYS_RESET)
    {
        sd_journal_print(LOG_INFO, "SYS RESET triggered\n");
        triggerSysReset();
    }
}

void write_register(uint8_t info, uint32_t reg, uint32_t value)
{
    oob_status_t ret;

    ret = esmi_oob_write_byte(info, reg, SBRMI, value);
    if (ret != OOB_SUCCESS)
    {
        sd_journal_print(LOG_ERR, "Failed to write register: 0x%x\n", reg);
        return;
    }
    sd_journal_print(LOG_DEBUG, "Write to register 0x%x is successful\n", reg);
}

void dump_processor_error_section(uint8_t info)
{

    rcd->P0_ErrorRecord.ProcError.ValidBits =
        CPU_ID_VALID | LOCAL_APIC_ID_VALID;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_0] = p0_eax;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_2] = p0_ebx;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_4] = p0_ecx;
    rcd->P0_ErrorRecord.ProcError.CpuId[INDEX_6] = p0_edx;
    rcd->P0_ErrorRecord.ProcError.CPUAPICId = ((p0_ebx >> SHIFT_24) & INT_255);

    if (num_of_proc == TWO_SOCKET)
    {
        rcd->P1_ErrorRecord.ProcError.ValidBits =
            CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_0] = p1_eax;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_2] = p1_ebx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_4] = p1_ecx;
        rcd->P1_ErrorRecord.ProcError.CpuId[INDEX_6] = p1_edx;
        rcd->P1_ErrorRecord.ProcError.CPUAPICId =
            ((p1_ebx >> SHIFT_24) & INT_255);
    }

    if (info == p0_info)
    {
        rcd->P0_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
    }
    if (info == p1_info)
    {
        rcd->P1_ErrorRecord.ProcError.ValidBits |= PROC_CONTEXT_STRUCT_VALID;
    }
}

void dump_context_info(uint16_t numbanks, uint16_t bytespermca, uint8_t info)
{

    getLastTransAddr(p0_info);

    uint8_t blk_id;

    DebugLogIdOffset = 0;

    for (blk_id = 0; blk_id < BlockId.size(); blk_id++)
    {
        harvestDebugLogDump(p0_info, BlockId[blk_id]);
    }

    if (num_of_proc == TWO_SOCKET)
    {
        getLastTransAddr(p1_info);

        DebugLogIdOffset = 0;

        for (blk_id = 0; blk_id < BlockId.size(); blk_id++)
        {
            harvestDebugLogDump(p1_info, BlockId[blk_id]);
        }
    }

    if (info == p0_info)
    {
        rcd->P0_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P0_ErrorRecord.ContextInfo.RegisterArraySize =
            numbanks * bytespermca;
    }
    else if (info == p1_info)
    {
        rcd->P1_ErrorRecord.ContextInfo.RegisterContextType = CTX_OOB_CRASH;
        rcd->P1_ErrorRecord.ContextInfo.RegisterArraySize =
            numbanks * bytespermca;
    }

    rcd->P0_ErrorRecord.ContextInfo.MicrocodeVersion = p0_ucode;
    rcd->P0_ErrorRecord.ContextInfo.Ppin = p0_ppin;

    if (num_of_proc == TWO_SOCKET)
    {
        rcd->P1_ErrorRecord.ContextInfo.MicrocodeVersion = p1_ucode;
        rcd->P1_ErrorRecord.ContextInfo.Ppin = p1_ppin;
    }
}

static bool harvest_mca_data_banks(uint8_t info, uint16_t numbanks,
                                   uint16_t bytespermca)
{
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t buffer;
    struct mca_bank mca_dump;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint32_t Severity;

    std::vector<std::string> sigIDOffset = Configuration::getSigIDOffset();

    dump_cper_header_section(rcd, FATAL_SECTION_COUNT, CPER_SEV_FATAL,
                             FATAL_ERR);

    dump_error_descriptor_section(rcd, INDEX_2, FATAL_ERR, &Severity);

    dump_processor_error_section(info);

    dump_context_info(numbanks, bytespermca, info);

    synd_lo_offset = std::stoul(sigIDOffset[INDEX_0], nullptr, BASE_16);
    synd_hi_offset = std::stoul(sigIDOffset[INDEX_1], nullptr, BASE_16);
    ipid_lo_offset = std::stoul(sigIDOffset[INDEX_2], nullptr, BASE_16);
    ipid_hi_offset = std::stoul(sigIDOffset[INDEX_3], nullptr, BASE_16);
    status_lo_offset = std::stoul(sigIDOffset[INDEX_4], nullptr, BASE_16);
    status_hi_offset = std::stoul(sigIDOffset[INDEX_5], nullptr, BASE_16);

    maxOffset32 =
        ((bytespermca % BYTE_4) ? INDEX_1 : INDEX_0) + (bytespermca >> BYTE_2);
    sd_journal_print(LOG_INFO, "Number of Valid MCA bank:%d\n", numbanks);
    sd_journal_print(LOG_INFO, "Number of 32 Bit Words:%d\n", maxOffset32);

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
                // retry
                uint16_t retryCount = Configuration::getApmlRetryCount();
                while (retryCount > 0)
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
                    retryCount--;
                    usleep(1000 * 1000);
                }
                if (ret != OOB_SUCCESS)
                {
                    sd_journal_print(LOG_ERR,
                                     "Socket %d : Failed to get MCA bank data "
                                     "from Bank:%d, Offset:0x%x\n",
                                     info, n, offset);
                    if (info == p0_info)
                    {
                        rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n]
                            .mca_data[offset] = BAD_DATA;
                    }
                    else if (info == p1_info)
                    {
                        rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n]
                            .mca_data[offset] = BAD_DATA;
                    }
                    continue;
                }

            } // if (ret != OOB_SUCCESS)

            if (info == p0_info)
            {
                rcd->P0_ErrorRecord.ContextInfo.CrashDumpData[n]
                    .mca_data[offset] = buffer;
            }
            else if (info == p1_info)
            {
                rcd->P1_ErrorRecord.ContextInfo.CrashDumpData[n]
                    .mca_data[offset] = buffer;
            }

            if (mca_dump.offset == status_lo_offset)
            {
                mca_status_lo = buffer;
            }
            if (mca_dump.offset == status_hi_offset)
            {
                mca_status_hi = buffer;

                /*Bit 23 and bit 25 of MCA_STATUS_HI
                  should be set for a valid signature ID*/
                if ((mca_status_hi & (INDEX_1 << SHIFT_25)) &&
                    (mca_status_hi & (INDEX_1 << SHIFT_23)))
                {
                    ValidSignatureID = true;
                }
            }
            if (mca_dump.offset == ipid_lo_offset)
            {
                mca_ipid_lo = buffer;
            }
            if (mca_dump.offset == ipid_hi_offset)
            {
                mca_ipid_hi = buffer;
            }
            if (mca_dump.offset == synd_lo_offset)
            {
                mca_synd_lo = buffer;
            }
            if (mca_dump.offset == synd_hi_offset)
            {
                mca_synd_hi = buffer;
            }

        } // for loop

        if (ValidSignatureID == true)
        {
            if (info == p0_info)
            {
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_0] =
                    mca_synd_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_1] =
                    mca_synd_hi;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_2] =
                    mca_ipid_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_3] =
                    mca_ipid_hi;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_4] =
                    mca_status_lo;
                rcd->P0_ErrorRecord.ProcError.SignatureID[INDEX_5] =
                    mca_status_hi;

                rcd->P0_ErrorRecord.ProcError.ValidBits =
                    rcd->P0_ErrorRecord.ProcError.ValidBits |
                    FAILURE_SIGNATURE_ID;
            }
            if (info == p1_info)
            {
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_0] =
                    mca_synd_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_1] =
                    mca_synd_hi;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_2] =
                    mca_ipid_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_3] =
                    mca_ipid_hi;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_4] =
                    mca_status_lo;
                rcd->P1_ErrorRecord.ProcError.SignatureID[INDEX_5] =
                    mca_status_hi;

                rcd->P1_ErrorRecord.ProcError.ValidBits =
                    rcd->P1_ErrorRecord.ProcError.ValidBits |
                    FAILURE_SIGNATURE_ID;
            }
            ValidSignatureID = false;
        }
        else
        {
            mca_synd_lo = 0;
            mca_synd_hi = 0;
            mca_ipid_lo = 0;
            mca_ipid_hi = 0;
            mca_status_lo = 0;
            mca_status_hi = 0;
        }
        n++;
    }

    return true;
}

static bool harvest_mca_validity_check(uint8_t info, uint16_t* numbanks,
                                       uint16_t* bytespermca)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    bool mac_validity_check = true;

    uint16_t apmlRetryCount = Configuration::getApmlRetryCount();

    while (ret != OOB_SUCCESS)
    {
        retries++;

        ret = read_bmc_ras_mca_validity_check(info, bytespermca, numbanks);

        if (retries > apmlRetryCount)
        {
            sd_journal_print(LOG_ERR,
                             "Socket %d: Failed to get MCA banks with valid "
                             "status. Error: %d\n",
                             info, ret);
            break;
        }

        if ((*numbanks == 0) || (*numbanks > MAX_MCA_BANKS))
        {
            sd_journal_print(LOG_ERR,
                             "Socket %d: Invalid MCA bank validity status. "
                             "Retry Count: %d\n",
                             info, retries);
            ret = OOB_MAILBOX_CMD_UNKNOWN;
            usleep(1000 * 1000);
            continue;
        }
    }

    if ((*numbanks <= 0) || (*numbanks > MAX_MCA_BANKS))
    {
        mac_validity_check = false;
    }

    return mac_validity_check;
}

void SystemRecovery(uint8_t buf)
{

    oob_status_t ret;
    uint32_t ack_resp = 0;

    if (Configuration::getSystemRecovery() == WARM_RESET)
    {
        if ((buf & SYS_MGMT_CTRL_ERR))
        {
            triggerColdReset();
        }
        else
        {
            /* In a 2P config, it is recommended to only send this command to P0
            Hence, sending the Signal only to socket 0*/
            ret = reset_on_sync_flood(p0_info, &ack_resp);
            if (ret)
            {
                sd_journal_print(LOG_ERR,
                                 "Failed to request reset after sync flood\n");
            }
            else
            {
                sd_journal_print(LOG_ERR, "WARM RESET triggered\n");
            }
        }
    }
    else if (Configuration::getSystemRecovery() == COLD_RESET)
    {
        triggerColdReset();
    }
    else if (Configuration::getSystemRecovery() == NO_RESET)
    {
        sd_journal_print(LOG_INFO, "NO RESET triggered\n");
    }
    else
    {
        sd_journal_print(LOG_ERR, "CdumpResetPolicy is not valid\n");
    }
}

void harvest_fatal_errors(uint8_t info, uint16_t numbanks, uint16_t bytespermca)
{
    // RAS MCA Validity Check
    if (true == harvest_mca_validity_check(info, &numbanks, &bytespermca))
    {
        harvest_mca_data_banks(info, numbanks, bytespermca);
    }
}

bool harvest_ras_errors(uint8_t info, std::string alert_name)
{
    std::unique_lock lock(harvest_in_progress_mtx);

    uint16_t bytespermca = 0;
    uint16_t numbanks = 0;
    bool ControlFabricError = false;
    bool FchHangError = false;
    uint8_t buf;
    bool ResetReady = false;
    bool RuntimeError = false;

    // Check if APML ALERT is because of RAS
    if (read_sbrmi_ras_status(info, &buf) == OOB_SUCCESS)
    {
        sd_journal_print(LOG_DEBUG, "Read RAS status register. Value: 0x%x\n",
                         buf);

        // check RAS Status Register
        if (buf & INT_15)
        {
            sd_journal_print(
                LOG_INFO, "The alert signaled is due to a RAS fatal error\n");

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

                P0_AlertProcessed = true;
                P1_AlertProcessed = true;
                ControlFabricError = true;
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

                FchHangError = true;
            }
            else if (buf & MCA_ERR_OVERFLOW)
            {

                RunTimeErrorInfoCheck(MCA_ERR, INTERRUPT_MODE);

                std::string mca_err_overflow_msg =
                    "MCA runtime error counter overflow occured";

                sd_journal_send("MESSAGE=%s", mca_err_overflow_msg.c_str(),
                                "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                                "OpenBMC.0.1.CPUError",
                                "REDFISH_MESSAGE_ARGS=%s",
                                mca_err_overflow_msg.c_str(), NULL);

                RuntimeError = true;
            }
            else if (buf & DRAM_CECC_ERR_OVERFLOW)
            {
                RunTimeErrorInfoCheck(DRAM_CECC_ERR, INTERRUPT_MODE);

                std::string dram_err_overflow_msg =
                    "DRAM CECC runtime error counter overflow occured";

                sd_journal_send("MESSAGE=%s", dram_err_overflow_msg.c_str(),
                                "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                                "OpenBMC.0.1.CPUError",
                                "REDFISH_MESSAGE_ARGS=%s",
                                dram_err_overflow_msg.c_str(), NULL);

                RuntimeError = true;
            }
            else if (buf & PCIE_ERR_OVERFLOW)
            {

                RunTimeErrorInfoCheck(PCIE_ERR, INTERRUPT_MODE);

                std::string pcie_err_overflow_msg =
                    "PCIE runtime error counter overflow occured";

                sd_journal_send("MESSAGE=%s", pcie_err_overflow_msg.c_str(),
                                "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                                "OpenBMC.0.1.CPUError",
                                "REDFISH_MESSAGE_ARGS=%s",
                                pcie_err_overflow_msg.c_str(), NULL);

                RuntimeError = true;
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

                harvest_fatal_errors(info, numbanks, bytespermca);
            }

            if (alert_name.compare("P0_ALERT") == 0)
            {
                P0_AlertProcessed = true;
            }

            if (alert_name.compare("P1_ALERT") == 0)
            {
                P1_AlertProcessed = true;
            }

            // Clear RAS status register
            // 0x4c is a SB-RMI register acting as write to clear
            // check PPR to determine whether potential bug in PPR or in
            // implementation of SMU?
            write_register(info, RAS_STATUS_REGISTER, buf);

            if (FchHangError == true || RuntimeError == true)
            {
                return true;
            }

            if (num_of_proc == TWO_SOCKET)
            {
                if ((P0_AlertProcessed == true) && (P1_AlertProcessed == true))
                {
                    ResetReady = true;
                }
            }
            else
            {
                ResetReady = true;
            }

            if (ResetReady == true)
            {

                if (ControlFabricError == false)
                {
                    write_to_cper_file(rcd, FATAL_ERR, INDEX_2);
                }

                rcd = nullptr;

                SystemRecovery(buf);

                P0_AlertProcessed = false;
                P1_AlertProcessed = false;
            }
        }
    }
    else
    {
        sd_journal_print(LOG_DEBUG, "Nothing to Harvest. Not RAS Error\n");
    }

    return true;
}

/* Schedule a wait event */
void P0AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Falling Edge: P0 APML Alert received\n");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p0_info, "P0_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Rising Edge: P0 APML Alert cancelled\n");
    }

    P0_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "P0 APML alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P0AlertEventHandler();
        });
}

void P1AlertEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_apmlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Falling Edge: P1 APML Alert received\n");

        if (rcd == nullptr)
        {
            rcd = std::make_shared<CPER_RECORD>();
        }

        harvest_ras_errors(p1_info, "P1_ALERT");
    }
    else if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        sd_journal_print(LOG_DEBUG, "Rising Edge: P1 APML Alert cancelled\n");
    }
    P1_apmlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "P1 APML alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P1AlertEventHandler();
        });
}

void P0PmicAfEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_pmicAfAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg =
            "P0 DIMM A-F PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG,
                         "Rising Edge: P0 PMIC DIMM A-F Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P0_pmicAfAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR,
                                 "P0 PMIC DIMM A-F alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P0PmicAfEventHandler();
        });
}

void P0PmicGlEventHandler()
{
    gpiod::line_event gpioLineEvent = P0_pmicGlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg =
            "P0 DIMM G-L PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG,
                         "Rising Edge: P0 PMIC DIMM G-L Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P0_pmicGlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR,
                                 "P0 PMIC DIMM G-L alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P0PmicGlEventHandler();
        });
}

void P1PmicAfEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_pmicAfAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg =
            "P1 DIMM A-F PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG,
                         "Rising Edge: P1 PMIC DIMM A-F Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P1_pmicAfAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR,
                                 "P1 PMIC DIMM A-F alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P1PmicAfEventHandler();
        });
}

void P1PmicGlEventHandler()
{
    gpiod::line_event gpioLineEvent = P1_pmicGlAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg =
            "P1 DIMM G-L PMIC FATAL Error detected. System will be power off";
        sd_journal_print(LOG_DEBUG,
                         "Rising Edge: P1 PMIC DIMM G-L Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
    }

    P1_pmicGlAlertEvent.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR,
                                 "P1 PMIC DIMM G-L alert handler error: %s\n",
                                 ec.message().c_str());
                return;
            }
            P1PmicGlEventHandler();
        });
}

void HPMFPGALockoutEventHandler()
{
    gpiod::line_event gpioLineEvent = HPMFPGALockoutAlertLine.event_read();

    if (gpioLineEvent.event_type == gpiod::line_event::RISING_EDGE)
    {
        std::string ras_err_msg =
            "HPM FPGA detected fatal error."
            "FPGA registers dumped to " HPM_FPGA_REGDUMP_FILE
            "A/C power cycle to recover";
        sd_journal_print(LOG_DEBUG,
                         "Rising Edge: HPM FPGA lockout Alert received\n");
        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);
        int ret = system("HPM_FPGA_REGDUMP > " HPM_FPGA_REGDUMP_FILE " 2>&1 &");

        if (ret == -1)
        {
            sd_journal_print(LOG_ERR,
                             "Failed to triggerhpm fpga register dump\n");
        }
    }
}

bool requestGPIOEvents(
    const std::string& name, const std::function<void()>& handler,
    gpiod::line& gpioLine,
    boost::asio::posix::stream_descriptor& gpioEventDescriptor)
{
    // Find the GPIO line
    gpioLine = gpiod::find_line(name);
    if (!gpioLine)
    {
        sd_journal_print(LOG_ERR, "Failed to find gpio line %s \n",
                         name.c_str());
        return false;
    }

    try
    {
        gpioLine.request(
            {"RAS", gpiod::line_request::EVENT_BOTH_EDGES, INDEX_0});
    }
    catch (std::exception& exc)
    {
        sd_journal_print(
            LOG_ERR,
            "Failed to request events for gpio line %s, exception: %s \n",
            name.c_str(), exc.what());
        return false;
    }

    int gpioLineFd = gpioLine.event_get_fd();
    if (gpioLineFd < 0)
    {
        sd_journal_print(LOG_ERR, "Failed to get gpio line %s fd\n",
                         name.c_str());
        return false;
    }

    gpioEventDescriptor.assign(gpioLineFd);

    gpioEventDescriptor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [&name, handler](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error: %s \n",
                                 ec.message().c_str());
                // TODO: throw here to force power-control to restart?
                return;
            }
            handler();
        });

    return true;
}
