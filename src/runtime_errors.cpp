#include "Config.hpp"
#include "cper.hpp"
#include "cper_runtime.hpp"
#include "ras.hpp"

std::shared_ptr<PROC_RUNTIME_ERR_RECORD> mca_ptr = nullptr;
std::shared_ptr<PROC_RUNTIME_ERR_RECORD> dram_ptr = nullptr;
std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> pcie_ptr = nullptr;

std::mutex mca_error_harvest_mtx;
std::mutex dram_error_harvest_mtx;
std::mutex pcie_error_harvest_mtx;

oob_status_t RunTimeErrValidityCheck(uint8_t soc_num,
                                     struct ras_rt_err_req_type rt_err_category,
                                     struct ras_rt_valid_err_inst* inst)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    if (apmlInitialized == true)
    {
        ret = get_bmc_ras_run_time_err_validity_ck(soc_num, rt_err_category,
                                                   inst);
        if (ret)
        {
            sd_journal_print(
                LOG_DEBUG,
                "Failed to get bmc ras runtime error validity check\n");
        }
    }

    return ret;
}

oob_status_t SetErrThreshold()
{
    oob_status_t ret = OOB_NOT_SUPPORTED;
    struct run_time_threshold th;

    memset(&th, 0, sizeof(th));

    if (Configuration::getMcaThresholdEn() == true)
    {
        th.err_type = 0; /*00 = MCA error type*/
        th.err_count_th = Configuration::getMcaErrCounter();
        th.max_intrupt_rate = 1;

        ret = set_bmc_ras_err_threshold(p0_info, th);

        if (ret != OOB_SUCCESS)
        {
            sd_journal_print(
                LOG_INFO,
                "Failed to set MCA error threshold for processor P0\n");
        }
        if (num_of_proc == TWO_SOCKET)
        {
            ret = set_bmc_ras_err_threshold(p1_info, th);

            if (ret != OOB_SUCCESS)
            {
                sd_journal_print(
                    LOG_INFO,
                    "Failed to set MCA error threshold for processor P1\n");
            }
        }
    }
    if (Configuration::getDramCeccThresholdEn() == true)
    {
        th.err_type = 1; /*01 = DRAM CECC error type*/
        th.err_count_th = Configuration::getDramCeccErrCounter();
        th.max_intrupt_rate = 1;

        ret = set_bmc_ras_err_threshold(p0_info, th);

        if (ret != OOB_SUCCESS)
        {
            sd_journal_print(
                LOG_INFO,
                "Failed to set DRAM CECC error threshold for processor P0\n");
        }

        if (num_of_proc == TWO_SOCKET)
        {
            ret = set_bmc_ras_err_threshold(p1_info, th);

            if (ret != OOB_SUCCESS)
            {
                sd_journal_print(LOG_INFO, "Failed to set DRAM CECC error "
                                           "threshold for processor P1\n");
            }
        }
    }
    if (Configuration::getPcieAerThresholdEn() == true)
    {
        th.err_type = 2; /*00 = PCIE error type*/
        th.err_count_th = Configuration::getPcieAerErrCounter();
        th.max_intrupt_rate = 1;

        ret = set_bmc_ras_err_threshold(p0_info, th);

        if (ret != OOB_SUCCESS)
        {
            sd_journal_print(
                LOG_INFO,
                "Failed to set PCIE  error threshold for processor P0\n");
        }

        if (num_of_proc == TWO_SOCKET)
        {
            ret = set_bmc_ras_err_threshold(p1_info, th);

            if (ret != OOB_SUCCESS)
            {
                sd_journal_print(
                    LOG_INFO,
                    "Failed to set PCIE error threshold for processor P1\n");
            }
        }
    }
    return ret;
}

oob_status_t SetOobConfig()
{
    oob_status_t ret;
    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));

    if (Configuration::getMcaPollingEn() == true)
    {
        /* Core MCA OOB Error Reporting Enable */
        oob_config.core_mca_err_reporting_en = ENABLE_BIT;
    }

    if (Configuration::getDramCeccPollingEn() == true)
    {
        /* DRAM CECC OOB Error Counter Mode */
        oob_config.core_mca_err_reporting_en = ENABLE_BIT;
        oob_config.dram_cecc_oob_ec_mode =
            ENABLE_BIT; /*Enabled in No leak mode*/
    }

    if (Configuration::getPcieAerPollingEn() == true)
    {
        /* PCIe OOB Error Reporting Enable */
        oob_config.pcie_err_reporting_en = ENABLE_BIT;
    }

    uint16_t retryCount = RETRY_45;

    while (retryCount > 0)
    {
        ret = set_bmc_ras_oob_config(p0_info, oob_config);

        if (ret == OOB_SUCCESS || ret == OOB_MAILBOX_CMD_UNKNOWN)
        {
            break;
        }
        else
        {
            sd_journal_print(LOG_ERR, "Failed to set ras oob configuration for "
                                      "Processor P0. Retrying....\n");
        }
        sleep(SLEEP_20);
        retryCount--;
    }

    if (num_of_proc == TWO_SOCKET)
    {
        retryCount = RETRY_45;
        while (retryCount > 0)
        {
            ret = set_bmc_ras_oob_config(p1_info, oob_config);

            if (ret == OOB_SUCCESS || ret == OOB_MAILBOX_CMD_UNKNOWN)
            {
                break;
            }
            else
            {
                sd_journal_print(LOG_ERR, "Failed to set ras oob configuration "
                                          "for Processor P1. Retrying....\n");
            }
            sleep(SLEEP_20);
            retryCount--;
        }
    }
    return ret;
}

/*The function returns the highest severity out of all Section Severity for CPER
  header Severity Order = Fatal > non-fatal uncorrected > corrected*/
bool calculate_highest_severity(uint32_t* Severity, uint16_t SectionCount,
                                uint32_t* HighestSeverity,
                                std::string ErrorType)
{
    bool rc = true;
    *HighestSeverity = SEV_NON_FATAL_CORRECTED;

    for (int i = 0; i < SectionCount; i++)
    {
        if (Severity[i] == CPER_SEV_FATAL)
        {
            if (ErrorType == RUNTIME_PCIE_ERR)
            {
                *HighestSeverity = CPER_SEV_FATAL;
                break;
            }
            else
            {
                sd_journal_print(
                    LOG_ERR, "Error Severity is fatal. This must be captured "
                             "in Crashdump CPER, not runtime CPER\n");
                rc = false;
            }
        }
        else if (Severity[i] == SEV_NON_FATAL_UNCORRECTED)
        {
            *HighestSeverity = SEV_NON_FATAL_UNCORRECTED;
            break;
        }
    }
    return rc;
}

void harvest_runtime_errors(uint8_t ErrorPollingType,
                            struct ras_rt_valid_err_inst p0_inst,
                            struct ras_rt_valid_err_inst p1_inst)
{

    uint32_t* Severity = nullptr;
    uint64_t* CheckInfo = nullptr;
    uint32_t HighestSeverity;
    uint32_t SectionDesSize = 0;
    uint32_t SectionSize = 0;

    uint16_t SectionCount = p0_inst.number_of_inst + p1_inst.number_of_inst;

    Severity = new uint32_t[SectionCount];
    CheckInfo = new uint64_t[SectionCount];

    if (ErrorPollingType == MCA_ERR)
    {
        std::unique_lock lock(mca_error_harvest_mtx);

        mca_ptr->SectionDescriptor = new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(mca_ptr->SectionDescriptor, 0, SectionDesSize);

        mca_ptr->ProcErrorSection = new proc_error_section[SectionCount];
        SectionSize = sizeof(proc_error_section) * SectionCount;
        memset(mca_ptr->ProcErrorSection, 0, SectionSize);

        uint16_t SectionStart = 0;

        if (p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(mca_ptr, p0_info, p0_inst, MCA_ERR,
                                    SectionStart, Severity, CheckInfo);

            dump_proc_error_info_section(mca_ptr, p0_info,
                                         p0_inst.number_of_inst, CheckInfo,
                                         SectionStart);
        }
        if (p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(mca_ptr, p1_info, p1_inst, MCA_ERR,
                                    SectionStart, Severity, CheckInfo);

            dump_proc_error_info_section(mca_ptr, p1_info, SectionCount,
                                         CheckInfo, SectionStart);
        }

        calculate_highest_severity(Severity, SectionCount, &HighestSeverity,
                                   RUNTIME_MCA_ERR);

        dump_cper_header_section(mca_ptr, SectionCount, HighestSeverity,
                                 RUNTIME_MCA_ERR);

        dump_error_descriptor_section(mca_ptr, SectionCount, RUNTIME_MCA_ERR,
                                      Severity);

        write_to_cper_file(mca_ptr, RUNTIME_MCA_ERR, SectionCount);

        if (mca_ptr->SectionDescriptor != nullptr)
        {
            delete[] mca_ptr->SectionDescriptor;
            mca_ptr->SectionDescriptor = nullptr;
        }

        if (mca_ptr->ProcErrorSection != nullptr)
        {
            delete[] mca_ptr->ProcErrorSection;
            mca_ptr->ProcErrorSection = nullptr;
        }
    }
    else if (ErrorPollingType == DRAM_CECC_ERR)
    {
        std::unique_lock lock(dram_error_harvest_mtx);

        dram_ptr->SectionDescriptor =
            new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(dram_ptr->SectionDescriptor, 0, SectionDesSize);

        dram_ptr->ProcErrorSection = new proc_error_section[SectionCount];
        SectionSize = sizeof(proc_error_section) * SectionCount;
        memset(dram_ptr->ProcErrorSection, 0, SectionSize);

        uint16_t SectionStart = 0;

        if (p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(dram_ptr, p0_info, p0_inst, DRAM_CECC_ERR,
                                    SectionStart, Severity, CheckInfo);

            dump_proc_error_info_section(dram_ptr, p0_info,
                                         p0_inst.number_of_inst, CheckInfo,
                                         SectionStart);
        }
        if (p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(dram_ptr, p1_info, p1_inst, DRAM_CECC_ERR,
                                    SectionStart, Severity, CheckInfo);

            dump_proc_error_info_section(dram_ptr, p1_info, SectionCount,
                                         CheckInfo, SectionStart);
        }

        calculate_highest_severity(Severity, SectionCount, &HighestSeverity,
                                   RUNTIME_DRAM_ERR);

        dump_cper_header_section(dram_ptr, SectionCount, HighestSeverity,
                                 RUNTIME_DRAM_ERR);

        dump_error_descriptor_section(dram_ptr, SectionCount, RUNTIME_DRAM_ERR,
                                      Severity);

        write_to_cper_file(dram_ptr, RUNTIME_DRAM_ERR, SectionCount);

        if (dram_ptr->SectionDescriptor != nullptr)
        {
            delete[] dram_ptr->SectionDescriptor;
            dram_ptr->SectionDescriptor = nullptr;
        }

        if (dram_ptr->ProcErrorSection != nullptr)
        {
            delete[] dram_ptr->ProcErrorSection;
            dram_ptr->ProcErrorSection = nullptr;
        }
    }
    else if (ErrorPollingType == PCIE_ERR)
    {

        std::unique_lock lock(pcie_error_harvest_mtx);

        pcie_ptr->SectionDescriptor =
            new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(pcie_ptr->SectionDescriptor, 0, SectionDesSize);

        pcie_ptr->PcieErrorSection = new pcie_error_section[SectionCount];
        SectionSize = sizeof(pcie_error_section) * SectionCount;
        memset(pcie_ptr->PcieErrorSection, 0, SectionSize);

        uint16_t SectionStart = 0;

        if (p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(pcie_ptr, p0_info, p0_inst, PCIE_ERR,
                                    SectionStart, Severity, CheckInfo);
            dump_pcie_error_info_section(pcie_ptr, SectionStart,
                                         p0_inst.number_of_inst);
        }
        if (p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(pcie_ptr, p1_info, p1_inst, PCIE_ERR,
                                    SectionStart, Severity, CheckInfo);
            dump_pcie_error_info_section(pcie_ptr, SectionStart, SectionCount);
        }

        calculate_highest_severity(Severity, SectionCount, &HighestSeverity,
                                   RUNTIME_PCIE_ERR);

        dump_cper_header_section(pcie_ptr, SectionCount, HighestSeverity,
                                 RUNTIME_PCIE_ERR);

        dump_error_descriptor_section(pcie_ptr, SectionCount, RUNTIME_PCIE_ERR,
                                      Severity);

        write_to_cper_file(pcie_ptr, RUNTIME_PCIE_ERR, SectionCount);

        if (pcie_ptr->SectionDescriptor != nullptr)
        {
            delete[] pcie_ptr->SectionDescriptor;
            pcie_ptr->SectionDescriptor = nullptr;
        }

        if (pcie_ptr->PcieErrorSection != nullptr)
        {
            delete[] pcie_ptr->PcieErrorSection;
            pcie_ptr->PcieErrorSection = nullptr;
        }
    }

    if (CheckInfo != nullptr)
    {
        delete[] CheckInfo;
        CheckInfo = nullptr;
    }

    if (Severity != nullptr)
    {
        delete[] Severity;
        Severity = nullptr;
    }
}

void RunTimeErrorInfoCheck(uint8_t ErrType, uint8_t ReqType)
{

    struct ras_rt_valid_err_inst p0_inst, p1_inst;
    struct ras_rt_err_req_type rt_err_category;

    oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN;
    oob_status_t p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

    rt_err_category.err_type = ErrType;
    rt_err_category.req_type = ReqType;

    memset(&p0_inst, 0, sizeof(p0_inst));
    memset(&p1_inst, 0, sizeof(p1_inst));

    p0_ret = RunTimeErrValidityCheck(p0_info, rt_err_category, &p0_inst);

    if (num_of_proc == TWO_SOCKET)
    {

        p1_ret = RunTimeErrValidityCheck(p1_info, rt_err_category, &p1_inst);
    }

    if (((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
        ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0)))
    {

        if (ErrType == MCA_ERR)
        {
            if (mca_ptr == nullptr)
            {
                mca_ptr = std::make_shared<PROC_RUNTIME_ERR_RECORD>();
            }
        }
        else if (ErrType == DRAM_CECC_ERR)
        {
            if (dram_ptr == nullptr)
            {
                dram_ptr = std::make_shared<PROC_RUNTIME_ERR_RECORD>();
            }
        }
        else if (ErrType == PCIE_ERR)
        {
            if (pcie_ptr == nullptr)
            {
                pcie_ptr = std::make_shared<PCIE_RUNTIME_ERR_RECORD>();
            }
        }

        harvest_runtime_errors(ErrType, p0_inst, p1_inst);
    }
}

void McaErrorPollingHandler(uint16_t PollingPeriod)
{

    if (Configuration::getMcaPollingEn() == true)
    {
        RunTimeErrorInfoCheck(MCA_ERR, POLLING_MODE);
    }

    if (McaErrorPollingEvent != nullptr)
        delete McaErrorPollingEvent;

    McaErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(PollingPeriod));

    McaErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n",
                                 ec.message().c_str());
                return;
            }
            McaErrorPollingHandler(Configuration::getMcaPollingPeriod());
        });
}

void DramCeccErrorPollingHandler(uint16_t PollingPeriod)
{

    if (Configuration::getDramCeccPollingEn() == true)
    {
        RunTimeErrorInfoCheck(DRAM_CECC_ERR, POLLING_MODE);
    }

    if (DramCeccErrorPollingEvent != nullptr)
        delete DramCeccErrorPollingEvent;

    DramCeccErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(PollingPeriod));

    DramCeccErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n",
                                 ec.message().c_str());
                return;
            }
            DramCeccErrorPollingHandler(
                Configuration::getDramCeccPollingPeriod());
        });
}

void PcieErrorPollingHandler(uint16_t PollingPeriod)
{

    if (Configuration::getPcieAerPollingEn() == true)
    {
        RunTimeErrorInfoCheck(PCIE_ERR, POLLING_MODE);
    }

    if (PcieAerErrorPollingEvent != nullptr)
        delete PcieAerErrorPollingEvent;

    PcieAerErrorPollingEvent = new boost::asio::deadline_timer(
        io, boost::posix_time::seconds(PollingPeriod));

    PcieAerErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n",
                                 ec.message().c_str());
                return;
            }
            PcieErrorPollingHandler(Configuration::getPcieAerPollingPeriod());
        });
}

void RunTimeErrorPolling()
{
    oob_status_t ret;

    ret = SetOobConfig();

    /*SetOobConfig is not supported for Genoa platform.
      Enable run time error polling only if SetOobConfig command
      is supported for the platform*/
    if (ret != OOB_MAILBOX_CMD_UNKNOWN)
    {
        McaErrorPollingHandler(Configuration::getMcaPollingPeriod());

        DramCeccErrorPollingHandler(Configuration::getDramCeccPollingPeriod());

        PcieErrorPollingHandler(Configuration::getPcieAerPollingPeriod());
    }
    else
    {
        sd_journal_print(
            LOG_INFO,
            "Runtime error polling is not supported for this platform\n");
    }

    ret = SetErrThreshold();

    if (ret == OOB_MAILBOX_CMD_UNKNOWN)
    {
        sd_journal_print(
            LOG_ERR,
            "Runtime error threshold is not supported for this platform\n");
    }
}
