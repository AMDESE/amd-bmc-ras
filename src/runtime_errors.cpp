#include "ras.hpp"
#include "cper.hpp"
#include "cper_runtime.hpp"
#include "write_cper_data.hpp"

extern boost::asio::io_service io;

std::shared_ptr<PROC_RUNTIME_ERR_RECORD> mca_ptr = nullptr;
std::shared_ptr<PROC_RUNTIME_ERR_RECORD> dram_ptr = nullptr;
std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> pcie_ptr = nullptr;

std::mutex mca_error_harvest_mtx;
std::mutex dram_error_harvest_mtx;
std::mutex pcie_error_harvest_mtx;

oob_status_t RunTimeErrValidityCheck(uint8_t soc_num,uint32_t rt_err_category,struct ras_rt_valid_err_inst *inst)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    ret = get_bmc_ras_run_time_err_validity_ck(soc_num, rt_err_category,
                           inst);
    if (ret) {
        sd_journal_print(LOG_DEBUG,"Failed to get bmc ras runtime error validity check\n");
    }

    return ret;
}

void SetOobConfig()
{
    oob_status_t ret;
    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));

    if(McaPollingEn == true)
    {
        /* Core MCA OOB Error Reporting Enable */
        oob_config.core_mca_err_reporting_en = ENABLE_BIT;
    }

    if(DramCeccPollingEn == true)
    {
        /* DRAM CECC OOB Error Counter Mode */
        oob_config.core_mca_err_reporting_en = ENABLE_BIT;
        oob_config.dram_cecc_oob_ec_mode = ENABLE_BIT; /*Enabled in No leak mode*/
    }

    if(PcieAerPollingEn == true)
    {
        /* PCIe OOB Error Reporting Enable */
        oob_config.pcie_err_reporting_en = ENABLE_BIT;
    }

    ret = set_bmc_ras_oob_config(p0_info, oob_config);

    if (ret) {
        sd_journal_print(LOG_ERR, "Failed to set ras oob configuration\n");
    }

    if(num_of_proc == TWO_SOCKET)
    {
        ret = set_bmc_ras_oob_config(p1_info, oob_config);

        if (ret) {
            sd_journal_print(LOG_ERR, "Failed to set ras oob configuration\n");
        }
    }

    sd_journal_print(LOG_INFO, "BMC RAS oob configuration set successfully\n");
}

template<typename T>
void dump_proc_error_section(const std::shared_ptr<T>& data,uint8_t soc_num,
            struct ras_rt_valid_err_inst inst,uint8_t category,uint16_t Section,uint32_t *Severity,uint64_t *CheckInfo)
{
    uint16_t maxOffset32;
    uint16_t n = 0;
    struct run_time_err_d_in d_in;
    uint32_t d_out;
    uint64_t mca_status_register = 0;
    uint32_t root_err_status = 0;
    uint32_t offset = 0;
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    sd_journal_print(LOG_INFO, "Harvesting errors for category %d\n",category);
    std::shared_ptr<PROC_RUNTIME_ERR_RECORD> ProcPtr;
    std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> PciePtr;

    if constexpr (std::is_same_v<T, PROC_RUNTIME_ERR_RECORD>) {
        ProcPtr = std::static_pointer_cast<PROC_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, PCIE_RUNTIME_ERR_RECORD>) {
        PciePtr = std::static_pointer_cast<PCIE_RUNTIME_ERR_RECORD>(data);
    }

    while(n < inst.number_of_inst)
    {
        if(category == DRAM_CECC_ERR)
        {
            offset = INDEX_4;
        }
        else {
            offset = 0;
        }

        int DumpIndex = 0;

        for (; offset < inst.number_bytes; offset = offset+INDEX_4)
        {
            memset(&d_in,0,sizeof(d_in));
            memset(&d_out,0,sizeof(d_out));
            d_in.offset = offset;
            d_in.category = category;
            d_in.valid_inst_index = n;

            ret = get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

            if (ret != OOB_SUCCESS)
            {
                // retry
                uint16_t retryCount = apmlRetryCount;
                while(retryCount > 0)
                {
                    memset(&d_in,0,sizeof(d_in));
                    memset(&d_out,0,sizeof(d_out));
                    d_in.offset = offset;
                    d_in.category = category;
                    d_in.valid_inst_index = n;

                    ret = get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

                    if (ret == OOB_SUCCESS)
                    {
                        break;
                    }
                    retryCount--;
                    usleep(1000 * 1000);
                }

            }
            if (ret != OOB_SUCCESS)
            {
                sd_journal_print(LOG_ERR, "Socket %d : Failed to get runtime error info for instance :%d, Offset:0x%x\n", soc_num, n, offset);
                if(ProcPtr) {
                    ProcPtr->ProcErrorSection[Section].ProcContextStruct.DumpData[DumpIndex] = BAD_DATA; 
                } else if(PciePtr) {
                    PciePtr->PcieErrorSection[Section].AerInfo[DumpIndex] = BAD_DATA;
                }
                continue;
            }

            if(ProcPtr)
            {
                ProcPtr->ProcErrorSection[Section].ProcContextStruct.DumpData[DumpIndex] = d_out;

                if(d_in.offset == INDEX_8)
                {
                    mca_status_register = mca_status_register | ((uint64_t) d_out);
                }
                else if(d_in.offset == INDEX_12)
                {
                    mca_status_register = ((uint64_t)d_out << INDEX_32) | mca_status_register;
                }
            } else if(PciePtr)
            {
                PciePtr->PcieErrorSection[Section].AerInfo[DumpIndex] = d_out;

                if(d_in.offset == INDEX_44)
                {
                    root_err_status = d_out;
                }
            }
            DumpIndex++;

        } // for loop

        if((category == MCA_ERR) || (category = DRAM_CECC_ERR))
        { 
            if ((mca_status_register & (1ULL << INDEX_61)) == 0) {
                Severity[n] = SEV_NON_FATAL_CORRECTED;
            }
            else if((mca_status_register & (1ULL << INDEX_61) == 1) && 
                   ((mca_status_register & (1ULL << INDEX_57)) == 0)) {
                Severity[n] = SEV_NON_FATAL_UNCORRECTED;
            }
        }
        else if(category = PCIE_ERR)
        {

            if (root_err_status & (INDEX_1 << INDEX_6))
            {
                Severity[Section] = CPER_SEV_FATAL;
            }
            else if (root_err_status & (INDEX_1 << INDEX_5))
            {
                Severity[Section] = SEV_NON_FATAL_UNCORRECTED;
            }
            else if (root_err_status & INDEX_1)
            {
                Severity[Section] = SEV_NON_FATAL_CORRECTED;
            }
        } 

        if((category == MCA_ERR) || (category = DRAM_CECC_ERR))
        {
            CheckInfo[Section] = 0;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_57) & 1ULL) << INDEX_19;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_61) & 1ULL) << INDEX_20;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_62) & 1ULL) << INDEX_23;
            CheckInfo[Section] |= (5ULL << INDEX_16);
        }

        n++;
        Section++;
    }
}

template<typename T>
void dump_pcie_error_info_section(const std::shared_ptr<T>& data,
                uint16_t SectionStart,uint16_t SectionCount)
{

    for(int i = SectionStart ; i < SectionCount ; i++)
    {
        data->PcieErrorSection[i].ValidationBits |= 1ULL | (1ULL << INDEX_1) 
                                                    | (1ULL << INDEX_3) | (1ULL << INDEX_7); 
        data->PcieErrorSection[i].PortType = INDEX_4; //Root Port
        data->PcieErrorSection[i].Version.Major = INDEX_2;
        data->PcieErrorSection[i].DeviceId.VendorId = PCIE_VENDOR_ID;
    }
}

template<typename T>
void dump_proc_error_info_section(const std::shared_ptr<T>& ProcPtr, uint8_t soc_num,uint16_t SectionCount,
                                 uint64_t *CheckInfo,uint32_t SectionStart)
{

    for(uint32_t i = SectionStart ; i < SectionCount ; i++)
    {
        ProcPtr->ProcErrorSection[i].ProcInfoSection.ValidBits =  0b11 | (SectionCount << INDEX_2) | (SectionCount << INDEX_8);

        if(soc_num == p0_info)
        {
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_0] = p0_eax;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_2] = p0_ebx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_4] = p0_ecx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_6] = p0_edx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CPUAPICId = ((p0_ebx >> SHIFT_24) & INT_255);
        }
        if(soc_num == p1_info)
        {
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_0] = p1_eax;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_2] = p1_ebx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_4] = p1_ecx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_6] = p1_edx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CPUAPICId = ((p1_ebx >> SHIFT_24) & INT_255);
        }

        ProcPtr->ProcErrorSection[i].ProcErrorInfo.ErrorType = MS_CHECK_GUID;
        ProcPtr->ProcErrorSection[i].ProcErrorInfo.ValidationBits = ENABLE_BIT;
        ProcPtr->ProcErrorSection[i].ProcErrorInfo.CheckInfo = CheckInfo[i];
        ProcPtr->ProcErrorSection[i].ProcContextStruct.RegContextType = ENABLE_BIT;
        ProcPtr->ProcErrorSection[i].ProcContextStruct.RegArraySize = MCA_BANK_MAX_OFFSET;
         
    }

}

/*The function returns the highest severity out of all Section Severity for CPER header
  Severity Order = Fatal > non-fatal uncorrected > corrected*/ 
bool calculate_highest_severity(uint32_t* Severity,uint16_t SectionCount,uint32_t* HighestSeverity,std::string ErrorType)
{
    bool rc = true;
    *HighestSeverity = SEV_NON_FATAL_CORRECTED;

    for(int i = 0 ; i < SectionCount; i++)
    {
        if(Severity[i] == CPER_SEV_FATAL)
        {
            if(ErrorType == RUNTIME_PCIE_ERR)
            {
                *HighestSeverity = CPER_SEV_FATAL;
                 break;
            }
            else
            {
                sd_journal_print(LOG_ERR, "Error Severity is fatal. This must be captured in Crashdump CPER, not runtime CPER\n");
                rc = false; 
            }
        }
        else if(Severity[i] == SEV_NON_FATAL_UNCORRECTED)
        {
            *HighestSeverity = SEV_NON_FATAL_UNCORRECTED;
             break;
        }
    }
    return rc;
}

void harvest_runtime_errors(uint8_t ErrorPollingType, struct ras_rt_valid_err_inst p0_inst,struct ras_rt_valid_err_inst p1_inst)
{

    uint8_t category;
    uint32_t *Severity = nullptr;
    uint64_t *CheckInfo = nullptr;
    uint32_t HighestSeverity;
    uint32_t SectionDesSize = 0;
    uint32_t SectionSize = 0;

    uint16_t SectionCount = p0_inst.number_of_inst + p1_inst.number_of_inst;

    Severity = new uint32_t[SectionCount];
    CheckInfo = new uint64_t[SectionCount];

    if(ErrorPollingType == MCA_ERR)
    {
        std::unique_lock lock(mca_error_harvest_mtx);

        mca_ptr->SectionDescriptor = new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(mca_ptr->SectionDescriptor, 0 , SectionDesSize);

        mca_ptr->ProcErrorSection = new proc_error_section[SectionCount];
        SectionSize = sizeof(proc_error_section) * SectionCount;
        memset(mca_ptr->ProcErrorSection, 0 , SectionSize);

        uint16_t SectionStart = 0;

        if(p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(mca_ptr,p0_info,p0_inst,MCA_ERR,SectionStart,Severity,CheckInfo);

            dump_proc_error_info_section(mca_ptr,p0_info,p0_inst.number_of_inst,CheckInfo,SectionStart);
        }
        if(p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(mca_ptr,p1_info,p1_inst,MCA_ERR,SectionStart,Severity,CheckInfo);

            dump_proc_error_info_section(mca_ptr,p1_info,SectionCount,CheckInfo,SectionStart);
        }

        calculate_highest_severity(Severity,SectionCount,&HighestSeverity,RUNTIME_MCA_ERR);

        dump_cper_header_section(mca_ptr, SectionCount, HighestSeverity, RUNTIME_MCA_ERR);

        dump_error_descriptor_section(mca_ptr, SectionCount,RUNTIME_MCA_ERR,Severity);

        write_to_cper_file(mca_ptr,RUNTIME_MCA_ERR,SectionCount);

        if(mca_ptr->SectionDescriptor != nullptr) {
            delete[] mca_ptr->SectionDescriptor;
            mca_ptr->SectionDescriptor = nullptr;
        }

        if(mca_ptr->ProcErrorSection != nullptr) {
            delete[] mca_ptr->ProcErrorSection;
            mca_ptr->ProcErrorSection = nullptr;
        }
    }
    else if(ErrorPollingType == DRAM_CECC_ERR)
    {
        std::unique_lock lock(dram_error_harvest_mtx);

        dram_ptr->SectionDescriptor = new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(dram_ptr->SectionDescriptor, 0 , SectionDesSize);

        dram_ptr->ProcErrorSection = new proc_error_section[SectionCount];
        SectionSize = sizeof(proc_error_section) * SectionCount;
        memset(dram_ptr->ProcErrorSection, 0 , SectionSize);

        uint16_t SectionStart = 0;

        if(p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(dram_ptr,p0_info,p0_inst,DRAM_CECC_ERR,SectionStart,Severity,CheckInfo);

            dump_proc_error_info_section(dram_ptr,p0_info,p0_inst.number_of_inst,CheckInfo,SectionStart);
        }
        if(p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(dram_ptr,p1_info,p1_inst,DRAM_CECC_ERR,SectionStart,Severity,CheckInfo);

            dump_proc_error_info_section(dram_ptr,p1_info,SectionCount,CheckInfo,SectionStart);
        }

        calculate_highest_severity(Severity,SectionCount,&HighestSeverity,RUNTIME_DRAM_ERR);

        dump_cper_header_section(dram_ptr, SectionCount, HighestSeverity, RUNTIME_DRAM_ERR);

        dump_error_descriptor_section(dram_ptr, SectionCount,RUNTIME_DRAM_ERR,Severity);

        write_to_cper_file(dram_ptr,RUNTIME_DRAM_ERR,SectionCount);

        if(dram_ptr->SectionDescriptor != nullptr) {
            delete[] dram_ptr->SectionDescriptor;
            dram_ptr->SectionDescriptor = nullptr;
        }

        if(dram_ptr->ProcErrorSection != nullptr) {
            delete[] dram_ptr->ProcErrorSection;
            dram_ptr->ProcErrorSection = nullptr;
        }

    }
    else if(ErrorPollingType == PCIE_ERR)
    {

        std::unique_lock lock(pcie_error_harvest_mtx);

        pcie_ptr->SectionDescriptor = new error_section_descriptor[SectionCount];
        SectionDesSize = sizeof(error_section_descriptor) * SectionCount;
        memset(pcie_ptr->SectionDescriptor, 0 , SectionDesSize);

        pcie_ptr->PcieErrorSection = new pcie_error_section[SectionCount];
        SectionSize = sizeof(pcie_error_section) * SectionCount;
        memset(pcie_ptr->PcieErrorSection, 0 , SectionSize);

        uint16_t SectionStart = 0;

        if(p0_inst.number_of_inst != 0)
        {
            dump_proc_error_section(pcie_ptr,p0_info,p0_inst,PCIE_ERR,SectionStart,Severity,CheckInfo);
            dump_pcie_error_info_section(pcie_ptr,SectionStart,p0_inst.number_of_inst);
        }
        if(p1_inst.number_of_inst != 0)
        {
            SectionStart = SectionCount - p1_inst.number_of_inst;

            dump_proc_error_section(pcie_ptr,p1_info,p1_inst,PCIE_ERR,SectionStart,Severity,CheckInfo);
            dump_pcie_error_info_section(pcie_ptr,SectionStart,SectionCount);
        }

        calculate_highest_severity(Severity,SectionCount,&HighestSeverity,RUNTIME_PCIE_ERR);

        dump_cper_header_section(pcie_ptr, SectionCount, HighestSeverity, RUNTIME_PCIE_ERR);

        dump_error_descriptor_section(pcie_ptr, SectionCount,RUNTIME_PCIE_ERR,Severity);

        write_to_cper_file(pcie_ptr,RUNTIME_PCIE_ERR,SectionCount);

        if(pcie_ptr->SectionDescriptor != nullptr) {
            delete[] pcie_ptr->SectionDescriptor;
            pcie_ptr->SectionDescriptor = nullptr;
        }

        if(pcie_ptr->PcieErrorSection != nullptr) {
            delete[] pcie_ptr->PcieErrorSection;
            pcie_ptr->PcieErrorSection = nullptr;
        }

    }

    if(CheckInfo != nullptr) {
        delete[] CheckInfo;
        CheckInfo = nullptr;
    }

    if(Severity != nullptr) {
        delete[] Severity;
        Severity = nullptr;
    }
}

void McaErrorPollingHandler(uint16_t PollingPeriod)
{
    struct ras_rt_valid_err_inst p0_inst,p1_inst;
    uint32_t rt_err_category;
    oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN ,p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

    rt_err_category = 0 ; /*00 = MCA*/
    memset(&p0_inst, 0, sizeof(p0_inst));
    memset(&p1_inst, 0, sizeof(p1_inst));

    p0_ret =  RunTimeErrValidityCheck(p0_info,rt_err_category,&p0_inst);

    if(num_of_proc == TWO_SOCKET)
    {
        
        p1_ret = RunTimeErrValidityCheck(p1_info,rt_err_category,&p1_inst);
    }

    if(((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
            ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0)))
    {

        if (mca_ptr == nullptr)
        {
            mca_ptr = std::make_shared<PROC_RUNTIME_ERR_RECORD>();
        }

        harvest_runtime_errors(MCA_ERR,p0_inst,p1_inst);
    }

    if(McaErrorPollingEvent != nullptr)
        delete McaErrorPollingEvent;

    McaErrorPollingEvent = new boost::asio::deadline_timer(io,boost::posix_time::seconds(PollingPeriod));

    McaErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n", ec.message().c_str());
                return;
            }
            McaErrorPollingHandler(PollingPeriod);
        });
}

void DramCeccErrorPollingHandler(uint16_t PollingPeriod)
{
    struct ras_rt_valid_err_inst p0_inst,p1_inst;
    uint32_t rt_err_category;
    oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN ,p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

    rt_err_category = ENABLE_BIT ; /*01 = DRAM CECC*/
    memset(&p0_inst, 0, sizeof(p0_inst));
    memset(&p1_inst, 0, sizeof(p1_inst));

    p0_ret = RunTimeErrValidityCheck(p0_info,rt_err_category,&p0_inst);

    if(num_of_proc == TWO_SOCKET)
    {
        p1_ret = RunTimeErrValidityCheck(p1_info,rt_err_category,&p1_inst);
    }

    if(((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
            ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0)))
    {
        if (dram_ptr == nullptr) {
            dram_ptr = std::make_shared<PROC_RUNTIME_ERR_RECORD>();
        }
        harvest_runtime_errors(DRAM_CECC_ERR,p0_inst,p1_inst);
    }

    if(DramCeccErrorPollingEvent != nullptr)
        delete DramCeccErrorPollingEvent;

    DramCeccErrorPollingEvent = new boost::asio::deadline_timer(io,boost::posix_time::seconds(PollingPeriod));

    DramCeccErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n", ec.message().c_str());
                return;
            }
            DramCeccErrorPollingHandler(PollingPeriod);
        });
}

void PcieErrorPollingHandler(uint16_t PollingPeriod)
{

    struct ras_rt_valid_err_inst p0_inst,p1_inst;
    uint32_t rt_err_category;
    oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN ,p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

    rt_err_category = BYTE_2 ; /*10 = PCIe*/
    memset(&p0_inst, 0, sizeof(p0_inst));
    memset(&p1_inst, 0, sizeof(p1_inst));

    p0_ret = RunTimeErrValidityCheck(p0_info,rt_err_category,&p0_inst);

    if(num_of_proc == TWO_SOCKET)
    {
        p1_ret = RunTimeErrValidityCheck(p1_info,rt_err_category,&p1_inst);

        if(p1_ret != OOB_SUCCESS)
        {
            memset(&p1_inst, 0, sizeof(p1_inst));
        } 
    }

    if(((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
            ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0)))
    {
        if (pcie_ptr == nullptr) {
            pcie_ptr = std::make_shared<PCIE_RUNTIME_ERR_RECORD>();
        }
        harvest_runtime_errors(PCIE_ERR,p0_inst,p1_inst);

    }

    if(PcieAerErrorPollingEvent != nullptr)
        delete PcieAerErrorPollingEvent;

    PcieAerErrorPollingEvent = new boost::asio::deadline_timer(io,boost::posix_time::seconds(PollingPeriod));

    PcieAerErrorPollingEvent->async_wait(
        [PollingPeriod](const boost::system::error_code ec) {
            if (ec)
            {
                sd_journal_print(LOG_ERR, "fd handler error failed: %s \n", ec.message().c_str());
                return;
            }
            PcieErrorPollingHandler(PollingPeriod);
        });
}

void RunTimeErrorPolling()
{
    if(TurinPlatform == true)
    {
        SetOobConfig();

        if(McaPollingEn == true)
        {
            McaErrorPollingHandler(McaPollingPeriod);
        }
        if(DramCeccPollingEn == true)
        {
            DramCeccErrorPollingHandler(DramCeccPollingPeriod);
        }
        if(PcieAerPollingEn == true)
        {
            PcieErrorPollingHandler(PcieAerPollingPeriod);
        }
    }
}
