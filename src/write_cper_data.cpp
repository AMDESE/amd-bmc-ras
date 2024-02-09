#include "Config.hpp"
#include "cper.hpp"
#include "cper_runtime.hpp"
#include "ras.hpp"

GUID_T InitializeGUID(unsigned int a, unsigned short b, unsigned short c,
                      unsigned char d0, unsigned char d1, unsigned char d2,
                      unsigned char d3, unsigned char d4, unsigned char d5,
                      unsigned char d6, unsigned char d7)
{
    GUID_T temp;
    temp.b[0] = (a)&0xff;
    temp.b[1] = ((a) >> 8) & 0xff;
    temp.b[2] = ((a) >> 16) & 0xff;
    temp.b[3] = ((a) >> 24) & 0xff;
    temp.b[4] = (b)&0xff;
    temp.b[5] = ((b) >> 8) & 0xff;
    temp.b[6] = (c)&0xff;
    temp.b[7] = ((c) >> 8) & 0xff;
    temp.b[8] = (d0);
    temp.b[9] = (d1);
    temp.b[10] = (d2);
    temp.b[11] = (d3);
    temp.b[12] = (d4);
    temp.b[13] = (d5);
    temp.b[14] = (d6);
    temp.b[15] = (d7);
    return temp;
}

GUID_T CPER_NOTIFY_MCE = InitializeGUID(0xE8F56FFE, 0x919C, 0x4cc5, 0xBA, 0x88,
                                        0x65, 0xAB, 0xE1, 0x49, 0x13, 0xBB);
GUID_T CPER_NOTIFY_CMC = InitializeGUID(0x2DCE8BB1, 0xBDD7, 0x450e, 0xB9, 0xAD,
                                        0x9C, 0xF4, 0xEB, 0xD4, 0xF8, 0x90);
GUID_T CPER_NOTIFY_PCIE = InitializeGUID(0xCF93C01F, 0x1A16, 0x4dfc, 0xB8, 0xBC,
                                         0x9C, 0x4D, 0xAF, 0x67, 0xC1, 0x04);
GUID_T CPER_CREATOR_PSTORE = InitializeGUID(
    0x61fa3fac, 0xcb80, 0x4292, 0x8b, 0xfb, 0xd6, 0x43, 0xb1, 0xde, 0x17, 0xf4);
GUID_T AMD_OOB_CRASHDUMP = InitializeGUID(
    0x32AC0C78, 0x2623, 0x48F6, 0xB0, 0xD0, 0x73, 0x65, 0x72, 0x5F, 0xD6, 0xAE);
GUID_T PROC_ERR_SECTION_TYPE = InitializeGUID(
    0xDC3EA0B0, 0xA144, 0x4797, 0xB9, 0x5B, 0x53, 0xFA, 0x24, 0x2B, 0x6E, 0x1D);
GUID_T PCIE_ERR_SECTION_TYPE = InitializeGUID(
    0xD995E954, 0xBBC1, 0x430F, 0xAD, 0x91, 0xB4, 0x4D, 0xCB, 0x3C, 0x6F, 0x35);
GUID_T MS_CHECK_GUID = InitializeGUID(0x48AB7F57, 0xDC34, 0x4f6c, 0xA7, 0xD3,
                                      0xB0, 0xB5, 0xB0, 0xA7, 0x43, 0x14);

template <typename T>
void dump_pcie_error_info_section(const std::shared_ptr<T>& data,
                                  uint16_t SectionStart, uint16_t SectionCount)
{

    for (int i = SectionStart; i < SectionCount; i++)
    {
        data->PcieErrorSection[i].ValidationBits |=
            1ULL | (1ULL << INDEX_1) | (1ULL << INDEX_3) | (1ULL << INDEX_7);
        data->PcieErrorSection[i].PortType = INDEX_4; // Root Port
        data->PcieErrorSection[i].Version.Major = INDEX_2;
        data->PcieErrorSection[i].DeviceId.VendorId = PCIE_VENDOR_ID;
    }
}

std::string FindDimmFruText(uint8_t soc_num, uint8_t UMCInstance,
                            uint8_t DimmNumber)
{
    std::map<int, char> dimmPairSequence = {
        {0, 'C'}, {1, 'E'}, {2, 'F'}, {3, 'A'}, {4, 'B'},  {5, 'D'},
        {6, 'I'}, {7, 'K'}, {8, 'L'}, {9, 'G'}, {10, 'H'}, {11, 'J'}};

    char Channel = '\0';
    auto it = dimmPairSequence.find(UMCInstance);
    if (it != dimmPairSequence.end())
    {
        Channel = it->second;
    }

    int DimmIdentifier = soc_num * 1000 + (Channel - 'A') * 10 + DimmNumber;
    std::string FruText = "";

    switch (DimmIdentifier)
    {
        /*SOC 0, Channel 'A',DIMM Number 0*/
        case 0:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_A");
            break;

        /*SOC 0, Channel 'A',DIMM Number 1*/
        case 1:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_A1");
            break;

        /*SOC 0, Channel 'B',DIMM Number 0*/
        case 10:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_B");
            break;

        /*SOC 0, Channel 'B',DIMM Number 1*/
        case 11:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_B1");
            break;

        /*SOC 0, Channel 'C',DIMM Number 0*/
        case 20:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_C");
            break;

        /*SOC 0, Channel 'C',DIMM Number 1*/
        case 21:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_C1");
            break;

        /*SOC 0, Channel 'D',DIMM Number 0*/
        case 30:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_D");
            break;

        /*SOC 0, Channel 'D',DIMM Number 1*/
        case 31:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_D1");
            break;

        /*SOC 0, Channel 'E',DIMM Number 0*/
        case 40:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_E");
            break;

        /*SOC 0, Channel 'E',DIMM Number 1*/
        case 41:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_E1");
            break;

        /*SOC 0, Channel 'F',DIMM Number 0*/
        case 50:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_F");
            break;

        /*SOC 0, Channel 'F',DIMM Number 1*/
        case 51:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_F1");
            break;

        /*SOC 0, Channel 'G',DIMM Number 0*/
        case 60:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_G");
            break;

        /*SOC 0, Channel 'G',DIMM Number 1*/
        case 61:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_G1");
            break;

        /*SOC 0, Channel 'H',DIMM Number 0*/
        case 70:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_H");
            break;

        /*SOC 0, Channel 'H',DIMM Number 1*/
        case 71:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_H1");
            break;

        /*SOC 0, Channel 'I',DIMM Number 0*/
        case 80:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_I");
            break;

        /*SOC 0, Channel 'I',DIMM Number 1*/
        case 81:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_I1");
            break;

        /*SOC 0, Channel 'J',DIMM Number 0*/
        case 90:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_J");
            break;

        /*SOC 0, Channel 'J',DIMM Number 1*/
        case 91:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_J1");
            break;

        /*SOC 0, Channel 'K',DIMM Number 0*/
        case 100:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_K");
            break;

        /*SOC 0, Channel 'K',DIMM Number 1*/
        case 101:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_K1");
            break;

        /*SOC 0, Channel 'L',DIMM Number 0*/
        case 110:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_L");
            break;

        /*SOC 0, Channel 'L',DIMM Number 1*/
        case 111:
            FruText = Configuration::getP0_DimmLabels("P0_DIMM_L1");
            break;

        /*SOC 1, Channel 'A',DIMM Number 0*/
        case 1000:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_A");
            break;

        /*SOC 1, Channel 'A',DIMM Number 1*/
        case 1001:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_A1");
            break;

        /*SOC 1, Channel 'B',DIMM Number 0*/
        case 1010:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_B");
            break;

        /*SOC 1, Channel 'B',DIMM Number 1*/
        case 1011:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_B1");
            break;

        /*SOC 1, Channel 'C',DIMM Number 0*/
        case 1020:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_C");
            break;

        /*SOC 1, Channel 'C',DIMM Number 1*/
        case 1021:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_C1");
            break;

        /*SOC 1, Channel 'D',DIMM Number 0*/
        case 1030:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_D");
            break;

        /*SOC 1, Channel 'D',DIMM Number 1*/
        case 1031:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_D1");
            break;

        /*SOC 1, Channel 'E',DIMM Number 0*/
        case 1040:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_E");
            break;

        /*SOC 1, Channel 'E',DIMM Number 1*/
        case 1041:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_E1");
            break;

        /*SOC 1, Channel 'F',DIMM Number 0*/
        case 1050:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_F");
            break;

        /*SOC 1, Channel 'F',DIMM Number 1*/
        case 1051:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_F1");
            break;

        /*SOC 1, Channel 'G',DIMM Number 0*/
        case 1060:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_G");
            break;

        /*SOC 1, Channel 'G',DIMM Number 1*/
        case 1061:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_G1");
            break;

        /*SOC 1, Channel 'H',DIMM Number 0*/
        case 1070:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_H");
            break;

        /*SOC 1, Channel 'H',DIMM Number 1*/
        case 1071:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_H1");
            break;

        /*SOC 1, Channel 'I',DIMM Number 0*/
        case 1080:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_I");
            break;

        /*SOC 1, Channel 'I',DIMM Number 1*/
        case 1081:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_I1");
            break;

        /*SOC 1, Channel 'J',DIMM Number 0*/
        case 1090:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_J");
            break;

        /*SOC 1, Channel 'J',DIMM Number 1*/
        case 1091:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_J1");
            break;

        /*SOC 1, Channel 'K',DIMM Number 0*/
        case 1100:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_K");
            break;

        /*SOC 1, Channel 'K',DIMM Number 1*/
        case 1101:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_K1");
            break;

        /*SOC 1, Channel 'L',DIMM Number 0*/
        case 1110:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_L");
            break;

        /*SOC 1, Channel 'L',DIMM Number 1*/
        case 1111:
            FruText = Configuration::getP1_DimmLabels("P1_DIMM_L1");
            break;

        default:
            break;
    }
    return FruText;
}

template <typename T>
void dump_proc_error_section(const std::shared_ptr<T>& data, uint8_t soc_num,
                             struct ras_rt_valid_err_inst inst,
                             uint8_t category, uint16_t Section,
                             uint32_t* Severity, uint64_t* CheckInfo)
{
    uint16_t n = 0;
    struct run_time_err_d_in d_in;
    uint32_t d_out = 0;
    uint64_t mca_status_register = 0;
    uint32_t root_err_status = 0;
    uint32_t offset = 0;
    uint32_t mca_ipid_lo_register = 0;
    uint32_t mca_ipid_hi_register = 0;
    uint32_t mca_synd_lo_register = 0;

    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

    sd_journal_print(LOG_INFO, "Harvesting errors for category %d\n", category);
    std::shared_ptr<PROC_RUNTIME_ERR_RECORD> ProcPtr;
    std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> PciePtr;

    if constexpr (std::is_same_v<T, PROC_RUNTIME_ERR_RECORD>)
    {
        ProcPtr = std::static_pointer_cast<PROC_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, PCIE_RUNTIME_ERR_RECORD>)
    {
        PciePtr = std::static_pointer_cast<PCIE_RUNTIME_ERR_RECORD>(data);
    }

    while (n < inst.number_of_inst)
    {
        if (category == DRAM_CECC_ERR)
        {
            offset = INDEX_4;
        }
        else
        {
            offset = 0;
        }

        int DumpIndex = 0;

        for (; offset < inst.number_bytes; offset = offset + INDEX_4)
        {
            memset(&d_in, 0, sizeof(d_in));
            memset(&d_out, 0, sizeof(d_out));
            d_in.offset = offset;
            d_in.category = category;
            d_in.valid_inst_index = n;

            ret = get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

            if (ret != OOB_SUCCESS)
            {
                // retry
                uint16_t retryCount = Configuration::getApmlRetryCount();
                while (retryCount > 0)
                {
                    memset(&d_in, 0, sizeof(d_in));
                    memset(&d_out, 0, sizeof(d_out));
                    d_in.offset = offset;
                    d_in.category = category;
                    d_in.valid_inst_index = n;

                    ret =
                        get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

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
                sd_journal_print(LOG_ERR,
                                 "Socket %d : Failed to get runtime error info "
                                 "for instance :%d, Offset:0x%x\n",
                                 soc_num, n, offset);
                if (ProcPtr)
                {
                    ProcPtr->ProcErrorSection[Section]
                        .ProcContextStruct.DumpData[DumpIndex] = BAD_DATA;
                }
                else if (PciePtr)
                {
                    PciePtr->PcieErrorSection[Section].AerInfo[DumpIndex] =
                        BAD_DATA;
                }
                continue;
            }

            if (ProcPtr)
            {
                ProcPtr->ProcErrorSection[Section]
                    .ProcContextStruct.DumpData[DumpIndex] = d_out;

                if (d_in.offset == INDEX_8)
                {
                    mca_status_register =
                        mca_status_register | ((uint64_t)d_out);
                }
                else if (d_in.offset == INDEX_12)
                {
                    mca_status_register =
                        ((uint64_t)d_out << INDEX_32) | mca_status_register;
                }
                if (category == MCA_ERR)
                {
                    if (d_in.offset == INDEX_40)
                    {
                        mca_ipid_lo_register = d_out;
                    }
                    if (d_in.offset == INDEX_44)
                    {
                        mca_ipid_hi_register = d_out;
                    }
                    if (d_in.offset == INDEX_48)
                    {
                        mca_synd_lo_register = d_out;
                    }
                }
                if (category == DRAM_CECC_ERR)
                {
                    if (d_in.offset == INDEX_44)
                    {
                        mca_ipid_lo_register = d_out;
                    }
                    if (d_in.offset == INDEX_48)
                    {
                        mca_ipid_hi_register = d_out;
                    }
                    if (d_in.offset == INDEX_52)
                    {
                        mca_synd_lo_register = d_out;
                    }
                }
            }
            else if (PciePtr)
            {
                PciePtr->PcieErrorSection[Section].AerInfo[DumpIndex] = d_out;

                if (d_in.offset == INDEX_44)
                {
                    root_err_status = d_out;
                }
            }
            DumpIndex++;

        } // for loop

        if ((category == MCA_ERR) || (category == DRAM_CECC_ERR))
        {
            if (((mca_status_register & (1ULL << INDEX_61)) == 0) &&
                ((mca_status_register & (1ULL << INDEX_44)) == 0))
            {
                Severity[Section] = SEV_NON_FATAL_CORRECTED;
            }
            else if ((((mca_status_register & (1ULL << INDEX_61)) == 0) &&
                      ((mca_status_register & (1ULL << INDEX_44)) != 0)) ||
                     (((mca_status_register & (1ULL << INDEX_61)) != 0) &&
                      ((mca_status_register & (1ULL << INDEX_57)) == 0)))
            {
                Severity[Section] = SEV_NON_FATAL_UNCORRECTED;
            }

            /*Calculate HwID from MCA_IPID_HI register*/
            uint32_t UmcHwId = mca_ipid_hi_register & MASK_11_TO_0;

            if (UmcHwId == TURIN_UMC_HW_ID)
            {
                /*Find UMC Instance*/
                uint8_t UMCInstance = static_cast<uint8_t>(
                    (mca_ipid_lo_register >> INDEX_20) & MASK_0X0F);

                uint8_t DimmNumber =
                    ((static_cast<uint8_t>(mca_synd_lo_register & INDEX_7)) >>
                     INDEX_1);

                std::string FruText =
                    FindDimmFruText(soc_num, UMCInstance, DimmNumber);

                memcpy(ProcPtr->SectionDescriptor[Section].FRUText,
                       FruText.c_str(), INDEX_20);
            }
        }
        else if (category == PCIE_ERR)
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

        if ((category == MCA_ERR) || (category = DRAM_CECC_ERR))
        {
            CheckInfo[Section] = 0;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_57) & 1ULL)
                                  << INDEX_19;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_61) & 1ULL)
                                  << INDEX_20;
            CheckInfo[Section] |= ((mca_status_register >> INDEX_62) & 1ULL)
                                  << INDEX_23;
            CheckInfo[Section] |= (5ULL << INDEX_16);
        }

        n++;
        Section++;
    }
}

template <typename T>
void calculate_time_stamp(const std::shared_ptr<T>& data)
{
    using namespace std;
    using namespace std::chrono;
    typedef duration<int, ratio_multiply<hours::period, ratio<24>>::type> days;

    system_clock::time_point now = system_clock::now();
    system_clock::duration tp = now.time_since_epoch();

    days d = duration_cast<days>(tp);
    tp -= d;
    hours h = duration_cast<hours>(tp);
    tp -= h;
    minutes m = duration_cast<minutes>(tp);
    tp -= m;
    seconds s = duration_cast<seconds>(tp);
    tp -= s;

    time_t tt = system_clock::to_time_t(now);
    tm utc_tm = *gmtime(&tt);

    data->Header.TimeStamp.Seconds = utc_tm.tm_sec;
    data->Header.TimeStamp.Minutes = utc_tm.tm_min;
    data->Header.TimeStamp.Hours = utc_tm.tm_hour;
    data->Header.TimeStamp.Flag = 1;
    data->Header.TimeStamp.Day = utc_tm.tm_mday;
    data->Header.TimeStamp.Month = utc_tm.tm_mon + 1;
    data->Header.TimeStamp.Year = utc_tm.tm_year;
    data->Header.TimeStamp.Century = 20 + utc_tm.tm_year / 100;
    data->Header.TimeStamp.Year = data->Header.TimeStamp.Year % 100;
}

template <typename T>
void dump_error_descriptor_section(const std::shared_ptr<T>& data,
                                   uint16_t SectionCount, std::string ErrorType,
                                   uint32_t* Severity)
{
    for (int i = 0; i < SectionCount; i++)
    {

        if (ErrorType == FATAL_ERR)
        {
            data->SectionDescriptor[i].SectionOffset =
                sizeof(COMMON_ERROR_RECORD_HEADER) +
                (INDEX_2 * sizeof(ERROR_SECTION_DESCRIPTOR));
            data->SectionDescriptor[i].SectionLength = sizeof(ERROR_RECORD);
            data->SectionDescriptor[i].SectionType = AMD_OOB_CRASHDUMP;
            data->SectionDescriptor[i].Severity = CPER_SEV_FATAL;
            data->SectionDescriptor[INDEX_0].FRUText[INDEX_0] = 'P';
            data->SectionDescriptor[INDEX_0].FRUText[INDEX_1] = '0';
            data->SectionDescriptor[INDEX_1].FRUText[INDEX_0] = 'P';
            data->SectionDescriptor[INDEX_1].FRUText[INDEX_1] = '1';
        }
        else if ((ErrorType == RUNTIME_MCA_ERR) ||
                 (ErrorType == RUNTIME_DRAM_ERR))
        {
            data->SectionDescriptor[i].SectionOffset =
                sizeof(common_error_record_header) +
                (sizeof(error_section_descriptor) * SectionCount) +
                (sizeof(proc_error_section) * i);
            data->SectionDescriptor[i].SectionLength =
                sizeof(proc_error_section);
            data->SectionDescriptor[i].SectionType = PROC_ERR_SECTION_TYPE;
            data->SectionDescriptor[i].Severity = Severity[i];

            if (strcasecmp(data->SectionDescriptor[i].FRUText, "null") ==
                INDEX_0)
            {
                std::strcpy(data->SectionDescriptor[i].FRUText, "MemoryError");
            }
            else if (data->SectionDescriptor[i].FRUText[INDEX_0] == '\0')
            {
                if (ErrorType == RUNTIME_MCA_ERR)
                {
                    std::strcpy(data->SectionDescriptor[i].FRUText,
                                "ProcessorError");
                }
                else if (ErrorType == RUNTIME_DRAM_ERR)
                {
                    std::strcpy(data->SectionDescriptor[i].FRUText,
                                "DramCeccError");
                }
            }
        }
        else if (ErrorType == RUNTIME_PCIE_ERR)
        {
            data->SectionDescriptor[i].SectionOffset =
                sizeof(common_error_record_header) +
                (sizeof(error_section_descriptor) * SectionCount) +
                (i * sizeof(pcie_error_section));
            data->SectionDescriptor[i].SectionLength =
                sizeof(pcie_error_section);
            data->SectionDescriptor[i].SectionType = PCIE_ERR_SECTION_TYPE;
            data->SectionDescriptor[i].Severity = Severity[i];
            std::strcpy(data->SectionDescriptor[i].FRUText, "PcieError");
        }

        data->SectionDescriptor[i].RevisionMinor = CPER_MINOR_REV;

        if (FamilyId == TURIN_FAMILY_ID)
        {
            data->SectionDescriptor[i].RevisionMajor =
                ((ADDC_GEN_NUMBER_2 & INT_15) << SHIFT_4) | ProgId;
        }
        else if (FamilyId == GENOA_FAMILY_ID)
        {
            data->SectionDescriptor[i].RevisionMajor =
                ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | ProgId;
        }

        data->SectionDescriptor[i].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
        data->SectionDescriptor[i].SectionFlags = CPER_PRIMARY;
    }
}

template <typename T>
void dump_cper_header_section(const std::shared_ptr<T>& data,
                              uint16_t SectionCount, uint32_t ErrorSeverity,
                              std::string ErrorType)
{
    /*ASCII 4-character array “CPER” (0x43, 0x50, 0x45, 0x52) */
    memcpy(data->Header.Signature, CPER_SIG_RECORD, CPER_SIG_SIZE);

    data->Header.Revision = CPER_RECORD_REV; /*(0x100)*/

    data->Header.SignatureEnd = CPER_SIG_END; /*(0xFFFFFFFF)*/

    /*Number of valid sections associated with the record*/
    data->Header.SectionCount = SectionCount;

    /*0 - Non-fatal uncorrected ; 1 - Fatal ; 2 - Corrected*/
    data->Header.ErrorSeverity = ErrorSeverity;

    /*Bit 0 = 1 -> PlatformID field contains valid info
      Bit 1 = 1 -> TimeStamp field contains valid info
      Bit 2 = 1 -> PartitionID field contains valid info*/
    data->Header.ValidationBits =
        (CPER_VALID_PLATFORM_ID | CPER_VALID_TIMESTAMP);

    /*Size of whole CPER record*/
    if ((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR))
    {
        data->Header.RecordLength =
            sizeof(common_error_record_header) +
            sizeof(error_section_descriptor) * SectionCount +
            sizeof(proc_error_section) * SectionCount;
    }
    if (ErrorType == RUNTIME_PCIE_ERR)
    {
        data->Header.RecordLength =
            sizeof(common_error_record_header) +
            (sizeof(error_section_descriptor) * SectionCount) +
            (sizeof(pcie_error_section) * SectionCount);
        sd_journal_print(LOG_INFO, "Size of pcie erorr section = %d\n",
                         (sizeof(pcie_error_section)));
    }
    else if (ErrorType == FATAL_ERR)
    {
        data->Header.RecordLength = sizeof(CPER_RECORD);
    }

    /*TimeStamp when OOB controller received the event*/
    calculate_time_stamp(data);

    data->Header.PlatformId[INDEX_0] = board_id;

    data->Header.CreatorId = CPER_CREATOR_PSTORE;

    if (ErrorType == RUNTIME_PCIE_ERR)
    {
        data->Header.NotifyType = CPER_NOTIFY_PCIE;
    }
    else if ((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR))
    {
        if (ErrorSeverity == SEV_NON_FATAL_CORRECTED)
        {
            data->Header.NotifyType = CPER_NOTIFY_CMC;
        }
        else
        {
            data->Header.NotifyType = CPER_NOTIFY_MCE;
        }
    }

    /*Starts at 1 and increments at each time when cper file is generated*/
    data->Header.RecordId = RecordId++;
}

template <typename T>
void dump_proc_error_info_section(const std::shared_ptr<T>& ProcPtr,
                                  uint8_t soc_num, uint16_t SectionCount,
                                  uint64_t* CheckInfo, uint32_t SectionStart)
{

    for (uint32_t i = SectionStart; i < SectionCount; i++)
    {
        ProcPtr->ProcErrorSection[i].ProcInfoSection.ValidBits =
            0b11 | (SectionCount << INDEX_2) | (SectionCount << INDEX_8);

        if (soc_num == p0_info)
        {
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_0] =
                p0_eax;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_2] =
                p0_ebx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_4] =
                p0_ecx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_6] =
                p0_edx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CPUAPICId =
                ((p0_ebx >> SHIFT_24) & INT_255);
        }
        if (soc_num == p1_info)
        {
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_0] =
                p1_eax;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_2] =
                p1_ebx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_4] =
                p1_ecx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CpuId[INDEX_6] =
                p1_edx;
            ProcPtr->ProcErrorSection[i].ProcInfoSection.CPUAPICId =
                ((p1_ebx >> SHIFT_24) & INT_255);
        }

        ProcPtr->ProcErrorSection[i].ProcErrorInfo.ErrorType = MS_CHECK_GUID;
        ProcPtr->ProcErrorSection[i].ProcErrorInfo.ValidationBits = ENABLE_BIT;
        ProcPtr->ProcErrorSection[i].ProcErrorInfo.CheckInfo = CheckInfo[i];
        ProcPtr->ProcErrorSection[i].ProcContextStruct.RegContextType =
            ENABLE_BIT;
        ProcPtr->ProcErrorSection[i].ProcContextStruct.RegArraySize =
            MCA_BANK_MAX_OFFSET;
    }
}

inline std::string getCperFilename(int num)
{
    return "ras-error" + std::to_string(num) + ".cper";
}

template <typename T>
void write_to_cper_file(const std::shared_ptr<T>& data, std::string ErrorType,
                        uint16_t SectionCount)
{

    static std::mutex index_file_mtx;
    std::unique_lock lock(index_file_mtx);

    std::string cperFileName;
    FILE* file;

    std::shared_ptr<PROC_RUNTIME_ERR_RECORD> ProcPtr;
    std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> PciePtr;
    std::shared_ptr<CPER_RECORD> FatalPtr;

    if constexpr (std::is_same_v<T, PROC_RUNTIME_ERR_RECORD>)
    {
        ProcPtr = std::static_pointer_cast<PROC_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, PCIE_RUNTIME_ERR_RECORD>)
    {
        PciePtr = std::static_pointer_cast<PCIE_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, CPER_RECORD>)
    {
        FatalPtr = std::static_pointer_cast<CPER_RECORD>(data);
    }

    cperFileName = getCperFilename(err_count);

    for (const auto& entry : std::filesystem::directory_iterator(kRasDir))
    {
        std::string filename = entry.path().filename().string();
        if (filename.size() >= cperFileName.size() &&
            filename.substr(filename.size() - cperFileName.size()) ==
                cperFileName)
        {
            std::filesystem::remove(entry.path());
        }
    }

    if (ErrorType == RUNTIME_MCA_ERR)
    {
        cperFileName = "mca-runtime-" + cperFileName;
    }
    else if (ErrorType == RUNTIME_DRAM_ERR)
    {
        cperFileName = "dram-runtime-" + cperFileName;
    }
    else if (ErrorType == RUNTIME_PCIE_ERR)
    {
        cperFileName = "pcie-runtime-" + cperFileName;
    }

    std::string cperFilePath = kRasDir.data() + cperFileName;

    file = fopen(cperFilePath.c_str(), "w");

    if ((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR))
    {
        if ((ProcPtr) && (file != NULL))
        {
            sd_journal_print(LOG_INFO, "Generating CPER file\n");

            fwrite(&ProcPtr->Header, sizeof(common_error_record_header), 1,
                   file);

            fwrite(ProcPtr->SectionDescriptor,
                   sizeof(error_section_descriptor) * SectionCount, 1, file);

            fwrite(ProcPtr->ProcErrorSection,
                   sizeof(proc_error_section) * SectionCount, 1, file);

            exportCrashdumpToDBus(err_count, ProcPtr->Header.TimeStamp);
        }
    }
    else if (ErrorType == FATAL_ERR)
    {
        if ((FatalPtr) && (file != NULL))
        {
            sd_journal_print(LOG_INFO,
                             "Generating CPER file for the fatal error\n");

            fwrite(FatalPtr.get(), FatalPtr->Header.RecordLength, 1, file);

            exportCrashdumpToDBus(err_count, FatalPtr->Header.TimeStamp);
        }
    }
    else if (ErrorType == RUNTIME_PCIE_ERR)
    {
        sd_journal_print(LOG_INFO, "Generating CPER file for the PCIE error\n");
        fwrite(&PciePtr->Header, sizeof(common_error_record_header), 1, file);
        fwrite(PciePtr->SectionDescriptor,
               sizeof(error_section_descriptor) * SectionCount, 1, file);
        fwrite(PciePtr->PcieErrorSection,
               sizeof(pcie_error_section) * SectionCount, 1, file);
        exportCrashdumpToDBus(err_count, PciePtr->Header.TimeStamp);
    }
    fclose(file);

    err_count++;

    if (err_count >= MAX_ERROR_FILE)
    {
        /*The maximum number of error files supported is 10.
          The counter will be rotated once it reaches max count*/
        err_count = (err_count % MAX_ERROR_FILE);
    }

    file = fopen(index_file, "w");
    if (file != NULL)
    {
        fprintf(file, "%d", err_count);
        fclose(file);
    }

    lock.unlock();
}

/*explicitly instantiate the template function for each type*/
template void
    calculate_time_stamp<CPER_RECORD>(const std::shared_ptr<CPER_RECORD>&);
template void calculate_time_stamp<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&);
template void calculate_time_stamp<PCIE_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&);

template void dump_error_descriptor_section<CPER_RECORD>(
    const std::shared_ptr<CPER_RECORD>&, uint16_t, std::string, uint32_t*);
template void dump_error_descriptor_section<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&, uint16_t, std::string,
    uint32_t*);
template void dump_error_descriptor_section<PCIE_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&, uint16_t, std::string,
    uint32_t*);

template void
    dump_cper_header_section<CPER_RECORD>(const std::shared_ptr<CPER_RECORD>&,
                                          uint16_t, uint32_t, std::string);
template void dump_cper_header_section<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&, uint16_t, uint32_t,
    std::string);
template void dump_cper_header_section<PCIE_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&, uint16_t, uint32_t,
    std::string);

template void
    write_to_cper_file<CPER_RECORD>(const std::shared_ptr<CPER_RECORD>&,
                                    std::string, uint16_t);
template void write_to_cper_file<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&, std::string, uint16_t);
template void write_to_cper_file<PCIE_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&, std::string, uint16_t);

template void dump_proc_error_section<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&, uint8_t,
    struct ras_rt_valid_err_inst, uint8_t, uint16_t, uint32_t*, uint64_t*);
template void dump_proc_error_section<PCIE_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&, uint8_t,
    struct ras_rt_valid_err_inst, uint8_t, uint16_t, uint32_t*, uint64_t*);
template void dump_pcie_error_info_section(
    const std::shared_ptr<PCIE_RUNTIME_ERR_RECORD>&, uint16_t, uint16_t);
template void dump_proc_error_info_section<PROC_RUNTIME_ERR_RECORD>(
    const std::shared_ptr<PROC_RUNTIME_ERR_RECORD>&, uint8_t, uint16_t,
    uint64_t*, uint32_t);
