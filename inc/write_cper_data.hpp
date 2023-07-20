#include "ras.hpp"
#include "cper.hpp"
#include "cper_runtime.hpp"

template<typename T>
void calculate_time_stamp(const std::shared_ptr<T>& data)
{
    using namespace std;
    using namespace std::chrono;
    typedef duration<int, ratio_multiply<hours::period, ratio<24> >::type> days;

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
    data->Header.TimeStamp.Century = 20 + utc_tm.tm_year/100;
    data->Header.TimeStamp.Year = data->Header.TimeStamp.Year % 100;
}

template<typename T>
void dump_error_descriptor_section(const std::shared_ptr<T>& data,uint16_t SectionCount,
                std::string ErrorType,uint32_t *Severity)
{
    for(int i = 0 ; i < SectionCount ; i++)
    {

        if(ErrorType == FATAL_ERR)
        {
            data->SectionDescriptor[i].SectionOffset = sizeof(COMMON_ERROR_RECORD_HEADER) +
                                   (INDEX_2 * sizeof(ERROR_SECTION_DESCRIPTOR));
            data->SectionDescriptor[i].SectionLength = sizeof(ERROR_RECORD);
            data->SectionDescriptor[i].SectionType = AMD_OOB_CRASHDUMP;
            data->SectionDescriptor[i].Severity = CPER_SEV_FATAL;
            data->SectionDescriptor[INDEX_0].FRUText[INDEX_0] = 'P';
            data->SectionDescriptor[INDEX_0].FRUText[INDEX_1] = '0';
            data->SectionDescriptor[INDEX_1].FRUText[INDEX_0] = 'P';
            data->SectionDescriptor[INDEX_1].FRUText[INDEX_1] = '1';
        }
        else if((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR))
        {
            data->SectionDescriptor[i].SectionOffset =  sizeof(common_error_record_header) +
                                                       (sizeof(error_section_descriptor) * SectionCount) +
                                                       (sizeof(proc_error_section) * i);
            data->SectionDescriptor[i].SectionLength = sizeof(proc_error_section);
            data->SectionDescriptor[i].SectionType = PROC_ERR_SECTION_TYPE; 
            data->SectionDescriptor[i].Severity = Severity[i];

            if(ErrorType == RUNTIME_MCA_ERR)
            {
                std::strcpy(data->SectionDescriptor[i].FRUText,"ProcessorError");
            }
            if(ErrorType == RUNTIME_DRAM_ERR)
            {
                std::strcpy(data->SectionDescriptor[i].FRUText,"DramCeccError");
            }
        }
        else if(ErrorType == RUNTIME_PCIE_ERR)
        {
            data->SectionDescriptor[i].SectionOffset = sizeof(common_error_record_header) + 
                                                       (sizeof(error_section_descriptor) * SectionCount) +
                                                       (i * sizeof(pcie_error_section));
            data->SectionDescriptor[i].SectionLength = sizeof(pcie_error_section);
            data->SectionDescriptor[i].SectionType = PCIE_ERR_SECTION_TYPE;
            data->SectionDescriptor[i].Severity = Severity[i];
            std::strcpy(data->SectionDescriptor[i].FRUText,"PcieError");
        }

        data->SectionDescriptor[i].RevisionMinor = CPER_MINOR_REV;

        if(GenoaPlatform == true)
        {
            data->SectionDescriptor[i].RevisionMajor = ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | EPYC_PROG_SEG_ID;
        } else if(TurinPlatform == true)
        {
            data->SectionDescriptor[i].RevisionMajor = ((ADDC_GEN_NUMBER_2 & INT_15) << SHIFT_4) | EPYC_PROG_SEG_ID;
        }

        data->SectionDescriptor[i].SecValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
        data->SectionDescriptor[i].SectionFlags = CPER_PRIMARY;
    }
}

template<typename T>
void dump_cper_header_section(const std::shared_ptr<T>& data, uint16_t SectionCount,
                              uint32_t ErrorSeverity, std::string ErrorType)
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
    data->Header.ValidationBits = (CPER_VALID_PLATFORM_ID | CPER_VALID_TIMESTAMP);

    /*Size of whole CPER record*/
    if((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR))
    {
        data->Header.RecordLength = sizeof(common_error_record_header) +
                                    sizeof(error_section_descriptor) * SectionCount +
                                    sizeof(proc_error_section) * SectionCount;
    }
    if(ErrorType == RUNTIME_PCIE_ERR)
    {
        data->Header.RecordLength = sizeof(common_error_record_header) +
                                    (sizeof(error_section_descriptor) * SectionCount) +
                                    (sizeof(pcie_error_section) * SectionCount);
        sd_journal_print(LOG_INFO, "Size of pcie erorr section = %d\n",(sizeof(pcie_error_section)));
    }
    else if(ErrorType == FATAL_ERR)
    {
        data->Header.RecordLength = sizeof(CPER_RECORD);
    }

    /*TimeStamp when OOB controller received the event*/
    calculate_time_stamp(data);

    data->Header.PlatformId[INDEX_0] = board_id;

    data->Header.CreatorId = CPER_CREATOR_PSTORE;

    if(ErrorType == RUNTIME_PCIE_ERR)
    {
        data->Header.NotifyType = CPER_NOTIFY_PCIE;
    }
    else if((ErrorType == RUNTIME_MCA_ERR ) || (ErrorType == RUNTIME_DRAM_ERR))
    {
        if(ErrorSeverity == SEV_NON_FATAL_CORRECTED)
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

inline std::string getCperFilename(int num) {
    return "ras-error" + std::to_string(num) + ".cper";
}

template<typename T>
void write_to_cper_file(const std::shared_ptr<T>& data,std::string ErrorType,uint16_t SectionCount )
{

    std::string cperFileName;
    FILE *file;

    std::shared_ptr<PROC_RUNTIME_ERR_RECORD> ProcPtr;
    std::shared_ptr<PCIE_RUNTIME_ERR_RECORD> PciePtr;
    std::shared_ptr<CPER_RECORD> FatalPtr;
  
    if constexpr (std::is_same_v<T, PROC_RUNTIME_ERR_RECORD>) {
        ProcPtr = std::static_pointer_cast<PROC_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, PCIE_RUNTIME_ERR_RECORD>) {
        PciePtr = std::static_pointer_cast<PCIE_RUNTIME_ERR_RECORD>(data);
    }
    if constexpr (std::is_same_v<T, CPER_RECORD>) {
        FatalPtr = std::static_pointer_cast<CPER_RECORD>(data);
    }

    cperFileName = getCperFilename(err_count);

    for (const auto& entry : std::filesystem::directory_iterator(kRasDir))
    {
        std::string filename = entry.path().filename().string();
        if(filename.size() >= cperFileName.size() &&
                 filename.substr(filename.size() - cperFileName.size()) == cperFileName)
        {
            std::filesystem::remove(entry.path());
        }
    }

    if(ErrorType == RUNTIME_MCA_ERR)
    {
        cperFileName = "mca-" + cperFileName;
    }
    else if(ErrorType == RUNTIME_DRAM_ERR)
    {
        cperFileName = "dram-" + cperFileName;
    }
    else if(ErrorType == RUNTIME_PCIE_ERR)
    {
        cperFileName = "pcie-" + cperFileName;
    }

    static std::mutex index_file_mtx;
    std::unique_lock lock(index_file_mtx);

    std::string cperFilePath = kRasDir.data() + cperFileName;
    err_count++;

    if(err_count >= MAX_ERROR_FILE)
    {
        /*The maximum number of error files supported is 10.
          The counter will be rotated once it reaches max count*/
          err_count = (err_count % MAX_ERROR_FILE);
    }

    file = fopen(index_file, "w");
    if(file != NULL)
    {
        fprintf(file,"%d",err_count);
        fclose(file);
    }
    lock.unlock();

    file = fopen(cperFilePath.c_str(), "w");

    if((ErrorType == RUNTIME_MCA_ERR) || (ErrorType == RUNTIME_DRAM_ERR)) 
    {
        if ((ProcPtr) && (file != NULL)) {
            sd_journal_print(LOG_INFO, "Generating CPER file\n");

            fwrite(&ProcPtr->Header,sizeof(common_error_record_header),1,file);

            fwrite(ProcPtr->SectionDescriptor,sizeof(error_section_descriptor) * SectionCount,1,file);

            fwrite(ProcPtr->ProcErrorSection,sizeof(proc_error_section) * SectionCount,1,file);
        }
    }else if(ErrorType == FATAL_ERR)
    {
        if ((FatalPtr) && (file != NULL)) {
            sd_journal_print(LOG_DEBUG, "Generating CPER file\n");
                fwrite(FatalPtr.get(), data->Header.RecordLength, 1, file);
        }
    }
    else if(ErrorType == RUNTIME_PCIE_ERR)
    {
        fwrite(&PciePtr->Header,sizeof(common_error_record_header),1,file);
        fwrite(PciePtr->SectionDescriptor,sizeof(error_section_descriptor) * SectionCount,1,file);
        fwrite(PciePtr->PcieErrorSection,sizeof(pcie_error_section) * SectionCount,1,file);
    }

    fclose(file);
}
