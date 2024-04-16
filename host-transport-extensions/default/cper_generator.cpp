#include "cper_generator.hpp"

#include "interface_manager.hpp"

template <typename T>
GUID_T CperGenerator<T>::initializeGUID(unsigned int a, unsigned short b,
                                        unsigned short c, unsigned char d0,
                                        unsigned char d1, unsigned char d2,
                                        unsigned char d3, unsigned char d4,
                                        unsigned char d5, unsigned char d6,
                                        unsigned char d7)
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

template <typename T>
void CperGenerator<T>::calculateTimeStamp(const std::shared_ptr<T>& data)
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

    data->header.timeStamp.seconds = utc_tm.tm_sec;
    data->header.timeStamp.minutes = utc_tm.tm_min;
    data->header.timeStamp.hours = utc_tm.tm_hour;
    data->header.timeStamp.flag = 1;
    data->header.timeStamp.day = utc_tm.tm_mday;
    data->header.timeStamp.month = utc_tm.tm_mon + 1;
    data->header.timeStamp.year = utc_tm.tm_year;
    data->header.timeStamp.century = 20 + utc_tm.tm_year / 100;
    data->header.timeStamp.year = data->header.timeStamp.year % 100;
}

template <typename T>
void CperGenerator<T>::dumpCperHeaderSection(const std::shared_ptr<T>& data,
                                             uint16_t sectionCount,
                                             uint32_t errorSeverity,
                                             std::string errorType)
{

    /*ASCII 4-character array “CPER” (0x43, 0x50, 0x45, 0x52) */
    memcpy(data->header.signature, CPER_SIG_RECORD.data(), CPER_SIG_SIZE);

    data->header.revision = CPER_RECORD_REV; /*(0x100)*/

    data->header.signatureEnd = CPER_SIG_END; /*(0xFFFFFFFF)*/

    /*Number of valid sections associated with the record*/
    data->header.sectionCount = sectionCount;

    /*0 - Non-fatal uncorrected ; 1 - Fatal ; 2 - Corrected*/
    data->header.errorSeverity = errorSeverity;

    /*Bit 0 = 1 -> PlatformID field contains valid info
      Bit 1 = 1 -> TimeStamp field contains valid info
      Bit 2 = 1 -> PartitionID field contains valid info*/
    data->header.validationBits =
        (CPER_VALID_PLATFORM_ID | CPER_VALID_TIMESTAMP);

    /*Size of whole CPER record*/
    if ((errorType == RUNTIME_MCA_ERR) || (errorType == RUNTIME_DRAM_ERR))
    {
        data->header.recordLength =
            sizeof(ErrorRecordHeader) +
            sizeof(ErrorSectionDescriptor) * sectionCount +
            sizeof(ProcErrorSection) * sectionCount;
    }
    if (errorType == RUNTIME_PCIE_ERR)
    {
        data->header.recordLength =
            sizeof(ErrorRecordHeader) +
            (sizeof(ErrorSectionDescriptor) * sectionCount) +
            (sizeof(PcieErrorSection) * sectionCount);
    }
    else if (errorType == FATAL_ERR)
    {
        data->header.recordLength =
            sizeof(ErrorRecordHeader) +
            (sizeof(ErrorSectionDescriptor) * sectionCount) +
            (sizeof(ErrorRecord) * sectionCount);
    }

    /*TimeStamp when OOB controller received the event*/
    calculateTimeStamp(data);

    data->header.platformId[INDEX_0] = boardId;

    data->header.creatorId =
        initializeGUID(0x61fa3fac, 0xcb80, 0x4292, 0x8b, 0xfb, 0xd6, 0x43, 0xb1,
                       0xde, 0x17, 0xf4);

    if (errorType == RUNTIME_PCIE_ERR)
    {
        data->header.notifyType =
            initializeGUID(0xCF93C01F, 0x1A16, 0x4dfc, 0xB8, 0xBC, 0x9C, 0x4D,
                           0xAF, 0x67, 0xC1, 0x04);
    }
    else if ((errorType == RUNTIME_MCA_ERR) || (errorType == RUNTIME_DRAM_ERR))
    {
        if (errorSeverity == SEV_NON_FATAL_CORRECTED)
        {
            data->header.notifyType =
                initializeGUID(0x2DCE8BB1, 0xBDD7, 0x450e, 0xB9, 0xAD, 0x9C,
                               0xF4, 0xEB, 0xD4, 0xF8, 0x90);
        }
        else
        {
            data->header.notifyType =
                initializeGUID(0xE8F56FFE, 0x919C, 0x4cc5, 0xBA, 0x88, 0x65,
                               0xAB, 0xE1, 0x49, 0x13, 0xBB);
        }
    }

    /*Starts at 1 and increments at each time when cper file is generated*/
    data->header.recordId = recordId++;
}

template <typename T>
void CperGenerator<T>::dumpErrorDescriptorSection(
    const std::shared_ptr<T>& data, uint16_t sectionCount,
    std::string errorType, uint32_t* severity)
{
    for (int i = 0; i < sectionCount; i++)
    {

        if (errorType == FATAL_ERR)
        {
            data->sectionDescriptor[i].sectionOffset =
                sizeof(ErrorRecordHeader) +
                (INDEX_2 * sizeof(ErrorSectionDescriptor)) +
                (i * sizeof(ErrorRecord));

            data->sectionDescriptor[i].sectionLength = sizeof(ErrorRecord);

            data->sectionDescriptor[i].sectionType =
                initializeGUID(0x32AC0C78, 0x2623, 0x48F6, 0xB0, 0xD0, 0x73,
                               0x65, 0x72, 0x5F, 0xD6, 0xAE);

            data->sectionDescriptor[i].severity = CPER_SEV_FATAL;

            data->sectionDescriptor[i].fruText[INDEX_0] = 'P';
            data->sectionDescriptor[i].fruText[INDEX_1] = '0' + i;
        }

        data->sectionDescriptor[i].revisionMinor = CPER_MINOR_REV;

        if (familyId == TURIN_FAMILY_ID)
        {
            data->sectionDescriptor[i].revisionMajor =
                ((ADDC_GEN_NUMBER_2 & INT_15) << SHIFT_4) | progId;
        }
        else if (familyId == GENOA_FAMILY_ID)
        {
            data->sectionDescriptor[i].revisionMajor =
                ((ADDC_GEN_NUMBER_1 & INT_15) << SHIFT_4) | progId;
        }

        data->sectionDescriptor[i].secValidMask = FRU_ID_VALID | FRU_TEXT_VALID;
        data->sectionDescriptor[i].sectionFlags = CPER_PRIMARY;
    }
}

template <typename T>
void CperGenerator<T>::dumpProcessorErrorSection(
    const std::shared_ptr<CperRecord>& fatalPtr, uint8_t info,
    uint16_t sectionCount, CpuId* cpuId)
{
    for (int i = 0; i < numOfCpu; i++)
    {
        fatalPtr->errorRecord[i].procError.validBits =
            CPU_ID_VALID | LOCAL_APIC_ID_VALID;
        fatalPtr->errorRecord[i].procError.cpuId[INDEX_0] = cpuId[i].eax;
        fatalPtr->errorRecord[i].procError.cpuId[INDEX_2] = cpuId[i].ebx;
        fatalPtr->errorRecord[i].procError.cpuId[INDEX_4] = cpuId[i].ecx;
        fatalPtr->errorRecord[i].procError.cpuId[INDEX_6] = cpuId[i].edx;
        fatalPtr->errorRecord[i].procError.cpuApicId =
            ((cpuId[i].ebx >> SHIFT_24) & INT_15);

        if (i == info)
        {
            fatalPtr->errorRecord[i].procError.validBits |=
                PROC_CONTEXT_STRUCT_VALID;
        }
    }
}

template <typename T>
void CperGenerator<T>::getLastTransAddr(
    const std::shared_ptr<CperRecord>& fatalPtr, uint8_t info)
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
        lg2::error("Failed to read RAS DF validity check");
    }
    else
    {
        if (err_chk.df_block_instances != 0)
        {
            lg2::info("Harvesting last transaction address");

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

                    fatalPtr->errorRecord[info]
                        .contextInfo.dfDumpData.lastTransAddr[n]
                        .wdtData[offset] = data;
                }
                n++;
            }
        }
    }
}

template <typename T>
void CperGenerator<T>::harvestDebugLogDump(
    const std::shared_ptr<CperRecord>& fatalPtr, uint8_t info, uint8_t blk_id,
    int64_t* apmlRetryCount, uint16_t& debugLogIdOffset)
{
    oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
    uint16_t retries = 0;
    uint16_t n = 0;
    uint16_t maxOffset32;
    uint32_t data;
    struct ras_df_err_chk err_chk;
    union ras_df_err_dump df_err = {0};

    while (ret != OOB_SUCCESS)
    {

        retries++;

        ret = read_ras_df_err_validity_check(info, blk_id, &err_chk);

        if (ret == OOB_SUCCESS)
        {
            lg2::info(
                "Socket: {SOCKET},Debug Log ID : {DBG_ID} read successful",
                "SOCKET", info, "DBG_ID", blk_id);
            break;
        }

        if (retries > *apmlRetryCount)
        {
            lg2::error("Socket: {SOCKET},Debug Log ID : {DBG_ID} read failed",
                       "SOCKET", info, "DBG_ID", blk_id);

            /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE
             * dump region*/
            fatalPtr->errorRecord[info]
                .contextInfo.debugLogIdData[debugLogIdOffset++] = blk_id;
            fatalPtr->errorRecord[info]
                .contextInfo.debugLogIdData[debugLogIdOffset++] = BAD_DATA;
            fatalPtr->errorRecord[info]
                .contextInfo.debugLogIdData[debugLogIdOffset++] = BAD_DATA;
            fatalPtr->errorRecord[info]
                .contextInfo.debugLogIdData[debugLogIdOffset++] = BAD_DATA;

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

            fatalPtr->errorRecord[info]
                .contextInfo.debugLogIdData[debugLogIdOffset++] =
                DbgLogIdHeader;

            maxOffset32 = ((err_chk.err_log_len % BYTE_4) ? INDEX_1 : INDEX_0) +
                          (err_chk.err_log_len >> BYTE_2);

            while (n < err_chk.df_block_instances)
            {
                bool apmlHang = false;

                for (int offset = 0; offset < maxOffset32; offset++)
                {

                    lg2::info("Harvtesing debug log ID dumps");

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
                            uint16_t retryCount = *apmlRetryCount;

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
                                lg2::error("Failed to read debug log dump for "
                                           "debug log ID : {BLK_ID}",
                                           "BLK_ID", blk_id);
                                data = BAD_DATA;
                                /*the Dump APML command fails in the middle of
                                  the iterative loop, then write BAADDA7A for
                                  the remaining iterations in the for loop*/
                                apmlHang = true;
                            }
                        }
                    }

                    fatalPtr->errorRecord[info]
                        .contextInfo.debugLogIdData[debugLogIdOffset++] = data;
                }
                n++;
            }
        }
    }
}

template <typename T>
void CperGenerator<T>::dumpContextInfo(
    const std::shared_ptr<CperRecord>& fatalPtr, uint16_t numbanks,
    uint16_t bytespermca, uint8_t info, uint16_t sectionCount,
    std::vector<uint8_t> blockId, uint64_t* ppin, uint32_t* uCode,
    int64_t* apmlRetryCount)
{
    for (int i = 0; i < numOfCpu; i++)
    {
        uint8_t blk_id;

        getLastTransAddr(fatalPtr, i);

        uint16_t debugLogIdOffset = 0;

        for (blk_id = 0; blk_id < blockId.size(); blk_id++)
        {
            harvestDebugLogDump(fatalPtr, i, blockId[blk_id], apmlRetryCount,
                                debugLogIdOffset);
        }

        fatalPtr->errorRecord[i].contextInfo.ppin = ppin[i];

        if (i == info)
        {
            fatalPtr->errorRecord[i].contextInfo.registerContextType =
                CTX_OOB_CRASH;
            fatalPtr->errorRecord[i].contextInfo.registerArraySize =
                numbanks * bytespermca;
        }
    }
}

template <typename T>
std::string CperGenerator<T>::getCperFilename(int num)
{
    return "ras-error" + std::to_string(num) + ".cper";
}

template <typename T>
void CperGenerator<T>::cperFileWrite(const std::shared_ptr<T>& data,
                                     std::string errorType,
                                     uint16_t sectionCount)
{

    static std::mutex index_file_mtx;
    std::unique_lock lock(index_file_mtx);

    std::string cperFileName;
    FILE* file;

    std::shared_ptr<CperRecord> fatalPtr;

    if constexpr (std::is_same_v<T, CperRecord>)
    {
        fatalPtr = std::static_pointer_cast<CperRecord>(data);
    }

    cperFileName = getCperFilename(errCount);

    for (const auto& entry : std::filesystem::directory_iterator(RAS_DIR))
    {
        std::string filename = entry.path().filename().string();
        if (filename.size() >= cperFileName.size() &&
            filename.substr(filename.size() - cperFileName.size()) ==
                cperFileName)
        {
            std::filesystem::remove(entry.path());
        }
    }

    std::string cperFilePath = RAS_DIR + cperFileName;

    file = fopen(cperFilePath.c_str(), "w");

    if (errorType == FATAL_ERR)
    {
        if ((fatalPtr) && (file != NULL))
        {
            lg2::info("Generating CPER file for the fatal error");

            fwrite(&fatalPtr->header, sizeof(ErrorRecordHeader), 1, file);
            fwrite(fatalPtr->sectionDescriptor,
                   sizeof(ErrorSectionDescriptor) * sectionCount, 1, file);
            fwrite(fatalPtr->errorRecord, sizeof(ErrorRecord) * sectionCount, 1,
                   file);
        }
    }

    fclose(file);

    errCount++;

    if (errCount >= MAX_ERROR_FILE)
    {
        /*The maximum number of error files supported is 10.
          The counter will be rotated once it reaches max count*/
        errCount = (errCount % MAX_ERROR_FILE);
    }

    file = fopen(INDEX_FILE.data(), "w");
    if (file != NULL)
    {
        fprintf(file, "%d", errCount);
        fclose(file);
    }

    lock.unlock();
}

template class CperGenerator<CperRecord>;
template class CperGenerator<ProcRuntimeErrRecord>;
template class CperGenerator<PcieRuntimeErrRecord>;
