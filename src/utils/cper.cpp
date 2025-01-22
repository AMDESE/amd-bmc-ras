#include "utils/cper.hpp"

#include "base_manager.hpp"
#include "crashdump_manager.hpp"
#include "oem_cper.hpp"
#include "utils/util.hpp"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <regex>

namespace amd
{
namespace ras
{
namespace util
{
namespace cper
{

constexpr std::string_view objectPath = "/com/amd/RAS";
constexpr size_t maxByte = 0xFF;
constexpr size_t singleBit = 1;
constexpr size_t doubleBit = 2;
constexpr size_t tripleBit = 3;
constexpr size_t quadBit = 4;
constexpr size_t hexBit = 6;
constexpr size_t octet = 8;
constexpr size_t nineteen = 19;
constexpr uint16_t hundred = 100;
constexpr uint16_t value256 = 0x100;
constexpr size_t maxCperCount = 10;

EFI_GUID gEfiEventCreatorIdGuid = {
    0x61FA3FAC,
    0xCB80,
    0x4292,
    {0x8B, 0xFB, 0xD6, 0x43, 0xB1, 0xDE, 0x17, 0xF4}};

EFI_GUID gEfiAmdCrashdumpGuid = {
    0x32AC0C78,
    0x2623,
    0x48F6,
    {0xB0, 0xD0, 0x73, 0x65, 0x72, 0x5F, 0xD6, 0xAE}};

EFI_GUID gEfiIa32x64ErrorTypeMsCheckGuid = {
    0x48AB7F57,
    0xDC34,
    0x4f6c,
    {0xA7, 0xD3, 0xB0, 0xB5, 0xB0, 0xA7, 0x43, 0x14}};

EFI_GUID gEfiPcieErrorSectionGuid = {
    0xd995e954,
    0xbbc1,
    0x430f,
    {0xad, 0x91, 0xb4, 0x4d, 0xcb, 0x3c, 0x6f, 0x35}};

EFI_GUID gEfiProcessorSpecificErrorSectionGuid = {
    0xdc3ea0b0,
    0xa144,
    0x4797,
    {0xb9, 0x5b, 0x53, 0xfa, 0x24, 0x2b, 0x6e, 0x1d}};

EFI_GUID gEfiEventNotificationTypePcieGuid = {
    0xCF93C01F,
    0x1A16,
    0x4dfc,
    {0xB8, 0xBC, 0x9C, 0x4D, 0xAF, 0x67, 0xC1, 0x04}};

EFI_GUID gEfiEventNotificationTypeCmcGuid = {
    0x2DCE8BB1,
    0xBDD7,
    0x450e,
    {0xB9, 0xAD, 0x9C, 0xF4, 0xEB, 0xD4, 0xF8, 0x90}};

EFI_GUID gEfiEventNotificationTypeMceGuid = {
    0xE8F56FFE,
    0x919C,
    0x4cc5,
    {0xBA, 0x88, 0x65, 0xAB, 0xE1, 0x49, 0x13, 0xBB}};

std::map<int, std::unique_ptr<CrashdumpInterface>> managers;

template void dumpHeader(const std::shared_ptr<FatalCperRecord>& data,
                         uint16_t sectionCount, uint32_t errorSeverity,
                         const std::string_view& errorType, uint32_t,
                         uint64_t& recordId);

template void dumpHeader(const std::shared_ptr<McaRuntimeCperRecord>& data,
                         uint16_t sectionCount, uint32_t errorSeverity,
                         const std::string_view& errorType, uint32_t boardId,
                         uint64_t& recordId);

template void dumpHeader(const std::shared_ptr<PcieRuntimeCperRecord>& data,
                         uint16_t sectionCount, uint32_t errorSeverity,
                         const std::string_view& errorType, uint32_t boardId,
                         uint64_t& recordId);

template void dumpErrorDescriptor(const std::shared_ptr<FatalCperRecord>&,
                                  uint16_t, const std::string_view&, uint32_t*,
                                  uint8_t);

template void dumpErrorDescriptor(const std::shared_ptr<McaRuntimeCperRecord>&,
                                  uint16_t, const std::string_view&, uint32_t*,
                                  uint8_t);

template void dumpErrorDescriptor(const std::shared_ptr<PcieRuntimeCperRecord>&,
                                  uint16_t, const std::string_view&, uint32_t*,
                                  uint8_t);

template void createFile(const std::shared_ptr<FatalCperRecord>&,
                         const std::string_view&, uint16_t, size_t&);

template void createFile(const std::shared_ptr<McaRuntimeCperRecord>&,
                         const std::string_view&, uint16_t, size_t&);

template void createFile(const std::shared_ptr<PcieRuntimeCperRecord>&,
                         const std::string_view&, uint16_t, size_t&);

std::string findCperFilename(size_t number)
{
    std::regex pattern(".*" + std::to_string(number) + "\\.cper");

    for (const auto& entry : std::filesystem::directory_iterator(RAS_DIR))
    {
        std::string filename = entry.path().filename().string();
        if (std::regex_match(filename, pattern))
        {
            return filename;
        }
    }

    return "";
}

void createIndexFile(size_t& errCount)
{
    std::string indexFile = INDEX_FILE;
    std::string rasDir = RAS_DIR;

    amd::ras::util::createFile(rasDir, indexFile);

    std::ifstream file(indexFile);
    if (file.is_open())
    {
        if (!(file >> errCount))
        {
            throw std::runtime_error("Failed to read CPER index number");
        }
        file.close();
    }
    else
    {
        throw std::runtime_error("Failed to read from index file");
    }
}

void exportToDBus(size_t num, const EFI_ERROR_TIME_STAMP& TimeStampStr,
                  sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus)
{
    if (num >= 10)
    {
        lg2::error("Crashdump only allows index 0~9\n");
        return;
    }

    const std::string filename = findCperFilename(num);
    const std::string fullFilePath = RAS_DIR + filename;

    // Use ISO-8601 as the timestamp format
    // For example: 2022-07-19T14:13:47Z
    const EFI_ERROR_TIME_STAMP& t = TimeStampStr;
    char timestamp[30];
    sprintf(timestamp, "%d-%d-%dT%d:%d:%dZ", (t.Century - 1) * hundred + t.Year,
            t.Month, t.Day, t.Hours, t.Minutes, t.Seconds);

    // Create crashdump DBus instance
    const std::string dbusPath =
        std::string(objectPath) + "/" + std::to_string(num);

    if (amd::ras::util::checkObjPath(dbusPath) == true)
    {
        auto it = managers.find(num);
        if (it != managers.end())
        {
            it->second.reset();
            managers.erase(it);
        }
    }
    std::unique_ptr<CrashdumpInterface> CperRecordMgr =
        std::make_unique<CrashdumpInterface>(objectServer, systemBus, dbusPath);

    CperRecordMgr->filename(filename);
    CperRecordMgr->log(fullFilePath);
    CperRecordMgr->timestamp(std::string{timestamp});

    managers[num] = {std::move(CperRecordMgr)};
}

void createRecord(sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus)
{
    // Check if any crashdump already exists.
    if (std::filesystem::exists(std::filesystem::path(RAS_DIR)))
    {
        std::regex pattern(".*ras-error([[:digit:]]+).cper");
        std::smatch match;
        for (const auto& p : std::filesystem::directory_iterator(
                 std::filesystem::path(RAS_DIR)))
        {
            std::string filename = p.path().filename();
            if (!std::regex_match(filename, match, pattern))
            {
                continue;
            }
            const size_t kNum = stoi(match.str(singleBit));
            const std::string cperFilename = RAS_DIR + filename;
            // exportCrashdumpToDBus needs the timestamp inside the CPER
            // file. So load it first.
            std::ifstream fin(cperFilename, std::ifstream::binary);
            if (!fin.is_open())
            {
                lg2::warning("Broken crashdump CPER file: {CPERFILE}",
                             "CPERFILE", cperFilename.c_str());
                continue;
            }
            fin.seekg(24); // Move the file pointer to offset 24
            EFI_ERROR_TIME_STAMP timestamp;

            if (!fin.read(reinterpret_cast<char*>(&timestamp),
                          sizeof(timestamp)))
            {
                lg2::info("Failed to read data from the file");
            }

            fin.close();
            exportToDBus(kNum, timestamp, objectServer, systemBus);
        }
    }
}

void dumpProcessorError(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                        uint8_t socNum, const std::unique_ptr<CpuId[]>& cpuId,
                        uint8_t cpuCount, uint16_t numbanks)
{
    for (size_t i = 0; i < cpuCount; i++)
    {
        if (i == socNum)
        {
            /*bit 0: APIC_ID Valid
              bit 1: CPUID Valid
              bit 2: RSVD
              bits 3-7: RSVD
              bits 8-13: Number of Processor Context Info structures present
              bits 14-63: RSVD*/
            fatalPtr->ErrorRecord[i].ProcError.ValidFields = tripleBit;
            fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[0] = cpuId[i].eax;
            fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[doubleBit] =
                cpuId[i].ebx;
            fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[quadBit] =
                cpuId[i].ecx;
            fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[hexBit] = cpuId[i].edx;
            fatalPtr->ErrorRecord[i].ProcError.ApicId =
                ((cpuId[i].ebx >> 24) & maxByte);

            if (numbanks != 0)
            {
                fatalPtr->ErrorRecord[i].ProcError.ValidFields |= value256;
            }
        }
    }
}

void dumpProcErrorInfoSection(
    const std::shared_ptr<McaRuntimeCperRecord>& procPtr, uint16_t sectionCount,
    uint64_t* checkInfo, uint32_t sectionStart, uint8_t cpuCount,
    const std::unique_ptr<CpuId[]>& cpuId)
{
    for (uint32_t i = sectionStart; i < sectionCount; i++)
    {
        procPtr->McaErrorInfo[i].ProcError.ValidFields =
            0b11 | (sectionCount << doubleBit) | (sectionCount << hexBit);

        for (size_t i = 0; i < cpuCount; i++)
        {
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[0] = cpuId[i].eax;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[doubleBit] =
                cpuId[i].ebx;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[quadBit] =
                cpuId[i].ecx;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[hexBit] = cpuId[i].edx;
            procPtr->McaErrorInfo[i].ProcError.ApicId =
                ((cpuId[i].ebx >> 24) & maxByte);
        }

        memcpy(&procPtr->McaErrorInfo[i].ErrorInfo.ErrorType,
               &gEfiIa32x64ErrorTypeMsCheckGuid, sizeof(EFI_GUID));
        procPtr->McaErrorInfo[i].ErrorInfo.ValidFields = singleBit;
        procPtr->McaErrorInfo[i].ErrorInfo.CheckInfo.Data64 = checkInfo[i];
        procPtr->McaErrorInfo[i].ContextInfo.RegisterType = singleBit;
        procPtr->McaErrorInfo[i].ContextInfo.ArraySize = 32;
    }
}

void dumpContext(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                 uint16_t numbanks, uint16_t bytespermca, uint8_t socNum,
                 const std::unique_ptr<uint64_t[]>& ppin,
                 const std::unique_ptr<uint32_t[]>& uCode)
{
    fatalPtr->ErrorRecord[socNum].Ppin = ppin[socNum];
    fatalPtr->ErrorRecord[socNum].MicrocodeVersion = uCode[socNum];

    if (numbanks != 0)
    {
        fatalPtr->ErrorRecord[socNum].RegisterContextType =
            singleBit; // MSR Registers
        fatalPtr->ErrorRecord[socNum].RegisterArraySize =
            numbanks * bytespermca;
    }
}

void dumpPcieErrorInfo(const std::shared_ptr<PcieRuntimeCperRecord>& data,
                       uint16_t sectionStart, uint16_t sectionCount)
{
    for (size_t i = sectionStart; i < sectionCount; i++)
    {
        data->PcieErrorData[i].ValidFields |=
            1ULL | (1ULL << singleBit) | (1ULL << tripleBit) | (1ULL << 7);
        data->PcieErrorData[i].PortType = quadBit;   // Root Port
        data->PcieErrorData[i].Version = 0x02000000; // Major = 2, Minor = 0
        data->PcieErrorData[i].DevBridge.VendorId = pcieVendorId;
    }
}

std::string getCperFilename(size_t num)
{
    return "ras-error" + std::to_string(num) + ".cper";
}

bool checkSignatureIdMatch(std::map<std::string, std::string>* configSigIdList,
                           const std::shared_ptr<FatalCperRecord>& rcd)
{
    bool ret = false;
    size_t socNum = 0;
    uint32_t tempVar[2][8];

    for (socNum = 0; socNum < socket2; socNum++)
    {
        std::memcpy(tempVar[socNum], rcd->ErrorRecord[socNum].SignatureID,
                    sizeof(tempVar[socNum]));
    }

    for (socNum = 0; socNum < socket2; socNum++)
    {
        bool equal = false;
        for (const auto& pair : *configSigIdList)
        {
            bool equal =
                amd::ras::util::compareBitwiseAnd(tempVar[socNum], pair.second);

            if (equal == true)
            {
                lg2::info(
                    "Signature ID matched with the config ile signature ID list\n");
                ret = true;
                break;
            }
        }
        if (equal == true)
        {
            break;
        }
    }
    return ret;
}

/*The function returns the highest severity out of all Section Severity for CPER
  header Severity Order = Fatal > non-fatal uncorrected > corrected*/
bool calculateSeverity(uint32_t* severity, uint16_t sectionCount,
                       uint32_t* highestSeverity,
                       const std::string_view& errorType)
{
    bool rc = true;

    *highestSeverity = sevNonFatalCorrected;

    for (size_t i = 0; i < sectionCount; i++)
    {
        if (severity[i] == singleBit) // Fatal Severity
        {
            if (errorType == runtimePcieErr)
            {
                *highestSeverity = singleBit;
                break;
            }
            else
            {
                lg2::error("Error Severity is fatal. This must be captured "
                           "in Crashdump CPER, not runtime CPER");
                rc = false;
            }
        }
        else if (severity[i] == sevNonFatalUncorrected)
        {
            *highestSeverity = sevNonFatalUncorrected;
            break;
        }
    }
    return rc;
}

template <typename PtrType>
void calculateTimestamp(const std::shared_ptr<PtrType>& data)
{
    using namespace std;
    using namespace std::chrono;
    using days = duration<int, ratio_multiply<hours::period, ratio<24>>::type>;

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
    data->Header.TimeStamp.Flag = singleBit;
    data->Header.TimeStamp.Day = utc_tm.tm_mday;
    data->Header.TimeStamp.Month = utc_tm.tm_mon + singleBit;
    data->Header.TimeStamp.Year = utc_tm.tm_year;
    data->Header.TimeStamp.Century = 20 + utc_tm.tm_year / hundred;
    data->Header.TimeStamp.Year = data->Header.TimeStamp.Year % hundred;
}

template <typename PtrType>
void dumpHeader(const std::shared_ptr<PtrType>& data, uint16_t sectionCount,
                uint32_t errorSeverity, const std::string_view& errorType,
                uint32_t boardId, uint64_t& recordId)
{
    data->Header.SignatureStart = 0x52455043; // CPER
    data->Header.Revision = value256;
    data->Header.SignatureEnd = 0xFFFFFFFF;

    /*Number of valid sections associated with the record*/
    data->Header.SectionCount = sectionCount;

    /*0 - Non-fatal uncorrected ; 1 - Fatal ; 2 - Corrected*/
    data->Header.ErrorSeverity = errorSeverity;

    /*Bit 0 = 1 -> PlatformID field contains valid info
      Bit 1 = 1 -> TimeStamp field contains valid info
      Bit 2 = 1 -> PartitionID field contains valid info*/
    data->Header.ValidationBits = (cperValidPlatformId | cperValidTimestamp);

    calculateTimestamp(data);

    data->Header.PlatformID.Data1 = boardId;

    memcpy(&data->Header.CreatorID, &gEfiEventCreatorIdGuid, sizeof(EFI_GUID));

    data->Header.RecordID = recordId++;

    /*Size of whole CPER record*/
    if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr))
    {
        data->Header.RecordLength =
            sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
            (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
            (sizeof(RUNTIME_ERROR_INFO) * sectionCount);

        if (errorSeverity == doubleBit)
        {
            memcpy(&data->Header.NotificationType,
                   &gEfiEventNotificationTypeCmcGuid, sizeof(EFI_GUID));
        }
        else
        {
            memcpy(&data->Header.NotificationType,
                   &gEfiEventNotificationTypeMceGuid, sizeof(EFI_GUID));
        }
    }
    else if (errorType == runtimePcieErr)
    {
        data->Header.RecordLength =
            sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
            (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
            (sizeof(EFI_PCIE_ERROR_DATA) * sectionCount);

        memcpy(&data->Header.NotificationType,
               &gEfiEventNotificationTypePcieGuid, sizeof(EFI_GUID));
    }
    else if (errorType == fatalErr)
    {
        data->Header.RecordLength =
            sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
            (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
            (sizeof(EFI_AMD_FATAL_ERROR_DATA) * sectionCount);
    }

    /*TimeStamp when OOB controller received the event*/
    calculateTimestamp(data);
}

template <typename PtrType>
void dumpErrorDescriptor(const std::shared_ptr<PtrType>& data,
                         uint16_t sectionCount,
                         const std::string_view& errorType, uint32_t* severity,
                         uint8_t progId)
{
    for (size_t i = 0; i < sectionCount; i++)
    {
        if (errorType == fatalErr)
        {
            /*offset in bytes of the corresponding section body
              from the base of the record header*/
            data->SectionDescriptor[i].SectionOffset =
                sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
                (sectionCount * sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) +
                (i * sizeof(EFI_AMD_FATAL_ERROR_DATA));

            /*The length in bytes of the section body*/
            data->SectionDescriptor[i].SectionLength =
                sizeof(EFI_AMD_FATAL_ERROR_DATA);

            memcpy(&data->SectionDescriptor[i].SectionType,
                   &gEfiAmdCrashdumpGuid, sizeof(EFI_GUID));

            data->SectionDescriptor[i].Severity = singleBit; // 1 = Fatal

            data->SectionDescriptor[i].FruString[0] = 'P';
            data->SectionDescriptor[i].FruString[1] = '0' + i;
        }
        else if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr))
        {
            data->SectionDescriptor[i].SectionOffset =
                sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
                (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
                (sizeof(RUNTIME_ERROR_INFO) * i);

            data->SectionDescriptor[i].SectionLength =
                sizeof(RUNTIME_ERROR_INFO);
            data->SectionDescriptor[i].SectionType =
                gEfiProcessorSpecificErrorSectionGuid;

            data->SectionDescriptor[i].Severity = severity[i];

            if (strcasecmp(data->SectionDescriptor[i].FruString, "null") == 0)
            {
                std::strncpy(data->SectionDescriptor[i].FruString,
                             "MemoryError", nineteen);
                data->SectionDescriptor[i].FruString[nineteen] = '\0';
            }
            else if (data->SectionDescriptor[i].FruString[0] == '\0')
            {
                if (errorType == runtimeMcaErr)
                {
                    std::strncpy(data->SectionDescriptor[i].FruString,
                                 "ProcessorError", nineteen);
                    data->SectionDescriptor[i].FruString[nineteen] = '\0';
                }
                else if (errorType == runtimeDramErr)
                {
                    std::strncpy(data->SectionDescriptor[i].FruString,
                                 "DramCeccError", nineteen);
                    data->SectionDescriptor[i].FruString[nineteen] = '\0';
                }
            }
        }
        else if (errorType == runtimePcieErr)
        {
            data->SectionDescriptor[i].SectionOffset =
                sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
                (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
                (i * sizeof(EFI_PCIE_ERROR_DATA));

            data->SectionDescriptor[i].SectionLength =
                sizeof(EFI_PCIE_ERROR_DATA);

            data->SectionDescriptor[i].SectionType = gEfiPcieErrorSectionGuid;

            data->SectionDescriptor[i].Severity = severity[i];

            std::strcpy(data->SectionDescriptor[i].FruString, "PcieError");
        }

        data->SectionDescriptor[i].Revision = singleBit; // 1 = EPYC

        data->SectionDescriptor[i].Revision =
            ((((addcGenNumber3 & maxByte) << quadBit) | progId) << 8) |
            minorRevision;

        /* Bit 0 - If 1, the FRUId field contains valid information
         * Bit 1 - If 1, the FRUTxt field contains valid information*/
        data->SectionDescriptor[i].SecValidMask = tripleBit;

        /*Bit 0 - Primary: FRU identified in section is
                  associated with the error condition*/
        data->SectionDescriptor[i].SectionFlags = singleBit;
    }
}

template <typename PtrType>
void createFile(const std::shared_ptr<PtrType>& data,
                const std::string_view& errorType, uint16_t sectionCount,
                size_t& errCount)
{
    static std::mutex index_file_mtx;
    std::unique_lock lock(index_file_mtx);

    std::string cperFileName;
    FILE* file;

    std::shared_ptr<McaRuntimeCperRecord> procPtr;
    std::shared_ptr<PcieRuntimeCperRecord> pciePtr;
    std::shared_ptr<FatalCperRecord> fatalPtr;

    if constexpr (std::is_same_v<PtrType, McaRuntimeCperRecord>)
    {
        procPtr = std::static_pointer_cast<McaRuntimeCperRecord>(data);
    }
    if constexpr (std::is_same_v<PtrType, PcieRuntimeCperRecord>)
    {
        pciePtr = std::static_pointer_cast<PcieRuntimeCperRecord>(data);
    }
    if constexpr (std::is_same_v<PtrType, FatalCperRecord>)
    {
        fatalPtr = std::static_pointer_cast<FatalCperRecord>(data);
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

    if (errorType == runtimeMcaErr)
    {
        cperFileName = "mca-runtime-" + cperFileName;
    }
    else if (errorType == runtimeDramErr)
    {
        cperFileName = "dram-runtime-" + cperFileName;
    }
    else if (errorType == runtimePcieErr)
    {
        cperFileName = "pcie-runtime-" + cperFileName;
    }

    std::string cperFilePath = RAS_DIR + cperFileName;
    lg2::info("Saving CPER file to {CPER}", "CPER", cperFilePath);

    file = fopen(cperFilePath.c_str(), "w");

    if (file == nullptr)
    {
        lg2::error("Cper File open afailed");
        return;
    }
    if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr))
    {
        if ((procPtr) && (file != nullptr))
        {
            fwrite(&procPtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER),
                   singleBit, file);

            fwrite(procPtr->SectionDescriptor,
                   sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount,
                   singleBit, file);

            fwrite(procPtr->McaErrorInfo,
                   sizeof(RUNTIME_ERROR_INFO) * sectionCount, singleBit, file);

            // exportCrashdumpToDBus(err_count, ProcPtr->Header.TimeStamp);
        }
    }
    else if (errorType == fatalErr)
    {
        if ((fatalPtr) && (file != nullptr))
        {
            fwrite(&fatalPtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER),
                   singleBit, file);

            fwrite(fatalPtr->SectionDescriptor,
                   sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount,
                   singleBit, file);

            fwrite(fatalPtr->ErrorRecord,
                   sizeof(EFI_AMD_FATAL_ERROR_DATA) * sectionCount, singleBit,
                   file);

            // exportCrashdumpToDBus(err_count, FatalPtr->Header.TimeStamp);

            std::string rasErrMsg = "CPER file generated for fatal error";

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.AtScaleDebugConnected",
                            "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
        }
    }
    else if (errorType == runtimePcieErr)
    {
        fwrite(&pciePtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER),
               singleBit, file);
        fwrite(pciePtr->SectionDescriptor,
               sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount, singleBit,
               file);
        fwrite(pciePtr->PcieErrorData,
               sizeof(EFI_PCIE_ERROR_DATA) * sectionCount, singleBit, file);
        // exportCrashdumpToDBus(err_count, PciePtr->Header.TimeStamp);
    }
    fclose(file);

    errCount++;

    if (errCount >= maxCperCount)
    {
        /*The maximum number of error files supported is 10.
          The counter will be rotated once it reaches max count*/
        errCount = (errCount % maxCperCount);
    }

    file = fopen(INDEX_FILE, "w");
    if (file != nullptr)
    {
        fprintf(file, "%lu", errCount);
        fclose(file);
    }

    lock.unlock();
}

} // namespace cper
} // namespace util
} // namespace ras
} // namespace amd
