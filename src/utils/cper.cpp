#include "utils/cper.hpp"

#include "base_manager.hpp"
#include "crashdump_manager.hpp"
#include "oem_cper.hpp"
#include "utils/util.hpp"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <array>
#include <filesystem>
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

EFI_GUID gEfiCoreDebugDumpSectionGuid = {
    0xFDBE4ADF,
    0x86EC,
    0x47E3,
    {0x89, 0xBE, 0x69, 0x30, 0x61, 0xA0, 0xF4, 0x68}};

EFI_GUID gEfiEventNotificationTypeCoreDebugDumpGuid = {
    0xF2AE518B,
    0xF661,
    0x434B,
    {0xBD, 0xD8, 0x54, 0x69, 0x9B, 0x7B, 0xEC, 0x81}};

std::mutex indexFileMtx;

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

template void dumpHeader(const std::shared_ptr<CoreDebugDumpCperRecord>& data,
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

template void
    dumpErrorDescriptor(const std::shared_ptr<CoreDebugDumpCperRecord>&,
                        uint16_t, const std::string_view&, uint32_t*, uint8_t);

template void createFile(const std::shared_ptr<FatalCperRecord>&,
                         const std::string_view&, uint16_t, size_t&,
                         const std::string&);

template void createFile(const std::shared_ptr<McaRuntimeCperRecord>&,
                         const std::string_view&, uint16_t, size_t&,
                         const std::string&);

template void createFile(const std::shared_ptr<PcieRuntimeCperRecord>&,
                         const std::string_view&, uint16_t, size_t&,
                         const std::string&);

template void createFile(const std::shared_ptr<CoreDebugDumpCperRecord>&,
                         const std::string_view&, uint16_t, size_t&,
                         const std::string&);

std::string findCperFilename(size_t number, const std::string& node)
{
    std::regex pattern;
    if (node != "0")
    {
        pattern = std::regex(
            ".*" + node + ".*error" + std::to_string(number) + "\\.cper");
    }
    else
    {
        pattern = std::regex(".*" + std::to_string(number) + "\\.cper");
    }

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

void createIndexFile(size_t& errCount, const std::string& node)
{
    std::string indexFile = std::string(INDEX_FILE) + "_" + node;
    std::string rasDir = RAS_DIR;

    amd::ras::util::createFile(rasDir, indexFile);

    std::ifstream file(indexFile);
    if (file.is_open())
    {
        if (!(file >> errCount))
        {
            // File is empty or unreadable, default to 0
            errCount = 0;
            file.close();
            std::ofstream out(indexFile, std::ios::trunc);
            if (out)
            {
                out << errCount;
            }
        }
        else
        {
            file.close();
        }
    }
    else
    {
        throw std::runtime_error("Failed to read from index file");
    }
}

void exportToDBus(size_t num, const EFI_ERROR_TIME_STAMP& TimeStampStr,
                  sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                  const std::string& node)
{
    if (num >= 10)
    {
        lg2::error("Crashdump only allows index 0~9\n");
        return;
    }

    const std::string filename = findCperFilename(num, node);
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
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                  const std::string& node)
{
    // Check if any crashdump already exists.
    std::regex pattern;

    if (std::filesystem::exists(std::filesystem::path(RAS_DIR)))
    {
        if (node != "0")
        {
            pattern =
                std::regex("node" + node + ".*ras-error([[:digit:]]+).cper");
        }
        else
        {
            pattern = std::regex(".*ras-error([[:digit:]]+).cper");
        }
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
            exportToDBus(kNum, timestamp, objectServer, systemBus, node);
        }
    }
}

void deleteCrashdumpInterface()
{
    managers.clear();
}

void dumpProcessorError(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                        uint8_t socNum, const std::unique_ptr<CpuId[]>& cpuId,
                        std::vector<size_t>& socIndex, uint16_t numbanks)
{
    for (size_t i : socIndex)
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

        for (size_t rec = 0; rec < cpuCount; rec++)
        {
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[0] = cpuId[rec].eax;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[doubleBit] =
                cpuId[rec].ebx;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[quadBit] =
                cpuId[rec].ecx;
            procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[hexBit] =
                cpuId[rec].edx;
            procPtr->McaErrorInfo[i].ProcError.ApicId =
                ((cpuId[rec].ebx >> 24) & maxByte);
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
                 const std::unique_ptr<uint32_t[]>& uCode, size_t contextType)
{
    fatalPtr->ErrorRecord[socNum].Ppin = ppin[socNum];
    fatalPtr->ErrorRecord[socNum].MicrocodeVersion = uCode[socNum];

    if (numbanks != 0)
    {
        fatalPtr->ErrorRecord[socNum].RegisterContextType =
            contextType; // MSR Registers
        fatalPtr->ErrorRecord[socNum].RegisterArraySize =
            numbanks * bytespermca;
    }
}

std::string getCperFilename(size_t num)
{
    return "ras-error" + std::to_string(num) + ".cper";
}

bool checkSignatureIdMatch(std::map<std::string, std::string>* configSigIdList,
                           const std::shared_ptr<FatalCperRecord>& rcd,
                           size_t cpuCount)
{
    bool ret = false;
    size_t socNum = 0;
    std::vector<std::array<uint32_t, 8>> tempVar(cpuCount);

    for (socNum = 0; socNum < cpuCount; socNum++)
    {
        std::memcpy(tempVar[socNum].data(),
                    rcd->ErrorRecord[socNum].SignatureID,
                    sizeof(tempVar[socNum]));
    }

    for (socNum = 0; socNum < cpuCount; socNum++)
    {
        bool equal = false;
        for (const auto& pair : *configSigIdList)
        {
            bool equal = amd::ras::util::compareBitwiseAnd(
                tempVar[socNum].data(), pair.second);

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
            (sizeof(EFI_AMD_PCIE_ERROR_DATA) * sectionCount);

        memcpy(&data->Header.NotificationType,
               &gEfiEventNotificationTypePcieGuid, sizeof(EFI_GUID));
    }
    else if (errorType == fatalErr)
    {
        data->Header.RecordLength =
            sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
            (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
            (sizeof(EFI_AMD_FATAL_ERROR_DATA) * sectionCount);

        memcpy(&data->Header.NotificationType,
               &gEfiEventNotificationTypeMceGuid, sizeof(EFI_GUID));
    }
    else if (errorType == coreDebugDumpErr)
    {
        /* RecordLength will be updated by the caller after payload sizes
           are known. Initialize with header + descriptors only. */
        data->Header.RecordLength =
            sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
            (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount);

        memcpy(&data->Header.NotificationType,
               &gEfiEventNotificationTypeCoreDebugDumpGuid, sizeof(EFI_GUID));
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
                (i * sizeof(EFI_AMD_PCIE_ERROR_DATA));

            data->SectionDescriptor[i].SectionLength =
                sizeof(EFI_AMD_PCIE_ERROR_DATA);

            data->SectionDescriptor[i].SectionType = gEfiPcieErrorSectionGuid;

            data->SectionDescriptor[i].Severity = severity[i];

            std::strcpy(data->SectionDescriptor[i].FruString, "PcieError");
        }
        else if (errorType == coreDebugDumpErr)
        {
            /* SectionOffset and SectionLength will be updated by the
               caller after payload sizes are determined. */
            data->SectionDescriptor[i].SectionOffset = 0;
            data->SectionDescriptor[i].SectionLength = 0;

            memcpy(&data->SectionDescriptor[i].SectionType,
                   &gEfiCoreDebugDumpSectionGuid, sizeof(EFI_GUID));

            /* Informational severity = 3 */
            data->SectionDescriptor[i].Severity = 3;

            std::strncpy(data->SectionDescriptor[i].FruString, "CoreDebugDump",
                         nineteen);
            data->SectionDescriptor[i].FruString[nineteen] = '\0';
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

void updateIndexFile(size_t& errCount, const std::string& node)
{
    errCount++;

    if (errCount >= maxCperCount)
    {
        /*The maximum number of error files supported is 10.
          The counter will be rotated once it reaches max count*/
        errCount = (errCount % maxCperCount);
    }

    // Lock the critical section (RAII)
    std::scoped_lock lk(indexFileMtx);

    // Build path
    const std::filesystem::path indexPath = std::filesystem::path(INDEX_FILE) +=
        "_" + std::string(node);

    // Overwrite the file with the current count
    std::ofstream out(indexPath, std::ios::trunc);
    if (!out)
    {
        return;
    }
    out << errCount;
}

template <typename PtrType>
void createFile(const std::shared_ptr<PtrType>& data,
                const std::string_view& errorType, uint16_t sectionCount,
                size_t& errCount, const std::string& node)
{
    std::string cperFileName;
    FILE* file;

    std::shared_ptr<McaRuntimeCperRecord> procPtr;
    std::shared_ptr<PcieRuntimeCperRecord> pciePtr;
    std::shared_ptr<FatalCperRecord> fatalPtr;
    std::shared_ptr<CoreDebugDumpCperRecord> coreDebugPtr;

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
    if constexpr (std::is_same_v<PtrType, CoreDebugDumpCperRecord>)
    {
        coreDebugPtr = std::static_pointer_cast<CoreDebugDumpCperRecord>(data);
    }

    cperFileName = getCperFilename(errCount);

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
    else if (errorType == coreDebugDumpErr)
    {
        cperFileName = "core-debug-dump-" + cperFileName;
    }

    if (node != "0")
    {
        cperFileName = "node" + node + "-" + cperFileName;
    }

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
    lg2::info("Creating CPER file: {CPERFILE}", "CPERFILE", cperFilePath.c_str());

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

            std::string rasErrMsg = "Generated runtime CPER file : ";
            rasErrMsg.append(cperFilePath);

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.AtScaleDebugConnected",
                            "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
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

            std::string rasErrMsg = "Generated Fatal CPER file : ";
            rasErrMsg.append(cperFilePath);

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.AtScaleDebugConnected",
                            "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
        }
    }
    else if (errorType == runtimePcieErr)
    {
        if ((pciePtr) && (file != nullptr))
        {
            fwrite(&pciePtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER),
                   singleBit, file);
            fwrite(pciePtr->SectionDescriptor,
                   sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount,
                   singleBit, file);
            fwrite(pciePtr->PcieErrorData,
                   sizeof(EFI_AMD_PCIE_ERROR_DATA) * sectionCount, singleBit,
                   file);

            std::string rasErrMsg = "Generated runtime CPER file : ";
            rasErrMsg.append(cperFilePath);

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.AtScaleDebugConnected",
                            "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
        }
    }
    else if (errorType == coreDebugDumpErr)
    {
        if ((coreDebugPtr) && (file != nullptr))
        {
            fwrite(&coreDebugPtr->Header,
                   sizeof(EFI_COMMON_ERROR_RECORD_HEADER), singleBit, file);

            fwrite(coreDebugPtr->SectionDescriptor,
                   sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount,
                   singleBit, file);

            for (uint16_t i = 0; i < sectionCount; i++)
            {
                fwrite(&coreDebugPtr->DebugDumpSection[i].header,
                       sizeof(CoreDebugDumpHeader), singleBit, file);

                uint32_t payloadSize =
                    coreDebugPtr->SectionDescriptor[i].SectionLength -
                    sizeof(CoreDebugDumpHeader);
                if (payloadSize > 0 &&
                    coreDebugPtr->DebugDumpSection[i].payload != nullptr)
                {
                    fwrite(coreDebugPtr->DebugDumpSection[i].payload,
                           payloadSize, singleBit, file);
                }
            }

            std::string rasErrMsg = "Generated Core Debug Dump CPER file : ";
            rasErrMsg.append(cperFilePath);

            sd_journal_send("MESSAGE=%s", rasErrMsg.c_str(), "PRIORITY=%i",
                            LOG_INFO, "REDFISH_MESSAGE_ID=%s",
                            "OpenBMC.0.1.AtScaleDebugConnected",
                            "REDFISH_MESSAGE_ARGS=%s", rasErrMsg.c_str(), NULL);
        }
    }
    fclose(file);
}

void mergeFile(const std::string& sourceFile, const std::string& destFile)
{
    constexpr size_t hdrSz = sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
    constexpr size_t descSz = sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

    // Helper: read entire file into byte vector.
    auto readBinary = [](const std::string& path,
                         std::vector<uint8_t>& buf) -> bool {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open())
        {
            return false;
        }
        in.seekg(0, std::ios::end);
        buf.resize(static_cast<size_t>(in.tellg()));
        in.seekg(0, std::ios::beg);
        return !!in.read(reinterpret_cast<char*>(buf.data()),
                         static_cast<std::streamsize>(buf.size()));
    };

    std::vector<uint8_t> destBuf, srcBuf;

    if (!readBinary(destFile, destBuf) || !readBinary(sourceFile, srcBuf))
    {
        lg2::error("mergeFile: failed to read source or dest CPER file");
        return;
    }

    if (destBuf.size() < hdrSz || srcBuf.size() < hdrSz)
    {
        lg2::error("mergeFile: file too small to contain a CPER header");
        return;
    }

    auto* srcHdr =
        reinterpret_cast<EFI_COMMON_ERROR_RECORD_HEADER*>(srcBuf.data());
    uint16_t srcSecCount = srcHdr->SectionCount;
    lg2::info("mergeFile: source CPER has {SRC_CNT} sections", "SRC_CNT",
             srcSecCount);

    if (srcSecCount == 0)
    {
        lg2::info("mergeFile: source CPER has 0 sections, nothing to merge");
        return;
    }

    if (srcBuf.size() < hdrSz + descSz * srcSecCount)
    {
        lg2::error("mergeFile: source file too small for declared sections");
        return;
    }

    auto* srcDescs = reinterpret_cast<EFI_ERROR_SECTION_DESCRIPTOR*>(
        srcBuf.data() + hdrSz);

    // Collect each source section payload using SectionOffset/SectionLength.
    std::vector<std::vector<uint8_t>> srcPayloads(srcSecCount);
    for (uint16_t s = 0; s < srcSecCount; ++s)
    {
        uint32_t off = srcDescs[s].SectionOffset;
        uint32_t len = srcDescs[s].SectionLength;
        lg2::info(
            "mergeFile: source section {IDX} has offset {OFF} and length {LEN}",
            "IDX", s, "OFF", off, "LEN", len);
        if (off + len > srcBuf.size())
        {
            lg2::error(
                "mergeFile: source section {IDX} extends past end of file",
                "IDX", s);
            return;
        }
        srcPayloads[s].assign(srcBuf.begin() + off,
                              srcBuf.begin() + off + len);
    }

    auto* destHdr =
        reinterpret_cast<EFI_COMMON_ERROR_RECORD_HEADER*>(destBuf.data());
    uint16_t destSecCount = destHdr->SectionCount;
    uint16_t newSecCount = destSecCount + srcSecCount;

    lg2::info(
        "mergeFile: dest has {DST_CNT} sections, source has {SRC_CNT} sections, "
        "merging into a total of {NEW_CNT} sections",
        "DST_CNT", destSecCount, "SRC_CNT", srcSecCount, "NEW_CNT", newSecCount);
    size_t extraDescBytes = static_cast<size_t>(srcSecCount) * descSz;
    size_t extraPayloadBytes = 0;
    for (auto& p : srcPayloads)
    {
        extraPayloadBytes += p.size();
    }

    // Build merged file buffer.
    std::vector<uint8_t> merged;
    merged.resize(destBuf.size() + extraDescBytes + extraPayloadBytes);
    size_t pos = 0;

    // 1) Copy header.
    std::memcpy(merged.data(), destBuf.data(), hdrSz);
    pos = hdrSz;

    // 2) Copy original descriptors, shifting SectionOffset by extraDescBytes.
    size_t destDescStart = hdrSz;
    for (uint16_t d = 0; d < destSecCount; ++d)
    {
        EFI_ERROR_SECTION_DESCRIPTOR desc;
        std::memcpy(&desc, destBuf.data() + destDescStart + d * descSz,
                     descSz);
        desc.SectionOffset += static_cast<uint32_t>(extraDescBytes);
        std::memcpy(merged.data() + pos, &desc, descSz);
        pos += descSz;
    }

    // 3) Append source descriptors with offsets pointing past original data.
    size_t appendBase = destBuf.size() + extraDescBytes;
    size_t payloadCursor = 0;
    for (uint16_t s = 0; s < srcSecCount; ++s)
    {
        EFI_ERROR_SECTION_DESCRIPTOR desc = srcDescs[s];
        desc.SectionOffset =
            static_cast<uint32_t>(appendBase + payloadCursor);
        std::memcpy(merged.data() + pos, &desc, descSz);
        pos += descSz;
        payloadCursor += srcPayloads[s].size();
    }

    // 4) Copy original section data.
    size_t destDataStart = hdrSz + destSecCount * descSz;
    size_t destDataLen = destBuf.size() - destDataStart;
    std::memcpy(merged.data() + pos, destBuf.data() + destDataStart,
                destDataLen);
    pos += destDataLen;

    // 5) Append source payloads.
    for (uint16_t s = 0; s < srcSecCount; ++s)
    {
        std::memcpy(merged.data() + pos, srcPayloads[s].data(),
                    srcPayloads[s].size());
        pos += srcPayloads[s].size();
    }

    // 6) Update header fields.
    auto* mergedHdr =
        reinterpret_cast<EFI_COMMON_ERROR_RECORD_HEADER*>(merged.data());
    mergedHdr->SectionCount = newSecCount;
    mergedHdr->RecordLength = static_cast<uint32_t>(pos);

    // 7) Rewrite the destination file.
    std::ofstream out(destFile, std::ios::binary | std::ios::trunc);
    if (out.is_open())
    {
        out.write(reinterpret_cast<const char*>(merged.data()),
                  static_cast<std::streamsize>(pos));
        out.close();
        lg2::info(
            "mergeFile: merged {SRC_CNT} sections from {SRC} into {DST}",
            "SRC_CNT", srcSecCount, "SRC", sourceFile, "DST", destFile);
    }
    else
    {
        lg2::error("mergeFile: failed to write merged CPER to {DST}", "DST",
                   destFile);
    }
}

} // namespace cper

void cper::dumpCoreDebugDumpHeader(
    const std::shared_ptr<CoreDebugDumpCperRecord>& coreDebugPtr,
    uint16_t sectionIdx, const std::unique_ptr<CpuId[]>& cpuId)
{
    CoreDebugDumpHeader& hdr =
        coreDebugPtr->DebugDumpSection[sectionIdx].header;
    std::memset(&hdr, 0, sizeof(CoreDebugDumpHeader));

    hdr.validBits.apicIdValid = 1;
    hdr.validBits.cpuidValid = 1;
    hdr.apicId = ((cpuId[0].ebx >> 24) & 0xFF);
    hdr.cpuidInfo.eax = cpuId[0].eax;
    hdr.cpuidInfo.ebx = cpuId[0].ebx;
    hdr.cpuidInfo.ecx = cpuId[0].ecx;
    hdr.cpuidInfo.edx = cpuId[0].edx;
}

void cper::populateSignatureId(EFI_AMD_FATAL_ERROR_DATA& errorRecord,
                               uint32_t mcaSyndLo, uint32_t mcaSyndHi,
                               uint32_t mcaIpidLo, uint32_t mcaIpidHi,
                               uint32_t mcaStatusLo, uint32_t mcaStatusHi)
{
    errorRecord.SignatureID[0] = mcaSyndLo;
    errorRecord.SignatureID[1] = mcaSyndHi;
    errorRecord.SignatureID[2] = mcaIpidLo;
    errorRecord.SignatureID[3] = mcaIpidHi;
    errorRecord.SignatureID[4] = mcaStatusLo;
    errorRecord.SignatureID[5] = mcaStatusHi;

    errorRecord.ProcError.ValidFields = errorRecord.ProcError.ValidFields | 0x4;
}

void cper::populateFruStringPspSynd(EFI_ERROR_SECTION_DESCRIPTOR& sectionDesc,
                                    uint32_t pspSynd1Lo, uint32_t pspSynd1Hi,
                                    uint32_t pspSynd2Lo, uint32_t pspSynd2Hi)
{
    constexpr size_t off1Lo = 0;
    constexpr size_t off1Hi = 4;
    constexpr size_t off2Lo = 8;
    constexpr size_t off2Hi = 12;
    constexpr size_t cpSize = 4;

    memcpy(sectionDesc.FruString + off1Lo, &pspSynd1Lo, cpSize);
    memcpy(sectionDesc.FruString + off1Hi, &pspSynd1Hi, cpSize);
    memcpy(sectionDesc.FruString + off2Lo, &pspSynd2Lo, cpSize);
    memcpy(sectionDesc.FruString + off2Hi, &pspSynd2Hi, cpSize);
}

} // namespace util
} // namespace ras
} // namespace amd
