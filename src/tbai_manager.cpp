#include "tbai_manager.hpp"

#include "utils/cper.hpp"
#include "utils/util.hpp"

extern "C"
{
#include "esmi_mailbox.h"
}

#include <phosphor-logging/lg2.hpp>

#include <regex>

constexpr uint32_t badData = 0xBAADDA7A;
constexpr size_t informational = 3;
constexpr uint16_t hundred = 100;

EFI_GUID gEfiAmdTraceBufferGuid = {
    0x3231C28E,
    0xB3A8,
    0x4814,
    {0xB3, 0xA4, 0x71, 0x29, 0xEF, 0xD6, 0x35, 0x97}};

namespace amd
{
namespace ras
{
namespace tbai
{
sdbusplus::message::object_path Manager::createDump(DumpCreateParams params)
{
    std::string objPath = "/com/amd/TBAI/tracelogs";

    auto it = params.find(sdbusplus::com::amd::Dump::server::Create::
                              convertCreateParametersToString(
                                  sdbusplus::com::amd::Dump::server::Create::
                                      CreateParameters::MPName));

    if (it != params.end())
    {
        mpName = std::get<std::string>(it->second);

        if (!(mpName.starts_with("SOC_0_") || mpName.starts_with("SOC_1_") ||
              mpName == "All"))
        {
            lg2::error("Not a valid MPName string");
            return std::string();
        }
    }
    else
    {
        lg2::error("MP name string is not provided");
        return std::string();
    }

    std::thread([this, params]() {
        this->harvestMpxTraceLog(params);
    }).detach();

    return objPath;
}

void Manager::harvestMpxTraceLog(DumpCreateParams params)
{
    std::unique_lock lock(tbaiMutex);
    size_t sectionCount = 0;
    size_t sectionIndex = 0;
    uint32_t boardId = 0;
    uint64_t recordId = 1;
    uint32_t errorSeverity = informational;
    size_t socNumber = socNum;
    uint8_t lutIndex;
    uint8_t progId = 1;
    constexpr uint8_t minorRevision = 0xB;

    size_t totalSectionCount;

    totalSectionCount = cpuCount * mpToIndexMap.size();

    auto it = params.find(sdbusplus::com::amd::Dump::server::Create::
                              convertCreateParametersToString(
                                  sdbusplus::com::amd::Dump::server::Create::
                                      CreateParameters::MPName));

    if (it != params.end())
    {
        mpName = std::get<std::string>(it->second);

        if (mpName.starts_with("SOC_0_"))
        {
            currentSectionCount = 1;
            socNum = 0;
            mpName = mpName.substr(6); // remove "SOC_0_"
        }
        else if (mpName.starts_with("SOC_1_"))
        {
            currentSectionCount = 1;
            socNum = 1;
            mpName = mpName.substr(6); // remove "SOC_1_"
        }
        else if (mpName == "All")
        {
            currentSectionCount = totalSectionCount;
            socNum = 0;
        }
    }

    mpxPtr = std::make_shared<FatalCperRecord>();
    if (mpxPtr->SectionDescriptor == nullptr)
    {
        mpxPtr->SectionDescriptor =
            new EFI_ERROR_SECTION_DESCRIPTOR[currentSectionCount];
        std::memset(mpxPtr->SectionDescriptor, 0,
                    currentSectionCount * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
    }
    mpxPtr->ErrorRecord = nullptr;

    if (mpxPtr->TraceBufferRecord == nullptr)
    {
        mpxPtr->TraceBufferRecord =
            new EFI_AMD_MP_TRACELOG_DATA[currentSectionCount];
        std::memset(mpxPtr->TraceBufferRecord, 0,
                    currentSectionCount * sizeof(EFI_AMD_MP_TRACELOG_DATA));
    }

    amd::ras::util::cper::dumpHeader(mpxPtr, currentSectionCount, errorSeverity,
                                     mpxTracelog, boardId, recordId);

    /*Populate section descriptor and section data*/
    for (; socNumber < cpuCount; socNumber++)
    {
        for (const auto& pair : mpToIndexMap)
        {
            if (((mpName != "All") && (pair.first != mpName)) ||
                ((mpName != "All") && (socNumber != socNum)))
            {
                continue;
            }

            lg2::info("First {FIR} mpName {MP}", "FIR", pair.first, "MP",
                      mpName);
            mpxPtr->SectionDescriptor[sectionCount].SectionLength =
                sizeof(EFI_AMD_MP_TRACELOG_DATA);

            mpxPtr->SectionDescriptor[sectionCount].SectionOffset =
                sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
                (currentSectionCount * sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) +
                (sectionCount * sizeof(EFI_AMD_MP_TRACELOG_DATA));

            mpxPtr->SectionDescriptor[sectionCount].Severity =
                informational; // 3 = informational

            std::string mpName = pair.first;
            lutIndex = pair.second;

            mpxPtr->SectionDescriptor[sectionCount].SectionType.Data1 |=
                (lutIndex << 11);

            mpxPtr->SectionDescriptor[sectionCount].SectionType.Data2 |= 0x1022;

            mpxPtr->SectionDescriptor[sectionCount].Revision =
                ((((amd::ras::util::cper::addcGenNumber3 &
                    amd::ras::util::cper::maxByte)
                   << amd::ras::util::cper::quadBit) |
                  progId)
                 << 8) |
                minorRevision;

            std::string fruText;
            if (socNumber == 0)
            {
                fruText = "SOC_0_" + mpName;
            }
            else if (socNum == 1)
            {
                fruText = "SOC_1_" + mpName;
            }

            size_t len = fruText.size();

            memcpy(mpxPtr->SectionDescriptor[sectionCount].FruString,
                   fruText.c_str(), len + 1);

            uint8_t dwNum = 1; // Number of double words to be read
            struct trace_buf_data_in dataIn = {0, 0, 0};
            uint32_t buffer;
            uint16_t maxOffset = 2048;
            size_t offset = 0;
            oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

            dataIn.entry_off = offset;
            dataIn.lut_index = lutIndex;
            dataIn.dw_num = dwNum;

            for (offset = 0; offset < maxOffset; offset++)
            {
                memset(&buffer, 0, sizeof(buffer));
                dataIn.entry_off = offset * 4;

                ret = esmi_oob_tbai_read_dw(socNumber, dataIn, &buffer);
                ret = esmi_oob_tbai_read_dw(socNumber, dataIn, &buffer);

                if (ret != OOB_SUCCESS)
                {
                    lg2::error(
                        "Socket {SOCKET} : Failed to get TBAI trace data "
                        "from LutIndex:{LUT}, Offset:{OFFSET}",
                        "SOCKET", socNumber, "LUT", lutIndex, "OFFSET",
                        lg2::hex, offset);

                    mpxPtr->TraceBufferRecord[sectionCount]
                        .TracelogData[offset] =
                        badData; // Write BAADDA7A pattern on error
                }
                else
                {
                    lg2::info(
                        "Socket {SOCKET} : TBAI trace data "
                        "from LutIndex:{LUT}, Offset:{OFFSET},data: {BUF}",
                        "SOCKET", socNumber, "LUT", lutIndex, "OFFSET",
                        lg2::hex, offset, "BUF", lg2::hex, buffer);

                    mpxPtr->TraceBufferRecord[sectionCount]
                        .TracelogData[offset] = buffer;
                }
                usleep(3);
            }
            sectionCount++;
        }
    }
    lg2::info("Data collection done");

    std::string filename;
    std::string lowerMpName;
    std::string dbusPath;
    size_t index;

    if (mpName == "All")
    {
        filename = "mpx-tracelog.cper";
        dbusPath = std::string(objectPath) + "/" + "mpx";
        index = (cpuCount + 1) + mpToIndexMap.size();
    }
    else
    {
        lowerMpName = mpName;
        std::transform(lowerMpName.begin(), lowerMpName.end(),
                       lowerMpName.begin(), ::tolower);

        filename = "soc_" + std::to_string(socNum) + "_" + lowerMpName +
                   "_tracelog.cper";

        dbusPath = std::string(objectPath) + "/soc_" + std::to_string(socNum) +
                   "_" + lowerMpName;

        index = (socNum + 1) * lutIndex;
    }
    lg2::info("Create file");
    amd::ras::util::cper::createFile(mpxPtr, mpxTracelog, currentSectionCount,
                                     sectionIndex, filename);
    lg2::info("Create file completed");
    // Use ISO-8601 as the timestamp format
    // For example: 2022-07-19T14:13:47Z
    const EFI_ERROR_TIME_STAMP& TimeStampStr = mpxPtr->Header.TimeStamp;

    const EFI_ERROR_TIME_STAMP& t = TimeStampStr;

    char timestamp[30];
    sprintf(timestamp, "%d-%d-%dT%d:%d:%dZ", (t.Century - 1) * hundred + t.Year,
            t.Month, t.Day, t.Hours, t.Minutes, t.Seconds);

    if (amd::ras::util::checkObjPath(dbusPath) == true)
    {
        auto it = tbaiRecordMgr.find(index);
        if (it != tbaiRecordMgr.end())
        {
            it->second.reset();
            tbaiRecordMgr.erase(it);
        }
    }

    std::unique_ptr<CrashdumpInterface> tbaiRecord =
        std::make_unique<CrashdumpInterface>(objServer, systemBus, dbusPath);
    tbaiRecord->filename(filename);
    tbaiRecord->log(std::string(RAS_DIR) + filename);
    tbaiRecord->timestamp(std::string{timestamp});

    tbaiRecordMgr[index] = {std::move(tbaiRecord)};

    if (mpxPtr->SectionDescriptor != nullptr)
    {
        delete[] mpxPtr->SectionDescriptor;
        mpxPtr->SectionDescriptor = nullptr;
    }
    if (mpxPtr->TraceBufferRecord != nullptr)
    {
        delete[] mpxPtr->TraceBufferRecord;
        mpxPtr->TraceBufferRecord = nullptr;
    }
    mpxPtr = nullptr;
}

Manager::Manager(sdbusplus::asio::object_server& objectServer,
                 std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                 boost::asio::io_context& io) :
    createDumpIface(*systemBus, objectPath), objServer(objectServer),
    systemBus(systemBus), io(io)
{
    amd::ras::util::mpTraceLogInfo(mpToIndexMap);

    amd::ras::util::getCpuCount(cpuCount);

    std::string dbusPath;
    int index = -1;

    if (std::filesystem::exists(std::filesystem::path(RAS_DIR)))
    {
        std::regex mpPattern(R"(soc_(\d+)_(.*?)_tracelog\.cper)");
        std::regex mpxPattern(R"((.*?)\-tracelog\.cper)");
        std::smatch match;

        for (const auto& p : std::filesystem::directory_iterator(
                 std::filesystem::path(RAS_DIR)))
        {
            std::string filename = p.path().filename().string();

            if (std::regex_match(filename, match, mpPattern))
            {
                dbusPath = std::string(objectPath) + "/soc_" + match[1].str() +
                           "_" + match[2].str();

                const std::string& s = match[2].str();
                for (const auto& [key, val] : mpToIndexMap)
                {
                    if (key.size() == s.size() &&
                        std::equal(
                            key.begin(), key.end(), s.begin(),
                            [](char a, char b) {
                                return std::toupper(
                                           static_cast<unsigned char>(a)) ==
                                       std::toupper(
                                           static_cast<unsigned char>(b));
                            }))
                    {
                        index = (std::stoi(match[1].str()) * 1) + val;
                    }
                }
                if (index == -1)
                    continue;
            }
            else if (std::regex_match(filename, match, mpxPattern))
            {
                dbusPath = std::string(objectPath) + "/" + match[1].str();
                index = (cpuCount + 1) * mpToIndexMap.size();
            }
            else
            {
                continue;
            }

            const std::string tbaiFilename = RAS_DIR + filename;
            std::ifstream fin(tbaiFilename, std::ifstream::binary);
            if (!fin.is_open())
            {
                lg2::warning("Broken MPX LOG CPER file: {CPERFILE}", "CPERFILE",
                             tbaiFilename);
                return;
            }
            fin.seekg(24); // Move the file pointer to offset 24
            EFI_ERROR_TIME_STAMP timestamp;

            if (!fin.read(reinterpret_cast<char*>(&timestamp),
                          sizeof(timestamp)))
            {
                lg2::info("Failed to read data from the file");
            }

            fin.close();
            const EFI_ERROR_TIME_STAMP& TimeStampStr = timestamp;

            const EFI_ERROR_TIME_STAMP& t = TimeStampStr;
            char timestampVal[30];
            sprintf(timestampVal, "%d-%d-%dT%d:%d:%dZ",
                    (t.Century - 1) * hundred + t.Year, t.Month, t.Day, t.Hours,
                    t.Minutes, t.Seconds);

            std::unique_ptr<CrashdumpInterface> tbaiRecord =
                std::make_unique<CrashdumpInterface>(objServer, systemBus,
                                                     dbusPath);
            tbaiRecord->filename(filename);
            tbaiRecord->log(std::string(RAS_DIR) + filename);
            tbaiRecord->timestamp(std::string{timestampVal});

            tbaiRecordMgr[index] = {std::move(tbaiRecord)};
        }
    }
}
} // namespace tbai
} // namespace ras
} // namespace amd
