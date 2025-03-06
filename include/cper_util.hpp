#pragma once

#include "crashdump_manager.hpp"
#include "error_monitor.hpp"
#include "hex_util.hpp"
#include "host_util.hpp"
#include "oem_cper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <regex>

static constexpr std::string_view runtimeMcaErr = "RUNTIME_MCA_ERROR";
static constexpr std::string_view runtimePcieErr = "RUNTIME_PCIE_ERROR";
static constexpr std::string_view runtimeDramErr = "RUNTIME_DRAM_ERROR";
static constexpr std::string_view fatalErr = "FATAL";

namespace amd
{
namespace ras
{
namespace cper
{
namespace util
{

constexpr uint8_t sevNonFatalUncorrected = 0;
constexpr uint8_t sevNonFatalCorrected = 2;

constexpr uint8_t cperValidPlatformId = 0x1;
constexpr uint8_t cperValidTimestamp = 0x2;
constexpr uint8_t addcGenNumber3 = 0x03;
constexpr uint8_t familyId1ah = 0x1A;
constexpr uint16_t pcieVendorId = 0x1022;
constexpr uint8_t minorRevision = 0xB;

std::string findCperFilename(size_t number);

void createIndexFile(size_t& errCount);

void exportToDBus(size_t num, const EFI_ERROR_TIME_STAMP& TimeStampStr,
                  sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus);

void createRecord(sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus);

template <typename PtrType>
void calculateTimestamp(const std::shared_ptr<PtrType>&);

template <typename PtrType>
void dumpHeader(const std::shared_ptr<PtrType>&, uint16_t, uint32_t,
                const std::string_view&, unsigned int, uint64_t&);
template <typename PtrType>
void dumpErrorDescriptor(const std::shared_ptr<PtrType>&, uint16_t,
                         const std::string_view&, uint32_t*, uint8_t);

void dumpProcessorError(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                        uint8_t socNum, const std::unique_ptr<CpuId[]>& cpuId,
                        uint8_t cpuCount);

void dumpProcErrorInfoSection(
    const std::shared_ptr<McaRuntimeCperRecord>& procPtr, uint16_t sectionCount,
    uint64_t* checkInfo, uint32_t sectionStart, uint8_t cpuCount,
    const std::unique_ptr<CpuId[]>& cpuId);

void dumpContext(const std::shared_ptr<FatalCperRecord>& fatalPtr,
                 uint16_t numbanks, uint16_t bytespermca, uint8_t socNum,
                 const std::unique_ptr<uint64_t[]>& ppin,
                 const std::unique_ptr<uint32_t[]>& uCode, uint8_t cpuCount);

void dumpPcieErrorInfo(const std::shared_ptr<PcieRuntimeCperRecord>& data,
                       uint16_t sectionStart, uint16_t sectionCount);

std::string getFilename(size_t num);

template <typename T>
void createFile(const std::shared_ptr<T>&, const std::string_view&, uint16_t,
                size_t&);

bool checkSignatureIdMatch(std::map<std::string, std::string>* configSigIdList,
                           const std::shared_ptr<FatalCperRecord>& rcd);

bool calculateSeverity(uint32_t* severity, uint16_t sectionCount,
                       uint32_t* highestSeverity,
                       const std::string_view& errorType);

} // namespace util
} // namespace cper
} // namespace ras
} // namespace amd
