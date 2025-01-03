#include "util_cper.hpp"

#include "oem_cper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>

namespace ras {
namespace cper {
namespace util {
constexpr int CPER_VALID_PLATFORM_ID = 0x1;
constexpr int CPER_VALID_TIMESTAMP = 0x2;
constexpr int ADDC_GEN_NUMBER_1 = 0x01;
constexpr int ADDC_GEN_NUMBER_2 = 0x02;
constexpr int TURIN_FAMILY_ID = 0x1A;
constexpr int GENOA_FAMILY_ID = 0x19;
constexpr uint16_t PCIE_VENDOR_ID = 0x1022;
constexpr int MINOR_REVISION = 0xB;

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

template void dumpHeaderSection(const std::shared_ptr<FatalCperRecord> &data,
                                uint16_t sectionCount, uint32_t errorSeverity,
                                const std::string &errorType,
                                unsigned int boardId, uint64_t &recordId);

template void
dumpHeaderSection(const std::shared_ptr<McaRuntimeCperRecord> &data,
                  uint16_t sectionCount, uint32_t errorSeverity,
                  const std::string &errorType, unsigned int boardId,
                  uint64_t &recordId);

template void
dumpHeaderSection(const std::shared_ptr<PcieRuntimeCperRecord> &data,
                  uint16_t sectionCount, uint32_t errorSeverity,
                  const std::string &errorType, unsigned int boardId,
                  uint64_t &recordId);

template void
dumpErrorDescriptorSection(const std::shared_ptr<FatalCperRecord> &, uint16_t,
                           const std::string &, uint32_t *, uint8_t, uint32_t);

template void
dumpErrorDescriptorSection(const std::shared_ptr<McaRuntimeCperRecord> &,
                           uint16_t, const std::string &, uint32_t *, uint8_t,
                           uint32_t);

template void
dumpErrorDescriptorSection(const std::shared_ptr<PcieRuntimeCperRecord> &,
                           uint16_t, const std::string &, uint32_t *, uint8_t,
                           uint32_t);

template void createCperFile(const std::shared_ptr<FatalCperRecord> &,
                             const std::string &, uint16_t, int &);

template void createCperFile(const std::shared_ptr<McaRuntimeCperRecord> &,
                             const std::string &, uint16_t, int &);

template void createCperFile(const std::shared_ptr<PcieRuntimeCperRecord> &,
                             const std::string &, uint16_t, int &);

template <typename T> void calculateTimeStamp(const std::shared_ptr<T> &data) {
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
void dumpHeaderSection(const std::shared_ptr<T> &data, uint16_t sectionCount,
                       uint32_t errorSeverity, const std::string &errorType,
                       unsigned int boardId, uint64_t &recordId) {
  data->Header.SignatureStart = 0x52455043; // CPER
  data->Header.Revision = 0x100;
  data->Header.SignatureEnd = 0xFFFFFFFF;

  /*Number of valid sections associated with the record*/
  data->Header.SectionCount = sectionCount;

  /*0 - Non-fatal uncorrected ; 1 - Fatal ; 2 - Corrected*/
  data->Header.ErrorSeverity = errorSeverity;

  /*Bit 0 = 1 -> PlatformID field contains valid info
    Bit 1 = 1 -> TimeStamp field contains valid info
    Bit 2 = 1 -> PartitionID field contains valid info*/
  data->Header.ValidationBits = (CPER_VALID_PLATFORM_ID | CPER_VALID_TIMESTAMP);

  calculateTimeStamp(data);

  data->Header.PlatformID.Data1 = boardId;

  memcpy(&data->Header.CreatorID, &gEfiEventCreatorIdGuid, sizeof(EFI_GUID));

  data->Header.RecordID = recordId++;

  /*Size of whole CPER record*/
  if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr)) {
    data->Header.RecordLength =
        sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
        (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
        (sizeof(RUNTIME_ERROR_INFO) * sectionCount);

    if (errorSeverity == 0x2) {
      memcpy(&data->Header.NotificationType, &gEfiEventNotificationTypeCmcGuid,
             sizeof(EFI_GUID));
    } else {
      memcpy(&data->Header.NotificationType, &gEfiEventNotificationTypeMceGuid,
             sizeof(EFI_GUID));
    }
  } else if (errorType == runtimePcieErr) {
    data->Header.RecordLength =
        sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
        (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
        (sizeof(EFI_PCIE_ERROR_DATA) * sectionCount);

    memcpy(&data->Header.NotificationType, &gEfiEventNotificationTypePcieGuid,
           sizeof(EFI_GUID));
  } else if (errorType == fatalErr) {
    data->Header.RecordLength =
        sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
        (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
        (sizeof(EFI_AMD_FATAL_ERROR_DATA) * sectionCount);
  }

  /*TimeStamp when OOB controller received the event*/
  calculateTimeStamp(data);
}

template <typename T>
void dumpErrorDescriptorSection(const std::shared_ptr<T> &data,
                                uint16_t sectionCount,
                                const std::string &errorType,
                                uint32_t *severity, uint8_t progId,
                                uint32_t familyId) {
  for (int i = 0; i < sectionCount; i++) {
    if (errorType == fatalErr) {
      /*offset in bytes of the corresponding section body
        from the base of the record header*/
      data->SectionDescriptor[i].SectionOffset =
          sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
          (sectionCount * sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) +
          (i * sizeof(EFI_AMD_FATAL_ERROR_DATA));

      /*The length in bytes of the section body*/
      data->SectionDescriptor[i].SectionLength =
          sizeof(EFI_AMD_FATAL_ERROR_DATA);

      memcpy(&data->SectionDescriptor[i].SectionType, &gEfiAmdCrashdumpGuid,
             sizeof(EFI_GUID));

      data->SectionDescriptor[i].Severity = 1; // 1 = Fatal

      data->SectionDescriptor[i].FruString[0] = 'P';
      data->SectionDescriptor[i].FruString[1] = '0' + i;
    } else if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr)) {
      data->SectionDescriptor[i].SectionOffset =
          sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
          (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
          (sizeof(RUNTIME_ERROR_INFO) * i);

      data->SectionDescriptor[i].SectionLength = sizeof(RUNTIME_ERROR_INFO);

      data->SectionDescriptor[i].SectionType =
          gEfiProcessorSpecificErrorSectionGuid;

      data->SectionDescriptor[i].Severity = severity[i];

      if (strcasecmp(data->SectionDescriptor[i].FruString, "null") == 0) {
        std::strncpy(data->SectionDescriptor[i].FruString, "MemoryError", 19);
        data->SectionDescriptor[i].FruString[19] = '\0';
      } else if (data->SectionDescriptor[i].FruString[0] == '\0') {
        if (errorType == runtimeMcaErr) {
          std::strncpy(data->SectionDescriptor[i].FruString, "ProcessorError",
                       19);
          data->SectionDescriptor[i].FruString[19] = '\0';
        } else if (errorType == runtimeDramErr) {
          std::strncpy(data->SectionDescriptor[i].FruString, "DramCeccError",
                       19);
          data->SectionDescriptor[i].FruString[19] = '\0';
        }
      }
    } else if (errorType == runtimePcieErr) {
      data->SectionDescriptor[i].SectionOffset =
          sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
          (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount) +
          (i * sizeof(EFI_PCIE_ERROR_DATA));

      data->SectionDescriptor[i].SectionLength = sizeof(EFI_PCIE_ERROR_DATA);

      data->SectionDescriptor[i].SectionType = gEfiPcieErrorSectionGuid;

      data->SectionDescriptor[i].Severity = severity[i];

      std::strcpy(data->SectionDescriptor[i].FruString, "PcieError");
    }

    data->SectionDescriptor[i].Revision = 0x1; // 1 = EPYC

    if (familyId == TURIN_FAMILY_ID) {
      data->SectionDescriptor[i].Revision =
          ((((ADDC_GEN_NUMBER_2 & 0xFF) << 4) | progId) << 8) | MINOR_REVISION;
    } else if (familyId == GENOA_FAMILY_ID) {
      data->SectionDescriptor[i].Revision =
          ((((ADDC_GEN_NUMBER_1 & 0xFF) << 4) | progId) << 8) | MINOR_REVISION;
    }
    /* Bit 0 - If 1, the FRUId field contains valid information
     * Bit 1 - If 1, the FRUTxt field contains valid information*/
    data->SectionDescriptor[i].SecValidMask = 3;

    /*Bit 0 - Primary: FRU identified in section is
              associated with the error condition*/
    data->SectionDescriptor[i].SectionFlags = 1;
  }
}

void dumpProcessorErrorSection(const std::shared_ptr<FatalCperRecord> &fatalPtr,
                               uint8_t socNum,
                               const std::unique_ptr<CpuId[]> &cpuId,
                               uint8_t cpuCount) {
  for (int i = 0; i < cpuCount; i++) {
    /*bit 0: APIC_ID Valid
      bit 1: CPUID Valid
      bit 2: RSVD
      bits 3-7: RSVD
      bits 8-13: Number of Processor Context Info structures present
      bits 14-63: RSVD*/
    fatalPtr->ErrorRecord[i].ProcError.ValidFields = 0x3;
    fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[0] = cpuId[i].eax;
    fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[2] = cpuId[i].ebx;
    fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[4] = cpuId[i].ecx;
    fatalPtr->ErrorRecord[i].ProcError.CpuIdInfo[6] = cpuId[i].edx;
    fatalPtr->ErrorRecord[i].ProcError.ApicId = ((cpuId[i].ebx >> 24) & 0xFF);

    if (i == socNum) {
      fatalPtr->ErrorRecord[i].ProcError.ValidFields |= 0x100;
    }
  }
}

void dumpProcErrorInfoSection(
    const std::shared_ptr<McaRuntimeCperRecord> &procPtr, uint16_t sectionCount,
    uint64_t *checkInfo, uint32_t sectionStart, uint8_t cpuCount,
    const std::unique_ptr<CpuId[]> &cpuId) {
  for (uint32_t i = sectionStart; i < sectionCount; i++) {
    procPtr->McaErrorInfo[i].ProcError.ValidFields =
        0b11 | (sectionCount << 2) | (sectionCount << 8);

    for (int i = 0; i < cpuCount; i++) {
      procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[0] = cpuId[i].eax;
      procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[2] = cpuId[i].ebx;
      procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[4] = cpuId[i].ecx;
      procPtr->McaErrorInfo[i].ProcError.CpuIdInfo[6] = cpuId[i].edx;
      procPtr->McaErrorInfo[i].ProcError.ApicId = ((cpuId[i].ebx >> 24) & 0xFF);
    }

    memcpy(&procPtr->McaErrorInfo[i].ErrorInfo.ErrorType,
           &gEfiIa32x64ErrorTypeMsCheckGuid, sizeof(EFI_GUID));
    procPtr->McaErrorInfo[i].ErrorInfo.ValidFields = 1;
    procPtr->McaErrorInfo[i].ErrorInfo.CheckInfo.Data64 = checkInfo[i];
    procPtr->McaErrorInfo[i].ContextInfo.RegisterType = 1;
    procPtr->McaErrorInfo[i].ContextInfo.ArraySize = 32;
  }
}

void dumpContextInfo(const std::shared_ptr<FatalCperRecord> &fatalPtr,
                     uint16_t numbanks, uint16_t bytespermca, uint8_t socNum,
                     const std::unique_ptr<uint64_t[]> &ppin,
                     const std::unique_ptr<uint32_t[]> &uCode,
                     uint8_t cpuCount) {
  for (int i = 0; i < cpuCount; i++) {
    fatalPtr->ErrorRecord[i].Ppin = ppin[i];
    fatalPtr->ErrorRecord[i].MicrocodeVersion = uCode[i];

    if (i == socNum) {
      fatalPtr->ErrorRecord[i].RegisterContextType = 1; // MSR Registers
      fatalPtr->ErrorRecord[i].RegisterArraySize = numbanks * bytespermca;
    }
  }
}

void dumpPcieErrorInfoSection(
    const std::shared_ptr<PcieRuntimeCperRecord> &data, uint16_t sectionStart,
    uint16_t sectionCount) {
  for (int i = sectionStart; i < sectionCount; i++) {
    data->PcieErrorData[i].ValidFields |=
        1ULL | (1ULL << 1) | (1ULL << 3) | (1ULL << 7);
    data->PcieErrorData[i].PortType = 4;         // Root Port
    data->PcieErrorData[i].Version = 0x02000000; // Major = 2, Minor = 0
    data->PcieErrorData[i].DevBridge.VendorId = PCIE_VENDOR_ID;
  }
}

std::string getCperFilename(int num) {
  return "ras-error" + std::to_string(num) + ".cper";
}

template <typename T>
void createCperFile(const std::shared_ptr<T> &data,
                    const std::string &errorType, uint16_t sectionCount,
                    int &errCount) {
  static std::mutex index_file_mtx;
  std::unique_lock lock(index_file_mtx);

  std::string cperFileName;
  FILE *file;

  std::shared_ptr<McaRuntimeCperRecord> procPtr;
  std::shared_ptr<PcieRuntimeCperRecord> pciePtr;
  std::shared_ptr<FatalCperRecord> fatalPtr;

  if constexpr (std::is_same_v<T, McaRuntimeCperRecord>) {
    procPtr = std::static_pointer_cast<McaRuntimeCperRecord>(data);
  }
  if constexpr (std::is_same_v<T, PcieRuntimeCperRecord>) {
    pciePtr = std::static_pointer_cast<PcieRuntimeCperRecord>(data);
  }
  if constexpr (std::is_same_v<T, FatalCperRecord>) {
    fatalPtr = std::static_pointer_cast<FatalCperRecord>(data);
  }

  cperFileName = getCperFilename(errCount);

  for (const auto &entry : std::filesystem::directory_iterator(RAS_DIR)) {
    std::string filename = entry.path().filename().string();
    if (filename.size() >= cperFileName.size() &&
        filename.substr(filename.size() - cperFileName.size()) ==
            cperFileName) {
      std::filesystem::remove(entry.path());
    }
  }

  if (errorType == runtimeMcaErr) {
    cperFileName = "mca-runtime-" + cperFileName;
  } else if (errorType == runtimeDramErr) {
    cperFileName = "dram-runtime-" + cperFileName;
  } else if (errorType == runtimePcieErr) {
    cperFileName = "pcie-runtime-" + cperFileName;
  }

  std::string cperFilePath = RAS_DIR + cperFileName;
  lg2::info("Saving CPER file to {CPER}", "CPER", cperFilePath);

  file = fopen(cperFilePath.c_str(), "w");

  if (file == NULL) {
    lg2::error("Cper File open afailed");
    return;
  }
  if ((errorType == runtimeMcaErr) || (errorType == runtimeDramErr)) {
    if ((procPtr) && (file != NULL)) {
      fwrite(&procPtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1, file);

      fwrite(procPtr->SectionDescriptor,
             sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount, 1, file);

      fwrite(procPtr->McaErrorInfo, sizeof(RUNTIME_ERROR_INFO) * sectionCount,
             1, file);

      // exportCrashdumpToDBus(err_count, ProcPtr->Header.TimeStamp);
    }
  } else if (errorType == fatalErr) {
    if ((fatalPtr) && (file != NULL)) {
      fwrite(&fatalPtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1,
             file);

      fwrite(fatalPtr->SectionDescriptor,
             sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount, 1, file);

      fwrite(fatalPtr->ErrorRecord,
             sizeof(EFI_AMD_FATAL_ERROR_DATA) * sectionCount, 1, file);

      // exportCrashdumpToDBus(err_count, FatalPtr->Header.TimeStamp);

      std::string ras_err_msg = "CPER file generated for fatal error";

      sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i", LOG_ERR,
                      "REDFISH_MESSAGE_ID=%s",
                      "OpenBMC.0.1.AtScaleDebugConnected",
                      "REDFISH_MESSAGE_ARGS=%s", ras_err_msg.c_str(), NULL);
    }
  } else if (errorType == runtimePcieErr) {
    fwrite(&pciePtr->Header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1, file);
    fwrite(pciePtr->SectionDescriptor,
           sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount, 1, file);
    fwrite(pciePtr->PcieErrorData, sizeof(EFI_PCIE_ERROR_DATA) * sectionCount,
           1, file);
    // exportCrashdumpToDBus(err_count, PciePtr->Header.TimeStamp);
  }
  fclose(file);

  errCount++;

  if (errCount >= 10) {
    /*The maximum number of error files supported is 10.
      The counter will be rotated once it reaches max count*/
    errCount = (errCount % 10);
  }

  file = fopen(INDEX_FILE, "w");
  if (file != NULL) {
    fprintf(file, "%u", errCount);
    fclose(file);
  }

  lock.unlock();
}

} // namespace util
} // namespace cper
} // namespace ras
