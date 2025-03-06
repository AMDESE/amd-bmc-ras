#pragma once

extern "C"
{
#include "libcper/Cper.h"
}

constexpr uint8_t mcaDataBankLen = 128;
constexpr uint16_t debugDumpDataLen = 12124;
constexpr size_t length4 = 4;
constexpr size_t length8 = 8;
constexpr size_t length32 = 32;
constexpr size_t length96 = 96;

struct CrashdumpData
{
    uint32_t McaData[mcaDataBankLen];
} __attribute__((packed));

using CRASHDUMP_T = CrashdumpData;

struct LastTransAddress
{
    uint32_t WdtData[length4];
} __attribute__((packed));

using LAST_TRANS_ADDR = LastTransAddress;

struct DfDump
{
    LAST_TRANS_ADDR LastTransAddr[length8];
} __attribute__((packed));

using DF_DUMP = DfDump;

struct AmdFatalErrorData
{
    EFI_IA32_X64_PROCESSOR_ERROR_RECORD ProcError;
    uint32_t SignatureID[length8];
    uint32_t Reserved[length8];
    uint16_t RegisterContextType;
    uint16_t RegisterArraySize;
    uint32_t MicrocodeVersion;
    uint64_t Ppin;
    CRASHDUMP_T CrashDumpData[length32];
    DF_DUMP DfDumpData;
    uint32_t Reserved1[length96];
    uint32_t DebugLogIdData[debugDumpDataLen];
} __attribute__((packed));

using EFI_AMD_FATAL_ERROR_DATA = AmdFatalErrorData;

struct RuntimeErrorInfo
{
    EFI_IA32_X64_PROCESSOR_ERROR_RECORD ProcError;
    EFI_IA32_X64_PROCESS_ERROR_INFO ErrorInfo;
    EFI_IA32_X64_PROCESSOR_CONTEXT_INFO ContextInfo;
    uint32_t DumpData[length32];
} __attribute__((packed));

using RUNTIME_ERROR_INFO = RuntimeErrorInfo;

struct FatalCperRecord
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    EFI_AMD_FATAL_ERROR_DATA* ErrorRecord;
} __attribute__((packed));

struct McaRuntimeCperRecord
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    RUNTIME_ERROR_INFO* McaErrorInfo;
} __attribute__((packed));

struct PcieRuntimeCperRecord
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    EFI_PCIE_ERROR_DATA* PcieErrorData;
} __attribute__((packed));
