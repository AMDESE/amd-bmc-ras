#pragma once

extern "C"
{
#include "libcper/Cper.h"
}

// Bytes of MCA register state stored for one bank. PMFW reports this length
// as err_log_len. RegisterArraySize is the bank count times this length.
constexpr uint8_t mcaDataBankLen = 128;
// Fatal OOB MCA harvest can report up to 256 banks (mailbox instance 0-255).
constexpr uint16_t maxMcaBanks = 256;
constexpr uint16_t debugDumpDataLen = 12124;
constexpr size_t mcaPspSynd1LoCode = 80;
constexpr size_t mcaPspSynd1HiCode = 84;
constexpr size_t mcaPspSynd2LoCode = 88;
constexpr size_t mcaPspSynd2HiCode = 92;
constexpr size_t length4 = 4;
constexpr size_t length8 = 8;
constexpr size_t length32 = 32;
constexpr size_t length96 = 96;
// Number of 32-bit words in the AMD PCIe error data buffer
// (AmdPcieErrorData::PcieData below). The PMFW reports a fixed-size PCIe
// error record of 91 DWORDs (364 bytes), so this bounds the PcieData array.
constexpr size_t length91 = 91;

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

// On-disk prefix of a fatal section, through PPIN. The MCA payload is not
// part of this struct: its length is RegisterArraySize, and it is written
// immediately after this prefix.
struct AmdFatalMcaPrefix
{
    EFI_IA32_X64_PROCESSOR_ERROR_RECORD ProcError;
    uint32_t SignatureID[length8];
    uint32_t Reserved[length8];
    uint16_t RegisterContextType;
    uint16_t RegisterArraySize;
    uint32_t MicrocodeVersion;
    uint64_t Ppin;
} __attribute__((packed));

// Fatal section body. On disk the order is prefix, then RegisterArraySize
// bytes of MCA banks, then DfDumpData, Reserved1, and DebugLogIdData.
// mcaBanks holds that MCA payload in memory. A 32-bank record stores
// 32 * 128 bytes; a 256-bank record stores 256 * 128 bytes.
struct AmdFatalErrorData : AmdFatalMcaPrefix
{
    uint16_t mcaBankCount;
    uint16_t mcaBytesPerBank;
    uint8_t* mcaBanks;
    DF_DUMP DfDumpData;
    uint32_t Reserved1[length96];
    uint32_t DebugLogIdData[debugDumpDataLen];
};

using EFI_AMD_FATAL_ERROR_DATA = AmdFatalErrorData;

// Fatal section size when no MCA banks are present. The file writer adds
// RegisterArraySize before the DF dump and debug log.
constexpr size_t fatalFixedSectionBytes =
    sizeof(AmdFatalMcaPrefix) + sizeof(DF_DUMP) +
    (length96 * sizeof(uint32_t)) + (debugDumpDataLen * sizeof(uint32_t));

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

struct AmdPcieErrorData
{
    uint32_t PcieData[length91];
} __attribute__((packed));

using EFI_AMD_PCIE_ERROR_DATA = AmdPcieErrorData;

struct PcieRuntimeCperRecord
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    EFI_AMD_PCIE_ERROR_DATA* PcieErrorData;
} __attribute__((packed));

constexpr size_t coreDebugDumpHeaderSize = 64;
constexpr size_t coreDebugDumpReservedSize = 22;
constexpr size_t instancesPerCore = 128;

struct CoreDebugDumpValidBits
{
    uint16_t apicIdValid:1;
    uint16_t cpuidValid:1;
    uint16_t reserved:14;
} __attribute__((packed));

struct CoreDebugDumpHeader
{
    CoreDebugDumpValidBits validBits;
    uint64_t apicId;
    struct
    {
        uint64_t eax;
        uint64_t ebx;
        uint64_t ecx;
        uint64_t edx;
    } cpuidInfo;
    uint8_t reserved[coreDebugDumpReservedSize];
} __attribute__((packed));

struct CoreDebugDumpSection
{
    CoreDebugDumpHeader header;
    uint32_t* payload;
} __attribute__((packed));

struct CoreDebugDumpCperRecord
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    CoreDebugDumpSection* DebugDumpSection;
} __attribute__((packed));
