#pragma once

#include "libcper/Cper.h"

typedef struct
{
    UINT32 McaData[128];
} CRASHDUMP_T;

typedef struct
{
    UINT32 WdtData[4];
} LAST_TRANS_ADDR;

typedef struct
{
    LAST_TRANS_ADDR LastTransAddr[8];
} DF_DUMP;

typedef struct
{
    EFI_IA32_X64_PROCESSOR_ERROR_RECORD ProcError;
    UINT32 SignatureID[8];
    UINT32 Reserved[8];
    UINT16 RegisterContextType;
    UINT16 RegisterArraySize;
    UINT32 MicrocodeVersion;
    UINT64 Ppin;
    CRASHDUMP_T CrashDumpData[32];
    DF_DUMP DfDumpData;
    UINT32 Reserved1[96];
    UINT32 DebugLogIdData[12124];
} __attribute__((packed)) EFI_AMD_FATAL_ERROR_DATA;

typedef struct
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    EFI_AMD_FATAL_ERROR_DATA* ErrorRecord;
} __attribute__((packed)) FatalCperRecord;

typedef struct
{
    EFI_IA32_X64_PROCESSOR_ERROR_RECORD ProcError;
    EFI_IA32_X64_PROCESS_ERROR_INFO ErrorInfo;
    EFI_IA32_X64_PROCESSOR_CONTEXT_INFO ContextInfo;
    UINT32 DumpData[32];
} __attribute__((packed)) RUNTIME_ERROR_INFO;
typedef struct
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    RUNTIME_ERROR_INFO* McaErrorInfo;
} __attribute__((packed)) McaRuntimeCperRecord;

typedef struct
{
    EFI_COMMON_ERROR_RECORD_HEADER Header;
    EFI_ERROR_SECTION_DESCRIPTOR* SectionDescriptor;
    EFI_PCIE_ERROR_DATA* PcieErrorData;
} __attribute__((packed)) PcieRuntimeCperRecord;
