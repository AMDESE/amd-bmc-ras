#pragma once

#include "libcper/Cper.h"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <filesystem>

constexpr int BASE_16 = 16;
constexpr int INDEX_0 = 0;
constexpr int INDEX_1 = 1;
constexpr int INDEX_2 = 2;
constexpr int INDEX_3 = 3;
constexpr int INDEX_4 = 4;
constexpr int INDEX_5 = 5;
constexpr int INDEX_6 = 6;
constexpr int INDEX_8 = 8;
constexpr int INDEX_12 = 12;
constexpr int INDEX_16 = 16;
constexpr int INDEX_19 = 19;
constexpr int INDEX_20 = 20;
constexpr int TURIN_FAMILY_ID = 0x1A;
constexpr int GENOA_FAMILY_ID = 0x19;
constexpr int RAS_STATUS_REGISTER = 0x4C;
constexpr int CPER_SEV_FATAL = 1;
constexpr int INT_255 = 0xFF;
constexpr int SOCKET_0 = 0;
constexpr int SOCKET_1 = 1;
constexpr int MAX_MCA_BANKS = 32;
constexpr int SHIFT_24 = 24;
constexpr int SHIFT_4 = 4;
constexpr int BYTE_4 = 4;
constexpr int BYTE_2 = 2;
constexpr int BAD_DATA = 0xBAADDA7A;
static const std::string FATAL_ERR = "FATAL";

struct CpuId
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

#define CCM_COUNT 8
#define DEBUG_LOG_DUMP_REGION 12124
#define MCA_BANK_MAX_OFFSET 128
#define MCA_BANKS 32
#define LAST_TRANS_ADDR_OFFSET 4

typedef struct
{
    UINT32 McaData[MCA_BANK_MAX_OFFSET];
} CRASHDUMP_T;

typedef struct
{
    UINT32 WdtData[LAST_TRANS_ADDR_OFFSET];
} LAST_TRANS_ADDR;

typedef struct
{
    LAST_TRANS_ADDR LastTransAddr[CCM_COUNT];
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
    CRASHDUMP_T CrashDumpData[MCA_BANKS];
    DF_DUMP DfDumpData;
    UINT32 Reserved1[96];
    UINT32 DebugLogIdData[DEBUG_LOG_DUMP_REGION];
} __attribute__((packed)) EFI_AMD_FATAL_ERROR_DATA;

typedef struct
{
    EFI_COMMON_ERROR_RECORD_HEADER header;
    EFI_ERROR_SECTION_DESCRIPTOR* sectionDescriptor;
    EFI_AMD_FATAL_ERROR_DATA* errorRecord;
} __attribute__((packed)) FatalCperRecord;
