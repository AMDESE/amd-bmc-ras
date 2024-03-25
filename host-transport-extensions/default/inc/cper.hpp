#pragma once

#include "ras.hpp"

typedef struct
{
    unsigned char b[INDEX_16];
} GUID_T;

typedef struct
{
    uint32_t mcaData[MCA_BANK_MAX_OFFSET] = {0};
} CRASHDUMP_T;

typedef struct
{
    uint32_t wdtData[LAST_TRANS_ADDR_OFFSET] = {0};
} LAST_TRANS_ADDR;

struct TimeStamp
{
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    uint8_t flag;
    uint8_t day;
    uint8_t month;
    uint8_t year;
    uint8_t century;
} __attribute__((packed));

struct ErrorRecordHeader
{
    unsigned char signature[CPER_SIG_SIZE];
    uint16_t revision;
    uint32_t signatureEnd;
    uint16_t sectionCount;
    uint32_t errorSeverity;
    uint32_t validationBits;
    uint32_t recordLength;
    TimeStamp timeStamp;
    uint64_t platformId[INDEX_2];
    GUID_T partitionId;
    GUID_T creatorId;
    GUID_T notifyType;
    uint64_t recordId;
    uint32_t flags;
    uint64_t persistenceInfo;
    uint8_t reserved[INDEX_12];
} __attribute__((packed));

struct ErrorSectionDescriptor
{
    uint32_t sectionOffset;
    uint32_t sectionLength;
    uint8_t revisionMinor;
    uint8_t revisionMajor;
    uint8_t secValidMask;
    uint8_t reserved;
    uint32_t sectionFlags;
    GUID_T sectionType;
    uint64_t fruId[INDEX_2];
    uint32_t severity;
    char fruText[INDEX_20];
} __attribute__((packed));

struct ProcessorErrorSection
{
    uint64_t validBits;
    uint64_t cpuApicId;
    uint32_t cpuId[INDEX_12];
    uint32_t signatureID[INDEX_8];
    uint32_t reserved[INDEX_8];
} __attribute__((packed));

struct DfDump
{
    LAST_TRANS_ADDR lastTransAddr[CCM_COUNT] = {0};
} __attribute__((packed));

struct ContextInfo
{
    uint16_t registerContextType;
    uint16_t registerArraySize;
    uint32_t microcodeVersion;
    uint64_t ppin;
    CRASHDUMP_T crashDumpData[GENOA_MCA_BANKS] = {0};
    DfDump dfDumpData;
    uint32_t reserved[RESERVE_96] = {0};
    uint32_t debugLogIdData[DEUB_LOG_DUMP_REGION] = {0};
} __attribute__((packed));

struct ErrorRecord
{
    ProcessorErrorSection procError;
    ContextInfo contextInfo;
} __attribute__((packed));

struct CperRecord
{
    ErrorRecordHeader header;
    ErrorSectionDescriptor* sectionDescriptor;
    ErrorRecord* errorRecord;
} __attribute__((packed));

struct ProcInfoSection
{
    uint64_t validBits;
    uint64_t cpuApicId;
    uint32_t cpuId[INDEX_12];
} __attribute__((packed));

struct ProcessorErrorInfo
{
    GUID_T errorType;
    uint64_t validationBits;
    uint64_t checkInfo;
    uint64_t targetId;
    uint64_t requestorId;
    uint64_t responderId;
    uint64_t ip;
} __attribute__((packed));

struct ProcContextSection
{
    uint16_t regContextType;
    uint16_t regArraySize;
    uint32_t msrAddr;
    uint64_t mmRegAddr;
    uint32_t dumpData[RUNTIME_MCA_BANK_MAX_OFFSET];
} __attribute__((packed));

struct ProcErrorSection
{
    ProcInfoSection procInfoSection;
    ProcessorErrorInfo procErrorInfo;
    ProcContextSection procContextStruct;
} __attribute__((packed));

struct PcieVersion
{
    uint8_t minor;
    uint8_t major;
    uint8_t reserved[INDEX_2];
} __attribute__((packed));

struct DeviceId
{
    uint16_t vendorId;
    uint16_t deviceId;
    uint8_t classCode[INDEX_3];
    uint8_t function;
    uint8_t device;
    uint16_t segment;
    uint8_t bus;
    uint8_t secondaryBus;
    uint8_t Reserved[INDEX_3];
} __attribute__((packed));

struct PcieErrorSection
{
    uint64_t validationBits;
    uint32_t portType;
    PcieVersion version;
    uint32_t commandStatus;
    uint32_t reserved;
    DeviceId deviceId;
    uint64_t deviceSerialNumber;
    uint32_t bridgeControlStatus;
    uint8_t capability[INDEX_60];
    uint32_t aerInfo[INDEX_24];
} __attribute__((packed));

struct ProcRuntimeErrRecord
{
    ErrorRecordHeader header;
    ErrorSectionDescriptor* sectionDescriptor;
    ProcErrorSection* procErrorSection;
} __attribute__((packed));

struct PcieRuntimeErrRecord
{
    ErrorRecordHeader header;
    ErrorSectionDescriptor* sectionDescriptor;
    PcieErrorSection* pcieErrorSection;
} __attribute__((packed));
