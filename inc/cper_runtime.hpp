#ifndef CPER_RUNTIME_H
#define CPER_RUNTIME_H

#include "cper.hpp"

#define RUNTIME_MCA_BANK_MAX_OFFSET (32)

struct proc_info_section
{
    uint64_t ValidBits;
    uint64_t CPUAPICId;
    uint32_t CpuId[INDEX_12];
} __attribute__((packed));

struct processor_error_info
{
    GUID_T ErrorType;
    uint64_t ValidationBits;
    uint64_t CheckInfo;
    uint64_t TargetId;
    uint64_t RequestorId;
    uint64_t ResponderId;
    uint64_t ip;
} __attribute__((packed));

struct proc_context_section
{
    uint16_t RegContextType;
    uint16_t RegArraySize;
    uint32_t MSR_Addr;
    uint64_t MM_RegAddr;
    uint32_t DumpData[RUNTIME_MCA_BANK_MAX_OFFSET];
} __attribute__((packed));

struct proc_error_section
{
    proc_info_section ProcInfoSection;
    processor_error_info ProcErrorInfo;
    proc_context_section ProcContextStruct;
} __attribute__((packed));

struct pcie_version
{
    uint8_t Minor;
    uint8_t Major;
    uint8_t Reserved[INDEX_2];
} __attribute__((packed));

struct device_id
{
    uint16_t VendorId;
    uint16_t DeviceId;
    uint8_t ClassCode[INDEX_3];
    uint8_t Function;
    uint8_t Device;
    uint16_t Segment;
    uint8_t Bus;
    uint8_t SecondaryBus;
    uint8_t Reserved[INDEX_3];
} __attribute__((packed));

struct pcie_error_section
{
    uint64_t ValidationBits;
    uint32_t PortType;
    pcie_version Version;
    uint32_t CommandStatus;
    uint32_t Reserved;
    device_id DeviceId;
    uint64_t DeviceSerialNumber;
    uint32_t BridgeControlStatus;
    uint8_t Capability[INDEX_60];
    uint32_t AerInfo[INDEX_24];
} __attribute__((packed));

struct proc_runtime_err_record
{
    common_error_record_header Header;
    error_section_descriptor* SectionDescriptor;
    proc_error_section* ProcErrorSection;
} __attribute__((packed));

typedef struct proc_runtime_err_record PROC_RUNTIME_ERR_RECORD;

struct pcie_runtime_err_record
{
    common_error_record_header Header;
    error_section_descriptor* SectionDescriptor;
    pcie_error_section* PcieErrorSection;
} __attribute__((packed));

typedef struct pcie_runtime_err_record PCIE_RUNTIME_ERR_RECORD;

#endif
