#ifndef CPER_H
#define CPER_H

#define CPER_SIG_SIZE               (4)
#define CPER_SIG_RECORD             ("CPER")
#define CPER_RECORD_REV             (0x0100)
#define SECTION_COUNT               (2)
#define CPER_SIG_END                (0xffffffff)
#define CPER_SEV_FATAL              (1)
#define CTX_OOB_CRASH               (0x01)
#define CPER_PRIMARY                (0)
#define RSVD                        (0)
#define GENOA_MCA_BANKS             (32)
#define MCA_BANK_MAX_OFFSET         (128)
#define SYS_MGMT_CTRL_ERR           (0x04)
#define RESET_HANG_ERR              (0x02)
#define DF_DUMP_RESERVED            (11571)
#define MAX_ERROR_FILE              (10)
#define LAST_TRANS_ADDR_OFFSET      (4)
#define PCIE_DUMP_OFFSET            (49)
#define MAX_PCIE_INSTANCES          (12)
#define CCM_COUNT                   (8)
#define BYTE_4                      (4)
#define BYTE_2                      (2)

/*
 * CPER section descriptor revision, used in revision field in struct
 * cper_section_descriptor
 */
#define CPER_MINOR_REV                (0x0002)

#define ADDC_GEN_NUMBER_1             (0x01)
#define ADDC_GEN_NUMBER_2             (0x02)
#define ADDC_GEN_NUMBER_3             (0x03)

#define EPYC_PROG_SEG_ID              (0x01)
#define MI_PROG_SEG_ID                (0x02)
#define NAVI_PROG_SEG_ID              (0x03)

/*
 * Validation bits definition for validation_bits in struct
 * cper_record_header. If set, corresponding fields in struct
 * cper_record_header contain valid information.
 */
#define CPER_VALID_PLATFORM_ID          (0x0001)
#define CPER_VALID_TIMESTAMP            (0x0002)
#define CPER_VALID_PARTITION_ID         (0x0004)

#define CPU_ID_VALID                    (0x02)
#define LOCAL_APIC_ID_VALID             (0x01)
#define FAILURE_SIGNATURE_ID            (0x04)

#define PROC_CONTEXT_STRUCT_VALID       (0x100)
#define INFO_VALID_CHECK_INFO           (0x01)

#define BLOCK_ID_33                     (33)
#define FRU_ID_VALID                    (0x01)
#define FRU_TEXT_VALID                  (0x02)
#define FOUR_BYTE_MASK                  (0xFFFFFFFF)
#define TWO_BYTE_MASK                   (0xFFFF)
#define INT_15                          (0x0F)
#define INT_255                         (0xFF)
#define SHIFT_4                         (4)
#define SHIFT_23                        (23)
#define SHIFT_25                        (25)
#define INDEX_0                         (0)
#define INDEX_1                         (1)
#define INDEX_2                         (2)
#define INDEX_3                         (3)
#define INDEX_4                         (4)
#define INDEX_5                         (5)
#define INDEX_8                         (8)
#define INDEX_16                        (0x10)
#define BASE_16                         (16)

typedef struct {
  unsigned char b[16];
} GUID_T;

#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)          \
((GUID_T)                               \
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,                   \
   (c) & 0xff, ((c) >> 8) & 0xff,                   \
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})

/* Machine Check Exception */
#define CPER_NOTIFY_MCE                         \
    GUID_INIT(0xE8F56FFE, 0x919C, 0x4cc5, 0xBA, 0x88, 0x65, 0xAB,   \
          0xE1, 0x49, 0x13, 0xBB)
#define CPER_CREATOR_PSTORE                     \
    GUID_INIT(0x61fa3fac, 0xcb80, 0x4292, 0x8b, 0xfb, 0xd6, 0x43,   \
          0xb1, 0xde, 0x17, 0xf4)
#define VENDOR_OOB_CRASHDUMP                    \
    GUID_INIT(0x32AC0C78, 0x2623, 0x48F6, 0xB0, 0xD0, 0x73, 0x65,   \
          0x72, 0x5F, 0xD6, 0xAE)

typedef struct {
  uint32_t mca_data[MCA_BANK_MAX_OFFSET];
} CRASHDUMP_T;

typedef struct {
  uint32_t WdtData[LAST_TRANS_ADDR_OFFSET];
} LAST_TRANS_ADDR;

typedef struct {
  uint32_t PcieData[PCIE_DUMP_OFFSET];
} PCIE_DUMP;

struct error_time_stamp {
  uint8_t    Seconds;
  uint8_t    Minutes;
  uint8_t    Hours;
  uint8_t    Flag;
  uint8_t    Day;
  uint8_t    Month;
  uint8_t    Year;
  uint8_t    Century;
} __attribute__((packed));

typedef struct error_time_stamp ERROR_TIME_STAMP;

struct common_error_record_header {
  unsigned char                      Signature[CPER_SIG_SIZE];
  uint16_t                           Revision;
  uint32_t                           SignatureEnd;
  uint16_t                           SectionCount;
  uint32_t                           ErrorSeverity;
  uint32_t                           ValidationBits;
  uint32_t                           RecordLength;
  ERROR_TIME_STAMP                   TimeStamp;
  uint64_t                           PlatformId[INDEX_2];
  GUID_T                             PartitionId;
  GUID_T                             CreatorId;
  GUID_T                             NotifyType;
  uint64_t                           RecordId;
  uint32_t                           Flags;
  uint64_t                           PersistenceInfo;
  uint8_t                            Reserved[12];
} __attribute__((packed));

typedef struct common_error_record_header COMMON_ERROR_RECORD_HEADER;

struct error_section_descriptor {
  uint32_t                           SectionOffset;
  uint32_t                           SectionLength;
  uint8_t                            RevisionMinor;
  uint8_t                            RevisionMajor;
  uint8_t                            SecValidMask;
  uint8_t                            Reserved;
  uint32_t                           SectionFlags;
  GUID_T                             SectionType;
  GUID_T                             FRUId;
  uint32_t                           Severity;
  unsigned char                      FRUText[20];
} __attribute__((packed));

typedef struct error_section_descriptor ERROR_SECTION_DESCRIPTOR;

struct processor_error_section {
  uint64_t                           ValidBits;
  uint64_t                           CPUAPICId;
  uint32_t                           CpuId[12];
  uint32_t                           SignatureID[INDEX_8];
  uint32_t                           Reserved[INDEX_8];
} __attribute__((packed));

typedef struct processor_error_section PROCESSOR_ERROR_SECTION;

struct df_dump {
  LAST_TRANS_ADDR                    LastTransAddr[CCM_COUNT];
}  __attribute__((packed));

typedef struct df_dump DF_DUMP;

struct pcie_dump {
  uint8_t                            BlockID;
  uint8_t                            ValidLogInstance;
  uint16_t                           LogInstanceSize;
  PCIE_DUMP                          PcieDump[MAX_PCIE_INSTANCES];
}  __attribute__((packed));

typedef struct pcie_dump PCIE_DUMP_DATA;

struct context_info {
  uint16_t                           RegisterContextType;
  uint16_t                           RegisterArraySize;
  uint32_t                           MicrocodeVersion;
  uint64_t                           Ppin;
  CRASHDUMP_T                        CrashDumpData[GENOA_MCA_BANKS];
  DF_DUMP                            DfDumpData;
  uint32_t                           Reserved[96];
  PCIE_DUMP_DATA                     PcieDumpData;
  uint32_t                           reserved[DF_DUMP_RESERVED];
} __attribute__((packed));

typedef struct context_info CONTEXT_INFO;

struct error_record {
    PROCESSOR_ERROR_SECTION           ProcError;
    CONTEXT_INFO                      ContextInfo;
} __attribute__((packed));

typedef struct error_record ERROR_RECORD;

struct cper_record {
    COMMON_ERROR_RECORD_HEADER        Header;
    ERROR_SECTION_DESCRIPTOR          SectionDescriptor[INDEX_2];
    ERROR_RECORD                      P0_ErrorRecord;
    ERROR_RECORD                      P1_ErrorRecord;
}  __attribute__((packed));

typedef struct cper_record CPER_RECORD;

#endif
