#ifndef CPER_H
#define CPER_H

#define CPER_SIG_SIZE               (4)
#define CPER_SIG_RECORD             ("CPER")
#define CPER_RECORD_REV             (0x0100)
#define FATAL_SECTION_COUNT         (2)
#define CPER_SIG_END                (0xffffffff)
#define CPER_SEV_FATAL              (1)
#define SEV_NON_FATAL_UNCORRECTED   (0)
#define SEV_NON_FATAL_CORRECTED     (2)
#define CTX_OOB_CRASH               (0x01)
#define CPER_PRIMARY                (1)
#define RSVD                        (0)
#define GENOA_MCA_BANKS             (32)
#define MCA_BANK_MAX_OFFSET         (128)
#define SYS_MGMT_CTRL_ERR           (0x04)
#define RESET_HANG_ERR              (0x02)
#define DEUB_LOG_DUMP_REGION        (12124)
#define MAX_ERROR_FILE              (10)
#define LAST_TRANS_ADDR_OFFSET      (4)
#define CCM_COUNT                   (8)
#define BYTE_4                      (4)
#define BYTE_2                      (2)
#define ENABLE_BIT                  (1)

#define BLOCK_ID_1                      (1)
#define BLOCK_ID_2                      (2)
#define BLOCK_ID_3                      (3)
#define BLOCK_ID_24                     (24)
#define BLOCK_ID_33                     (33)
#define BLOCK_ID_36                     (36)
#define BLOCK_ID_37                     (37)
#define BLOCK_ID_38                     (38)
#define BLOCK_ID_39                     (39)
#define BLOCK_ID_40                     (40)

/*
 * CPER section descriptor revision, used in revision field in struct
 * cper_section_descriptor
 */
#define CPER_MINOR_REV                (0x0004)

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
#define INT_15                          (0xFF)
#define INT_255                         (0xFF)
#define SHIFT_4                         (4)
#define SHIFT_23                        (23)
#define SHIFT_25                        (25)
#define SHIFT_32                        (32)
#define INDEX_0                         (0)
#define INDEX_1                         (1)
#define INDEX_2                         (2)
#define INDEX_3                         (3)
#define INDEX_4                         (4)
#define INDEX_5                         (5)
#define INDEX_6                         (6)
#define INDEX_7                         (7)
#define INDEX_8                         (8)
#define INDEX_11                        (11)
#define INDEX_12                        (12)
#define INDEX_16                        (0x10)
#define INDEX_19                        (19)
#define INDEX_20                        (20)
#define INDEX_23                        (23)
#define INDEX_24                        (24)
#define INDEX_32                        (32)
#define INDEX_44                        (44)
#define INDEX_57                        (57)
#define INDEX_60                        (60)
#define INDEX_61                        (61)
#define INDEX_62                        (62)
#define BASE_16                         (16)
#define RESERVE_96                      (96)

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
#define CPER_NOTIFY_CMC                         \
    GUID_INIT(0x2DCE8BB1, 0xBDD7, 0x450e, 0xB9, 0xAD, 0x9C, 0xF4,   \
          0xEB, 0xD4, 0xF8, 0x90)
#define CPER_NOTIFY_PCIE                        \
    GUID_INIT(0xCF93C01F, 0x1A16, 0x4dfc, 0xB8, 0xBC, 0x9C, 0x4D,   \
          0xAF, 0x67, 0xC1, 0x04)
#define CPER_CREATOR_PSTORE                     \
    GUID_INIT(0x61fa3fac, 0xcb80, 0x4292, 0x8b, 0xfb, 0xd6, 0x43,   \
          0xb1, 0xde, 0x17, 0xf4)
#define AMD_OOB_CRASHDUMP                       \
    GUID_INIT(0x32AC0C78, 0x2623, 0x48F6, 0xB0, 0xD0, 0x73, 0x65,   \
          0x72, 0x5F, 0xD6, 0xAE)
#define PROC_ERR_SECTION_TYPE                   \
    GUID_INIT(0xDC3EA0B0, 0xA144, 0x4797, 0xB9, 0x5B, 0x53, 0xFA,   \
          0x24, 0x2B, 0x6E, 0x1D)
#define PCIE_ERR_SECTION_TYPE                   \
    GUID_INIT(0xD995E954, 0xBBC1, 0x430F, 0xAD, 0x91, 0xB4, 0x4D,   \
          0xCB, 0x3C, 0x6F, 0x35)

#define MS_CHECK_GUID                           \
    GUID_INIT(0x48AB7F57, 0xDC34, 0x4f6c, 0xA7, 0xD3, 0xB0, 0xB5,   \
          0xB0, 0xA7, 0x43, 0x14)

typedef struct {
  uint32_t mca_data[MCA_BANK_MAX_OFFSET];
} CRASHDUMP_T;

typedef struct {
  uint32_t WdtData[LAST_TRANS_ADDR_OFFSET];
} LAST_TRANS_ADDR;

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
  uint64_t                           FRUId[INDEX_2];
  uint32_t                           Severity;
  char                               FRUText[INDEX_20];
} __attribute__((packed));

typedef struct error_section_descriptor ERROR_SECTION_DESCRIPTOR;

struct processor_error_section {
  uint64_t                           ValidBits;
  uint64_t                           CPUAPICId;
  uint32_t                           CpuId[INDEX_12];
  uint32_t                           SignatureID[INDEX_8];
  uint32_t                           Reserved[INDEX_8];
} __attribute__((packed));

typedef struct processor_error_section PROCESSOR_ERROR_SECTION;

struct df_dump {
  LAST_TRANS_ADDR                    LastTransAddr[CCM_COUNT];
}  __attribute__((packed));

typedef struct df_dump DF_DUMP;

struct context_info {
  uint16_t                           RegisterContextType;
  uint16_t                           RegisterArraySize;
  uint32_t                           MicrocodeVersion;
  uint64_t                           Ppin;
  CRASHDUMP_T                        CrashDumpData[GENOA_MCA_BANKS];
  DF_DUMP                            DfDumpData;
  uint32_t                           Reserved[RESERVE_96];
  uint32_t                           DebugLogIdData[DEUB_LOG_DUMP_REGION];
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
