#pragma once

#include "ras.hpp"

extern "C"
{
#include "apml.h"
#include "apml_common.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_rmi.h"
}

/** @class CperGenerator
 *  @brief Implementation of CPER record creation
 */
template <typename T>
class CperGenerator
{
  protected:
    uint32_t boardId;
    uint8_t numOfCpu;
    uint64_t recordId;
    uint8_t progId;
    uint32_t familyId;
    int errCount;

  public:
    /**
     * @brief Constructs a CperGenerator object.
     *
     * @param[in] numOfCpu   The total number of sockets in the system.
     * @param[in] progId     The program ID.
     * @param[in] familyId   The family ID.
     * @param[in] errCount   The preserved error count number for numbering cper
     * files.
     */
    CperGenerator(uint8_t numOfCpu, uint8_t progId, uint32_t familyId,
                  int errCount) :
        numOfCpu(numOfCpu), recordId(1), progId(progId), familyId(familyId),
        errCount(errCount)
    {}

    /** @brief Push contents of the error record header of the CPER file
     *  @param[in] data - Shared pointer to the CPER record object.
     *  @param[in] sectionCount - Number of error sections in the CPER record.
     *  @param[in] errorSeverity - Error Severity - fatal , correctable or
     * uncorrectable.
     *  @param[in] errorType - Fatal or runtime - MCA, DRAM or PCIE AER errors.
     */
    void dumpCperHeaderSection(const std::shared_ptr<T>& data,
                               uint16_t sectionCount, uint32_t errorSeverity,
                               std::string errorType);

    /** @brief Function to calculate and set the timestamp for a given data
     * object
     *  @param[in] data - Shared pointer to the CPER record object.
     */
    void calculateTimeStamp(const std::shared_ptr<T>& data);

    /** @brief Function to dump the error descriptor section of a given data
     * object
     *  @param[in] data - Shared pointer to CPER record object
     *  @param[in] ErrorType - The type of error.
     */
    void dumpErrorDescriptorSection(const std::shared_ptr<T>&, uint16_t,
                                    std::string);

    /** @brief Function to dump processor error section to CPER record.
     *  @param[in] socNum - socket number.
     *  @param[in] - pointer of the structure variable CpuId
     */
    void dumpProcessorErrorSection(const std::shared_ptr<FatalCperRecord>&,
                                   uint8_t, CpuId*);

    /** @brief Function to write error information to a CPER file.
     *  @param[in] data - Shared pointer to the CPER record object
     *  @param[in] ErrorType - The type of error.
     *  @param[in] SectionCount - The number of error descriptor sections.
     */
    void cperFileWrite(const std::shared_ptr<T>&, std::string, uint16_t);

    /** @brief Function to dump context information to CPER record.
     *  @param[in] data - Shared pointer to the CPER record object
     *  @param[in]  - Number of valid MCA banks.
     *  @param[in]  - Number of valid bytes per MCA bank.
     *  @param[in]  - Socket Number
     *  @param[in]  - The number of fatal error sections.
     *  @param[in]  - A vector of uint8_t representing block IDs
     *  @param[in]  - PPIn The processor pin read from apml commands
     *  @param[in]  - Microcode version read from apml commands
     *  @param[in]  - The total number of apml retriesi during failure.
     */
    void dumpContextInfo(const std::shared_ptr<FatalCperRecord>&, uint16_t,
                         uint16_t, uint8_t, std::vector<uint8_t>, uint64_t*,
                         uint32_t*, int64_t*);

    /** @brief Function to dump the last transaction address during a fatal
     * error
     *  @param[in] data - Shared pointer to the CPER record object
     *  @param[in] socNum - socket number.
     */
    void getLastTransAddr(const std::shared_ptr<FatalCperRecord>&, uint8_t);

    /** @brief Function to harvest number of valid debug log instances during a
     * Syncflood.
     *  @param[in] data - Shared pointer to the CPER record object
     *  @param[in] socNum - socket number.
     *  @param[in]  - A vector of uint8_t representing block IDs
     *  @param[in]  - PPIn The processor pin read from apml commands
     *  @param[in]  - Offset for the debug log ID in the CPER record
     */
    void harvestDebugLogDump(const std::shared_ptr<FatalCperRecord>&, uint8_t,
                             uint8_t, int64_t*, uint16_t&);

    std::string getCperFilename(int);
};
