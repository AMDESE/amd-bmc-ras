#include "cper.hpp"

/** @class CperGenerator
 *  @brief Implementation of CPER record creation
 */

template <typename T>
class CperGenerator
{

  public:
    /** @brief Push contents of the error record header of the CPER file
     *  @param[in] data - Shared pointer to the CPER record object.
     *  @param[in] sectionCount - Number of error sections in the CPER record.
     *  @param[in] errorSeverity - Error Severity - fatal , correctable or
     * uncorrectable.
     *  @param[in] errorType - Fatal or runtime - MCA, DRAM or PCIE AER errors.
     */
    void dumpCperHeaderSection(const std::shared_ptr<T>&, uint16_t, uint32_t,
                               std::string);

    /** @brief Create a GUID with the input reference number provided
        @param[in] Input paramters a,b,c,d0 to d7.
        @returns unique identifier as GUID_T
     */
    GUID_T initializeGUID(unsigned int, unsigned short, unsigned short,
                          unsigned char, unsigned char, unsigned char,
                          unsigned char, unsigned char, unsigned char,
                          unsigned char, unsigned char);

    /** @brief Function to calculate and set the timestamp for a given data
     * object
     *  @param[in] data - Shared pointer to the CPER record object.
     */
    void calculateTimeStamp(const std::shared_ptr<T>& data);

    /** @brief Function to dump the error descriptor section of a given data
     * object
     *  @param[in] data - Shared pointer to CPER record object
     *  @param[in] SectionCount - The number of error descriptor sections.
     *  @param[in] ErrorType - The type of error.
     *  @param[out] Severity - Pointer to the severity level of the error.
     */
    void dumpErrorDescriptorSection(const std::shared_ptr<T>&, uint16_t,
                                    std::string, uint32_t*);

    /** @brief Function to dump processor error section to CPER record.
     *  @param[in] socNum - socket number.
     */
    void dumpProcessorErrorSection(uint8_t);

    /** @brief Function to dump context information to CPER record.
     *  @param[in]  - Number of valid MCA banks.
     *  @param[in]  - Number of valid bytes per MCA bank.
     *  @param[in]  - Socket Number
     */
    void dumpContextInfo(uint16_t, uint16_t, uint8_t);

    /** @brief Function to write error information to a CPER file.
     *  @param[in] data - Shared pointer to the CPER record object
     *  @param[in] ErrorType - The type of error.
     *  @param[in] SectionCount - The number of error descriptor sections.
     */
    void cperFileWrite(const std::shared_ptr<T>&, std::string, uint16_t);
};
