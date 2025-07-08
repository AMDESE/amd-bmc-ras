#pragma once

#include "base_manager.hpp"

static constexpr std::string_view runtimeMcaErr = "RUNTIME_MCA_ERROR";
static constexpr std::string_view runtimePcieErr = "RUNTIME_PCIE_ERROR";
static constexpr std::string_view runtimeDramErr = "RUNTIME_DRAM_ERROR";
static constexpr std::string_view fatalErr = "FATAL";

namespace amd
{
namespace ras
{
namespace util
{
namespace cper
{

constexpr uint8_t sevNonFatalUncorrected = 0;
constexpr uint8_t sevNonFatalCorrected = 2;

constexpr uint8_t cperValidPlatformId = 0x1;
constexpr uint8_t cperValidTimestamp = 0x2;
constexpr uint8_t addcGenNumber3 = 0x03;
constexpr uint8_t familyId1ah = 0x1A;
constexpr uint16_t pcieVendorId = 0x1022;
constexpr uint8_t minorRevision = 0xB;

/** @brief Finds a filename in the RAS directory that matches a given pattern.
 *
 *  @details Searches the RAS directory for a file whose name contains the
 * specified number and ends with ".cper". If a matching file is found, its name
 * is returned; otherwise, an empty string is returned.
 *
 *  @param[in] number - The number to be included in the filename pattern.
 *
 *  @return Returns the name of the matching file, or an empty string if no
 * match is found.
 */
std::string findCperFilename(size_t);

/** @brief Creates an index file and reads the error count from it.
 *
 *  @details Creates an index file in the specified RAS directory using the
 * provided utility function. Opens the created file and reads the error count.
 * Throws a runtime error if the file cannot be read or if the error count
 * cannot be extracted.
 *
 *  @param[out] errCount - Reference to a variable where the error count will be
 * stored.
 *
 *  @throw std::runtime_error if the file cannot be read or the error count
 * cannot be extracted.
 */
void createIndexFile(size_t&);

/** @brief Exports crashdump data to D-Bus.
 *
 *  @details Creates a D-Bus instance for crashdump data using the provided
 * index and timestamp. Logs an error if the index is out of range (0-9). Finds
 * the filename, formats the timestamp, and creates or replaces the D-Bus
 * instance.
 *
 *  @param[in] num - The index number for the crashdump file.
 *  @param[in] TimeStampStr - The timestamp structure for the crashdump.
 *  @param[in] objectServer - The D-Bus object server.
 *  @param[in] systemBus - The D-Bus system bus connection.
 *
 *  @throw std::runtime_error if the file cannot be read or the error count
 * cannot be extracted.
 */
void exportToDBus(size_t, const EFI_ERROR_TIME_STAMP&,
                  sdbusplus::asio::object_server&,
                  std::shared_ptr<sdbusplus::asio::connection>&);

/** @brief Creates D-Bus records for existing crashdumps.
 *
 *  @details Checks for existing crashdump files in the RAS directory, reads
 * their timestamps, and exports them to D-Bus.
 *
 *  @param[in] objectServer - The D-Bus object server.
 *  @param[in] systemBus - The D-Bus system bus connection.
 */
void createRecord(sdbusplus::asio::object_server& objectServer,
                  std::shared_ptr<sdbusplus::asio::connection>& systemBus);

/** @brief Calculates and sets the current timestamp in the provided data
 * structure.
 *
 *  @details Uses the current system time to populate the timestamp fields in
 * the data structure. The timestamp includes seconds, minutes, hours, day,
 * month, year, and century.
 *
 *  @param[in] data - Shared pointer to the data structure where the timestamp
 * will be set.
 */
template <typename PtrType>
void calculateTimestamp(const std::shared_ptr<PtrType>&);

/** @brief CPER header initialization.
 *
 *  @details Initializes the CPER header with provided details.
 *
 *  @param[in] data - Shared pointer to the data structure.
 *  @param[in] sectionCount - Number of valid sections.
 *  @param[in] errorSeverity - Severity of the error.
 *  @param[in] errorType - Type of the error.
 *  @param[in] boardId - ID of the board.
 *  @param[in] recordId - Reference to the record ID.
 */

template <typename PtrType>
void dumpHeader(const std::shared_ptr<PtrType>&, uint16_t, uint32_t,
                const std::string_view&, unsigned int, uint64_t&);

/** @brief CPER Error descriptor initialization.
 *
 *  @details Initializes the CPER error descriptor with provided details.
 *
 *  @param[in] data - Shared pointer to the data structure.
 *  @param[in] sectionCount - Number of sections.
 *  @param[in] errorType - Type of the error.
 *  @param[in] severity - Pointer to the severity values.
 *  @param[in] progId - Program ID.
 */
template <typename PtrType>
void dumpErrorDescriptor(const std::shared_ptr<PtrType>&, uint16_t,
                         const std::string_view&, uint32_t*, uint8_t);

/** @brief Dumps processor error details into the fatal CPER record.
 *
 *  @details Populates the fatal CPER record with cpuid , APIC Id info.
 *
 *  @param[in] fatalPtr - Shared pointer to the fatal CPER record.
 *  @param[in] socNum - SoC number.
 *  @param[in] cpuId - Unique pointer to an array of CPU IDs.
 *  @param[in] cpuCount - Number of CPUs.
 */
void dumpProcessorError(const std::shared_ptr<FatalCperRecord>&, uint8_t,
                        const std::unique_ptr<CpuId[]>&, uint8_t, uint16_t);

/** @brief Dumps processor error information into the MCA runtime CPER record.
 *
 *  @details Populates the MCA runtime CPER record with processor error
 * information, including valid bits,MCA array size, MS check GUID.
 *
 *  @param[in] procPtr - Shared pointer to the MCA runtime CPER record.
 *  @param[in] sectionCount - Number of sections.
 *  @param[in] checkInfo - Pointer to the check information.
 *  @param[in] sectionStart - Start of the section.
 *  @param[in] cpuCount - Number of CPUs.
 *  @param[in] cpuId - Unique pointer to an array of CPU IDs.
 */
void dumpProcErrorInfoSection(const std::shared_ptr<McaRuntimeCperRecord>&,
                              uint16_t, uint64_t*, uint32_t, uint8_t,
                              const std::unique_ptr<CpuId[]>&);

/** @brief Dumps context information into the fatal CPER record.
 *
 *  @details Populates the fatal CPER record with context information, including
 * the number of banks, bytes per MCA, SoC number, PPIN, microcode.
 *
 *  @param[in] fatalPtr - Shared pointer to the fatal CPER record.
 *  @param[in] numbanks - Number of banks.
 *  @param[in] bytespermca - Bytes per MCA.
 *  @param[in] socNum - SoC number.
 *  @param[in] ppin - Unique pointer to an array of PPIN values.
 *  @param[in] uCode - Unique pointer to an array of microcode values.
 *  @param[in] cpuCount - Number of CPUs.
 */
void dumpContext(const std::shared_ptr<FatalCperRecord>&, uint16_t numbanks,
                 uint16_t bytespermca, uint8_t,
                 const std::unique_ptr<uint64_t[]>&,
                 const std::unique_ptr<uint32_t[]>&, size_t);

/** @brief Dumps PCIe error information into the PCIe runtime CPER record.
 *
 *  @details Populates the PCIe runtime CPER record with error information,
 * including Port type, Version and vendor ID.
 *
 *  @param[in] data - Shared pointer to the PCIe runtime CPER record.
 *  @param[in] sectionStart - Start of the section.
 *  @param[in] sectionCount - Number of sections.
 */
void dumpPcieErrorInfo(const std::shared_ptr<PcieRuntimeCperRecord>& data,
                       uint16_t sectionStart, uint16_t sectionCount);

/** @brief Creates a CPER file based on the error type and section count.
 *
 *  @details Removes existing CPER files in the RAS directory, sets the filename
 * based on the error type, and saves the new CPER file. Logs the file path
 * where the CPER file is saved.
 *
 *  @param[in] data - Shared pointer to the data structure to be saved.
 *  @param[in] errorType - The type of error as a string view.
 *  @param[in] sectionCount - The number of sections in the CPER file.
 *  @param[in] errCount - Reference to the error count.
 */
template <typename T>
void createFile(const std::shared_ptr<T>&, const std::string_view&, uint16_t,
                size_t&);

/** @brief Checks if the signature ID matches the configuration list.
 *
 *  @details Compares the signature ID of the fatal error with the
 * configuration signature ID list.
 *
 *  @param[in] configSigIdList - Pointer to the map of configuration signature
 * IDs.
 *  @param[in] rcd - Shared pointer to the fatal CPER record.
 *
 *  @return Returns true if the signature ID matches, false otherwise.
 */
bool checkSignatureIdMatch(std::map<std::string, std::string>*,
                           const std::shared_ptr<FatalCperRecord>&);

/** @brief Determines the highest severity level from section severities for
 * CPER.
 *
 *  @details Evaluates the severity levels of different sections and returns the
 * highest severity. The severity order is: Fatal > non-fatal uncorrected >
 * corrected. Logs an error if a fatal severity is found in a runtime CPER.
 *
 *  @param[in] severity - Pointer to an array of severity values.
 *  @param[in] sectionCount - The number of sections to evaluate.
 *  @param[in] highestSeverity - Pointer to store the highest severity value.
 *  @param[in] errorType - The type of error as a string view.
 *
 *  @return Returns true if the severity calculation is successful, false
 * otherwise.
 */
bool calculateSeverity(uint32_t*, uint16_t, uint32_t*, const std::string_view&);

} // namespace cper
} // namespace util
} // namespace ras
} // namespace amd
