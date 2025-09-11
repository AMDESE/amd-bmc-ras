#pragma once

#include <sdbusplus/asio/object_server.hpp>

namespace amd
{
namespace ras
{
namespace util
{
/** @brief Creates a file in the specified directory.
 *
 *  @details Ensures that the specified directory exists and
 *  creates the file if it doesn't already exist.
 *
 *  @param[in] directoryName - Name of the directory to create or use.
 *  @param[in] fileName - Name of the file to create.
 *
 *  @return Throws a std::runtime_error on failure to create
 *  the directory or file.
 */
void createFile(const std::string&, const std::string&);

/** @brief Converts a hexadecimal string to a vector of 32-bit unsigned
 * integers.
 *
 *  @details Processes the input hexadecimal string, skipping the "0x" prefix if
 * present, and converts it into a vector of 32-bit unsigned integers. The
 * function processes the string in chunks of 8 characters (32 bits) and pads
 * the result vector with leading zeros if necessary to ensure it has at least 8
 * elements.
 *
 *  @param[in] hexString - The input hexadecimal string to be converted.
 *
 *  @return Returns a vector of 32-bit unsigned integers representing the
 * hexadecimal string.
 */
std::vector<uint32_t> stringToVector(const std::string&);

/** @brief Compares the bitwise AND result of an array and a hexadecimal string.
 *
 *  @details Converts the input hexadecimal string to a vector of 32-bit
 * unsigned integers, pads the input array with leading zeros if necessary,
 * reverses the order of elements, performs a bitwise AND operation between the
 * array and the vector, and compares the result with the original vector.
 *
 *  @param[in] Var - Pointer to the array of 32-bit unsigned integers.
 *  @param[in] hexString - The input hexadecimal string to be compared.
 *
 *  @return Returns true if the bitwise AND result matches the original vector,
 * false otherwise.
 */
bool compareBitwiseAnd(const uint32_t*, const std::string& hexString);

/** @brief Requests a transition of the host state based on the provided
 * command.
 *
 * @details This function handles various host state transitions as specified by
 * the command string.
 *
 * @param command The command string specifying the desired host state
 * transition.
 */
void requestHostTransition(std::string);

/** @brief Triggers RSMRST signal.
 *
 * @details This function triggers a reset of the RSMRST (Resume Reset) signal.
 */
void triggerRsmrstReset();

/** @brief Initiates a system reset.
 *
 * @details This function triggers system reset using D-Bus calls.
 */
void triggerSysReset();

/** @brief Triggers a cold reset.
 *
 * @details Triggers a cold reset using the specified reset signal.
 *
 * @param Type of the cold reset signal to be executed.
 */
void triggerColdReset(const std::string*);

/** @brief Initiates a warm reset.
 *
 * @details trigger warm reset using apml command.
 *
 * @param[in] socNum - Socket number of the processor.
 */
void triggerWarmReset(std::string& node);

/** @brief Performs a RAS recovery action.
 *
 * @details This function executes the appropriate recovery procedures after a
 * fatal error.
 *
 *  @param[in] buf - Status buffer indicating error conditions.
 * @param[in] socNum - Socket number of the processor.
 *  @param[in] systemRecovery - Pointer to the system recovery policy string.
 *  @param[in] resetSignal - Pointer to the reset signal string.
 */
void rasRecoveryAction(std::string&, uint8_t, const std::string*,
                       const std::string*);

/** @brief Gets value from D-Bus property.
 *
 *  @details Reads D-Bus property value within the given interface.
 *  Returns the property value as the specified type.
 *
 *  @param[in] bus - D-Bus connection.
 *  @param[in] service - D-Bus service name.
 *  @param[in] path - Object path of the property.
 *  @param[in] interface - Interface of the property.
 *  @param[in] propertyName - Name of the property to retrieve.
 *
 *  @return Returns the value of the property as type ReturnType.
 *  @return Throws sdbusplus::exception::SdBusError on failure.
 */

template <typename ReturnType>
ReturnType getProperty(sdbusplus::bus::bus&, const char*, const char*,
                       const char*, const char*);

/** @brief Checks if the given D-Bus path exists.
 *
 *  @details Queries the D-Bus for paths related to crash dumps and checks if
 * the specified path exists.
 *
 *  @param[in] dbusPath - The D-Bus path to check.
 *
 *  @return Returns true if the D-Bus path exists, false otherwise.
 */
bool checkObjPath(std::string);

} // namespace util
} // namespace ras
} // namespace amd
