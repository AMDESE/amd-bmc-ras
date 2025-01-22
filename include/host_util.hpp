#pragma once

#include "dbus_util.hpp"

namespace amd
{
namespace ras
{
namespace host
{
namespace util
{

/** @brief Requests a transition of the host state based on the provided
 * command.
 *
 * @details This function handles various host state transitions as specified by
 * the command string.
 */
void requestHostTransition(std::string command);

/** @brief Triggers RSMRST signal.
 *
 * @brief This function triggers a reset of the RSMRST (Resume Reset) signal.
 */
void triggerRsmrstReset();

/** @brief Initiates a system reset.
 *
 * @brief This function triggers system reset using D-Bus calls.
 */
void triggerSysReset();

/** @brief Triggers a cold reset using the specified reset signal.
 *
 * @param A cold reset power cycles the system.
 */
void triggerColdReset(const std::string* resetSignal);

/** @brief Initiates a warm reset.
 *
 * @param trigger warm reset using apml command.
 */
void triggerWarmReset();

/** @brief Performs a RAS recovery action.
 *
 * @details This function uses the provided buffer, system recovery string, and
 * reset signal to execute the appropriate recovery procedures.
 *
 */
void rasRecoveryAction(uint8_t buf, const std::string* systemRecovery,
                       const std::string* resetSignal);

} // namespace util
} // namespace host
} // namespace ras
} // namespace amd
