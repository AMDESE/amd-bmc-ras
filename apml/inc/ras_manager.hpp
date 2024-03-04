#pragma once

extern "C" {
#include "apml.h"
#include "esmi_cpuid_msr.h"
#include "esmi_mailbox.h"
#include "esmi_mailbox_nda.h"
#include "esmi_rmi.h"
}

enum ErrorType
{
    ERROR_TYPE_FATAL,
    ERROR_TYPE_NON_FATAL
};

class InterfaceManager
{
  private:
  public:
    /** @brief Method to do apml initialization.

        @throws exception if the apml interface is corrupted and the host datas
       are unable to be read.
      */
    void init();

    /** @brief Method to configure initial set of registers for ADDC
     * functionality.
     */
    void configure();

    /** @brief Method to override configuration dbus interface.
        Method to create d-bus object path for existing and newly created CPER
       record.
    */
    void dbusOffload();

    /** @brief Method to monitor fatal and non fatal error in the host and
       harvest the error data on fatal/non-fatal errors.
        @param[in] - Enum representation of FATAL or NON-FATAL error.
    */
    void harvestDumps(ErrorType);

    /** @brief Method to perform system recovery after a Crashdump.
     */
    void doRecoveryAction();
}
