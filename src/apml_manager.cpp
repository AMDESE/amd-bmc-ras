#include "apml_manager.hpp"

#include "config_manager.hpp"
#include "oem_cper.hpp"
#include "util.hpp"
#include "util_cper.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

namespace ras {
namespace apml {
constexpr int BAD_DATA = 0xBAADDA7A;
constexpr int EPYC_PROG_SEG_ID = 0x01;
constexpr int FATAL_ERROR = 1;
constexpr int GENOA_FAMILY_ID = 0x19;
constexpr int RESET_HANG_ERR = 0x02;
constexpr int SBRMI_CONTROL_REGISTER = 0x1;
constexpr int SYS_MGMT_CTRL_ERR = 0x04;
constexpr int SOCKET_0 = 0;
constexpr int SOCKET_1 = 1;
constexpr int TURIN_FAMILY_ID = 0x1A;
constexpr int POLLING_MODE = 0;
constexpr int INTERRUPT_MODE = 1;
constexpr uint8_t MCA_ERR = 0;
constexpr uint8_t DRAM_CECC_ERR = 1;
constexpr uint8_t PCIE_ERR = 2;
constexpr uint8_t CHIP_SEL_NUM_POS = 21;
constexpr uint8_t MCA_ERR_OVERFLOW = 8;
constexpr uint8_t DRAM_CECC_ERR_OVERFLOW = 16;
constexpr uint8_t PCIE_ERR_OVERFLOW = 32;

enum BlockID : unsigned short {
  BLOCK_ID_1 = 1,
  BLOCK_ID_2,
  BLOCK_ID_3,
  BLOCK_ID_23 = 23,
  BLOCK_ID_24,
  BLOCK_ID_33 = 33,
  BLOCK_ID_36 = 36,
  BLOCK_ID_37,
  BLOCK_ID_38,
  BLOCK_ID_40 = 40
};

void writeRegister(uint8_t info, uint32_t reg, uint32_t value) {
  oob_status_t ret;

  ret = esmi_oob_write_byte(info, reg, SBRMI, value);
  if (ret != OOB_SUCCESS) {
    lg2::error("Failed to write register: {REG}", "REG", lg2::hex, reg);
    return;
  }
  lg2::debug("Write to register {REGISTER} is successful", "REGISTER", reg);
}

oob_status_t readRegister(uint8_t info, uint32_t reg, uint8_t *value) {
  oob_status_t ret;
  uint16_t retryCount = 10;

  while (retryCount > 0) {
    ret = esmi_oob_read_byte(info, reg, SBRMI, value);
    if (ret == OOB_SUCCESS) {
      break;
    }

    lg2::error("Failed to read register: {REGISTER} Retrying\n", "REGISTER",
               lg2::hex, reg);

    usleep(1000 * 1000);
    retryCount--;
  }
  if (ret != OOB_SUCCESS) {
    lg2::error("Failed to read register: {REGISTER}\n", "REGISTER", lg2::hex,
               reg);
  }

  return ret;
}

void Manager::currentHostStateMonitor() {
  sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
  boost::system::error_code ec;

  static auto match = sdbusplus::bus::match::match(
      bus,
      "type='signal',member='PropertiesChanged', "
      "interface='org.freedesktop.DBus.Properties', "
      "arg0='xyz.openbmc_project.State.Host'",
      [this](sdbusplus::message::message &message) {
        oob_status_t ret;
        std::string intfName;
        std::map<std::string, std::variant<std::string>> properties;

        try {
          message.read(intfName, properties);
        } catch (std::exception &e) {
          lg2::info("Unable to read host state");
          return;
        }
        if (properties.empty()) {
          lg2::error("ERROR: Empty PropertiesChanged signal received");
          return;
        }

        // We only want to check for CurrentHostState
        if (properties.begin()->first != "CurrentHostState") {
          return;
        }
        std::string *currentHostState =
            std::get_if<std::string>(&(properties.begin()->second));
        if (currentHostState == nullptr) {
          lg2::error("CurrentHostState Property invalid");
          return;
        }

        apmlInitialized = false;

        /*if (std::filesystem::exists(dramCeccErrorFile.data()))
        {
            nlohmann::json j;
            std::ifstream file(dramCeccErrorFile.data());
            file >> j;

            for (auto& pair : P0_DimmEccCount)
            {
                pair.second = 0;
                j[pair.first] = pair.second;
            }

            for (auto& pair : P1_DimmEccCount)
            {
                pair.second = 0;
                j[pair.first] = pair.second;
            }

            std::ofstream outFile(dramCeccErrorFile.data());
            outFile << std::setw(INDEX_4) << j << std::endl;
        }*/

        if (*currentHostState !=
            "xyz.openbmc_project.State.Host.HostState.Off") {
          lg2::info("Current host state monitor changed");
          uint32_t d_out = 0;

          while (ret != OOB_SUCCESS) {
            ret = get_bmc_ras_oob_config(0, &d_out);

            if (ret == OOB_SUCCESS) {
              platformInitialize();
              watchdogTimerCounter = 0;
              break;
            }
            sleep(1);
          }
        }
      });
}

void Manager::platformInitialize() {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  struct processor_info platInfo[1];

  if (platformInitialized == false) {
    while (ret != OOB_SUCCESS) {
      uint8_t socNum = 0;

      ret = esmi_get_processor_info(socNum, platInfo);

      if (ret == OOB_SUCCESS) {
        familyId = platInfo->family;
        break;
      }
      sleep(1);
    }

    if (ret == OOB_SUCCESS) {
      if (platInfo->family == GENOA_FAMILY_ID) {
        blockId = {BLOCK_ID_33};
      } else if (platInfo->family == TURIN_FAMILY_ID) {
        currentHostStateMonitor();
        for (uint8_t i = 0; i < cpuCount; i++) {
          clearSbrmiAlertMask(i);
        }

        blockId = {BLOCK_ID_1,  BLOCK_ID_2,  BLOCK_ID_3,  BLOCK_ID_23,
                   BLOCK_ID_24, BLOCK_ID_33, BLOCK_ID_36, BLOCK_ID_37,
                   BLOCK_ID_38, BLOCK_ID_40};

        runTimeErrorPolling();

        runtimeErrPollingSupported = true;
      }
      platformInitialized = true;
      apmlInitialized = true;
    } else {
      lg2::error("Failed to perform platform initialization");
    }
  } else {
    apmlInitialized = true;

    for (uint8_t i = 0; i < cpuCount; i++) {
      clearSbrmiAlertMask(i);
    }

    if (runtimeErrPollingSupported == true) {
      lg2::info("Setting MCA and DRAM OOB Config");

      setMcaOobConfig();

      lg2::info("Setting MCA and DRAM Error threshold");

      mcaErrThresholdEnable();
    }
  }
}

void Manager::init() {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  uint32_t d_out = 0;

  while (ret != OOB_SUCCESS) {
    ret = get_bmc_ras_oob_config(0, &d_out);

    if (ret == OOB_MAILBOX_CMD_UNKNOWN) {
      ret = esmi_get_processor_info(0, plat_info);
    }
    sleep(1);
  }

  platformInitialize();

  sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
  boost::system::error_code ec;

  static auto match = sdbusplus::bus::match::match(
      bus,
      "type='signal',member='PropertiesChanged', "
      "interface='org.freedesktop.DBus.Properties', "
      "arg0='xyz.openbmc_project.State.Watchdog'",
      [this](sdbusplus::message::message &message) {
        std::string intfName;
        std::map<std::string, std::variant<bool>> properties;

        try {
          message.read(intfName, properties);
        } catch (std::exception &e) {
          lg2::error("Unable to read watchdog state");
          return;
        }
        if (properties.empty()) {
          lg2::error("Empty PropertiesChanged signal received");
          return;
        }

        // We only want to check for CurrentHostState
        if (properties.begin()->first != "Enabled") {
          return;
        }

        bool *currentTimerEnable =
            std::get_if<bool>(&(properties.begin()->second));

        if (*currentTimerEnable == false) {
          sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
          std::string CurrentTimerUse = ras::util::getProperty<std::string>(
              bus, "xyz.openbmc_project.Watchdog",
              "/xyz/openbmc_project/watchdog/host0",
              "xyz.openbmc_project.State.Watchdog", "CurrentTimerUse");

          if (CurrentTimerUse ==
              "xyz.openbmc_project.State.Watchdog.TimerUse.BIOSFRB2") {
            watchdogTimerCounter++;

            /*Watchdog Timer Enable property will be changed twice after
              BIOS post complete. Platform initialization should be
              performed only during the second property change*/
            if (watchdogTimerCounter == 2) {
              lg2::info("BIOS post complete. Setting PCIE OOb config");
              setPcieOobConfig();

              lg2::info("Setting PCIE Error threshold");
              pcieErrThresholdEnable();
            }
          }
        }
      });

  /*Read CpuID*/
  for (int i = 0; i < cpuCount; i++) {
    uint32_t core_id = 0;
    oob_status_t ret;
    cpuId[i].eax = 1;
    cpuId[i].ebx = 0;
    cpuId[i].ecx = 0;
    cpuId[i].edx = 0;

    ret = esmi_oob_cpuid(i, core_id, &cpuId[i].eax, &cpuId[i].ebx,
                         &cpuId[i].ecx, &cpuId[i].edx);

    if (ret) {
      lg2::error("Failed to get the CPUID for socket {CPU}", "CPU", i);
    }
  }
}

void Manager::configure() {
  createDbusInterface(objectServer, systemBus);

  // Request GPIO events for P0 alert handling
  requestGPIOEvents("P0_I3C_APML_ALERT_L",
                    std::bind(&ras::apml::Manager::p0AlertEventHandler, this),
                    p0apmlAlertLine, p0apmlAlertEvent);

  // Request GPIO events for P1 alert handling
  if (cpuCount == 2) {
    requestGPIOEvents("P1_I3C_APML_ALERT_L",
                      std::bind(&ras::apml::Manager::p1AlertEventHandler, this),
                      p0apmlAlertLine, p1apmlAlertEvent);
  }
}

void Manager::clearSbrmiAlertMask(uint8_t socNum) {
  oob_status_t ret;

  lg2::info("Clear Alert Mask bit of SBRMI Control register");

  uint8_t buffer;

  ret = readRegister(socNum, SBRMI_CONTROL_REGISTER, &buffer);

  if (ret == OOB_SUCCESS) {
    buffer = buffer & 0xFE;
    writeRegister(socNum, SBRMI_CONTROL_REGISTER,
                  static_cast<uint32_t>(buffer));
  }
}

void Manager::requestGPIOEvents(
    const std::string &name, const std::function<void()> &handler,
    gpiod::line &gpioLine,
    boost::asio::posix::stream_descriptor &gpioEventDescriptor) {
  try {
    // Find the GPIO line
    gpioLine = gpiod::find_line(name);
    if (!gpioLine) {
      throw std::runtime_error("Failed to find GPIO line: " + name);
    }

    // Request events for the GPIO line
    gpioLine.request({"RAS", gpiod::line_request::EVENT_BOTH_EDGES, 0});

    // Get the GPIO line file descriptor
    int gpioLineFd = gpioLine.event_get_fd();
    if (gpioLineFd < 0) {
      throw std::runtime_error("Failed to get GPIO line file descriptor: " +
                               name);
    }

    // Assign the file descriptor to gpioEventDescriptor
    gpioEventDescriptor.assign(gpioLineFd);

    // Set up asynchronous wait for events
    gpioEventDescriptor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [&name, handler](const boost::system::error_code ec) {
          if (ec) {
            throw std::runtime_error("Error in fd handler: " + ec.message());
          }
          handler();
        });
  } catch (const std::exception &e) {
    lg2::error("Exception: {ERROR}", "ERROR", e.what());
  }
}

void Manager::p0AlertEventHandler() {
  gpiod::line_event gpioLineEvent = p0apmlAlertLine.event_read();

  if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE) {
    lg2::debug("Falling Edge: P0 APML Alert received");

    if (rcd == nullptr) {
      rcd = std::make_shared<FatalCperRecord>();
    }

    decodeInterrupt(SOCKET_0);
  }
  p0apmlAlertEvent.async_wait(boost::asio::posix::stream_descriptor::wait_read,
                              [this](const boost::system::error_code ec) {
                                if (ec) {
                                  lg2::error(
                                      "P0 APML alert handler error: {ERROR}",
                                      "ERROR", ec.message().c_str());
                                  return;
                                }
                                p0AlertEventHandler();
                              });
}

void Manager::p1AlertEventHandler() {
  gpiod::line_event gpioLineEvent = p1apmlAlertLine.event_read();

  if (gpioLineEvent.event_type == gpiod::line_event::FALLING_EDGE) {
    lg2::debug("Falling Edge: P1 APML Alert received");

    if (rcd == nullptr) {
      rcd = std::make_shared<FatalCperRecord>();
    }

    decodeInterrupt(SOCKET_1);
  }
  p1apmlAlertEvent.async_wait(boost::asio::posix::stream_descriptor::wait_read,
                              [this](const boost::system::error_code ec) {
                                if (ec) {
                                  lg2::error(
                                      "P1 APML alert handler error: {ERROR}",
                                      "ERROR", ec.message().c_str());
                                  return;
                                }
                                p1AlertEventHandler();
                              });
}

bool Manager::harvestMcaValidityCheck(uint8_t info, uint16_t *numbanks,
                                      uint16_t *bytespermca) {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
  uint16_t retries = 0;
  bool mcaValidityCheck = true;

  amd::ras::config::Manager::AttributeValue apmlRetry =
      configMgr.getAttribute("ApmlRetries");
  int64_t *apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

  while (ret != OOB_SUCCESS) {
    retries++;

    ret = read_bmc_ras_mca_validity_check(info, bytespermca, numbanks);

    if (retries > *apmlRetryCount) {
      lg2::error("Socket {SOCK}: Failed to get MCA banks with valid status",
                 "SOCK", info);
      break;
    }

    if ((*numbanks == 0) || (*numbanks > 32)) {
      lg2::error("Socket {SOCKET}: Invalid MCA bank validity status. "
                 "Retry Count: {RETRY_COUNT}",
                 "SOCKET", info, "RETRY_COUNT", retries);
      ret = OOB_MAILBOX_CMD_UNKNOWN;
      usleep(1000 * 1000);
      continue;
    }
  }

  if ((*numbanks <= 0) || (*numbanks > 32)) {
    mcaValidityCheck = false;
  }

  return mcaValidityCheck;
}

bool Manager::decodeInterrupt(uint8_t socNum) {
  std::unique_lock lock(harvestMutex);
  uint16_t bytespermca = 0;
  uint16_t numbanks = 0;
  uint8_t buf;
  bool fchHangError = false;
  bool controlFabricError = false;
  bool resetReady = false;
  bool runtimeError = false;

  // Check if APML ALERT is because of RAS
  if (read_sbrmi_ras_status(socNum, &buf) == OOB_SUCCESS) {
    lg2::debug("Read RAS status register. Value: {BUF}", "BUF", buf);

    // check RAS Status Register
    if (buf & 0xFF) {
      lg2::error("The alert signaled is due to a RAS fatal error");

      if (buf & SYS_MGMT_CTRL_ERR) {
        /*if RasStatus[reset_ctrl_err] is set in any of the processors,
          proceed to cold reset, regardless of the status of the other P
        */

        std::string ras_err_msg =
            "Fatal error detected in the control fabric. "
            "BMC may trigger a reset based on policy set. ";

        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);

        p0AlertProcessed = true;
        p1AlertProcessed = true;
        controlFabricError = true;
      } else if (buf & RESET_HANG_ERR) {
        std::string ras_err_msg =
            "System hang while resetting in syncflood."
            "Suggested next step is to do an additional manual "
            "immediate reset";

        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);

        fchHangError = true;
      } else if (buf & FATAL_ERROR) {
        std::string ras_err_msg = "RAS FATAL Error detected. "
                                  "System may reset after harvesting "
                                  "MCA data based on policy set. ";

        sd_journal_send("MESSAGE=%s", ras_err_msg.c_str(), "PRIORITY=%i",
                        LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        ras_err_msg.c_str(), NULL);

        if (true == harvestMcaValidityCheck(socNum, &numbanks, &bytespermca)) {
          harvestMcaDataBanks(socNum, numbanks, bytespermca);
        }
      } else if (buf & MCA_ERR_OVERFLOW) {

        runTimeErrorInfoCheck(MCA_ERR, INTERRUPT_MODE);

        std::string mca_err_overflow_msg =
            "MCA runtime error counter overflow occured";

        sd_journal_send("MESSAGE=%s", mca_err_overflow_msg.c_str(),
                        "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        mca_err_overflow_msg.c_str(), NULL);

        runtimeError = true;
      } else if (buf & DRAM_CECC_ERR_OVERFLOW) {
        runTimeErrorInfoCheck(DRAM_CECC_ERR, INTERRUPT_MODE);

        std::string dram_err_overflow_msg =
            "DRAM CECC runtime error counter overflow occured";

        sd_journal_send("MESSAGE=%s", dram_err_overflow_msg.c_str(),
                        "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        dram_err_overflow_msg.c_str(), NULL);

        runtimeError = true;
      } else if (buf & PCIE_ERR_OVERFLOW) {

        runTimeErrorInfoCheck(PCIE_ERR, INTERRUPT_MODE);

        std::string pcie_err_overflow_msg =
            "PCIE runtime error counter overflow occured";

        sd_journal_send("MESSAGE=%s", pcie_err_overflow_msg.c_str(),
                        "PRIORITY=%i", LOG_ERR, "REDFISH_MESSAGE_ID=%s",
                        "OpenBMC.0.1.CPUError", "REDFISH_MESSAGE_ARGS=%s",
                        pcie_err_overflow_msg.c_str(), NULL);

        runtimeError = true;
      }

      if (socNum == SOCKET_0) {
        p0AlertProcessed = true;
      }

      if (socNum == SOCKET_1) {
        p1AlertProcessed = true;
      }

      // Clear RAS status register
      // 0x4c is a SB-RMI register acting as write to clear
      // check PPR to determine whether potential bug in PPR or in
      // implementation of SMU?

      writeRegister(socNum, 0x4C, buf);

      if (fchHangError == true || runtimeError == true) {
        return true;
      }

      if (cpuCount == 2) {
        if ((p0AlertProcessed == true) && (p1AlertProcessed == true)) {
          resetReady = true;
        }
      } else {
        resetReady = true;
      }
      if (resetReady == true) {
        if (controlFabricError == false) {
          ras::cper::util::createCperFile(rcd, fatalErr, 2, errCount);

          exportCrashdumpToDBus(errCount - 1, rcd->Header.TimeStamp,
                                objectServer, systemBus);
        }

        bool recoveryAction = true;

        amd::ras::config::Manager::AttributeValue aifsArmed =
            configMgr.getAttribute("AifsArmed");
        bool *aifsArmedFlag = std::get_if<bool>(&aifsArmed);

        amd::ras::config::Manager::AttributeValue configSigId =
            configMgr.getAttribute("AifsSignatureIdList");
        std::map<std::string, std::string> *configSigIdList =
            std::get_if<std::map<std::string, std::string>>(&configSigId);

        if ((*aifsArmedFlag == true) &&
            (ras::util::checkSignatureIdMatch(configSigIdList, rcd) == true)) {
          lg2::info("AIFS armed for the system");

          std::ifstream inputFile("/var/lib/bmcweb/eventservice_config.json");

          /*Check if there is any active subscriptions for
            the local AIFS flow*/
          if (inputFile.is_open()) {
            nlohmann::json jsonData;
            inputFile >> jsonData;

            if (jsonData.find("Subscriptions") != jsonData.end()) {
              const auto &subscriptionsArray = jsonData["Subscriptions"];
              if (subscriptionsArray.is_array()) {
                for (const auto &subscription : subscriptionsArray) {
                  const auto &messageIds = subscription["MessageIds"];
                  if (messageIds.is_array()) {
                    bool messageIdFound =
                        std::any_of(messageIds.begin(), messageIds.end(),
                                    [](const std::string &messageId) {
                                      return messageId == "AifsFailureMatch";
                                    });
                    if (messageIdFound) {
                      recoveryAction = false;

                      struct ras_override_delay d_in = {0, 0, 0};
                      bool ack_resp;
                      d_in.stop_delay_counter = 1;
                      oob_status_t ret;

                      amd::ras::config::Manager::AttributeValue
                          disableResetCounter = configMgr.getAttribute(
                              "DisableAifsResetOnSyncfloodCounter");
                      bool *disableResetCntr =
                          std::get_if<bool>(&disableResetCounter);

                      if (*disableResetCntr == true) {
                        lg2::info("Disable Aifs Delay Reset on Syncflood "
                                  "counter is true. Sending Delay Reset on "
                                  "Syncflood override APML command");
                        ret = override_delay_reset_on_sync_flood(socNum, d_in,
                                                                 &ack_resp);

                        if (ret) {
                          lg2::error("Failed to override delay value reset on "
                                     "syncflood Err:{ERRNO}",
                                     "ERRNO", ret);
                        } else {
                          lg2::info("Successfully sent Reset delay on "
                                    "Syncflood command");
                        }
                      }
                      sd_journal_send("PRIORITY=%i", LOG_INFO,
                                      "REDFISH_MESSAGE_ID=%s",
                                      "OpenBMC.0.1."
                                      "AifsFailureMatch",
                                      NULL);
                      break;
                    }
                  }
                }
              }
            }
            inputFile.close();
          }
        }
        if (recoveryAction == true) {
          amd::ras::config::Manager::AttributeValue ResetSignalVal =
              configMgr.getAttribute("ResetSignalType");
          std::string *resetSignal = std::get_if<std::string>(&ResetSignalVal);

          amd::ras::config::Manager::AttributeValue SystemRecoveryVal =
              configMgr.getAttribute("SystemRecoveryMode");
          std::string *systemRecovery =
              std::get_if<std::string>(&SystemRecoveryVal);

          ras::util::rasRecoveryAction(buf, systemRecovery, resetSignal);
        }

        if (rcd->SectionDescriptor != nullptr) {
          delete[] rcd->SectionDescriptor;
          rcd->SectionDescriptor = nullptr;
        }
        if (rcd->ErrorRecord != nullptr) {
          delete[] rcd->ErrorRecord;
          rcd->ErrorRecord = nullptr;
        }

        rcd = nullptr;

        p0AlertProcessed = false;
        p1AlertProcessed = false;
      }
    }
  } else {
    lg2::debug("Nothing to Harvest. Not RAS Error");
  }
  return true;
}

void Manager::getLastTransAddr(const std::shared_ptr<FatalCperRecord> &fatalPtr,
                               uint8_t socNum) {
  oob_status_t ret;
  uint8_t blkId = 0;
  uint16_t n = 0;
  uint16_t maxOffset32;
  uint32_t data;
  struct ras_df_err_chk err_chk;
  union ras_df_err_dump df_err = {0};

  ret = read_ras_df_err_validity_check(socNum, blkId, &err_chk);

  if (ret) {
    lg2::error("Failed to read RAS DF validity check");
  } else {
    if (err_chk.df_block_instances != 0) {
      maxOffset32 =
          ((err_chk.err_log_len % 4) ? 1 : 0) + (err_chk.err_log_len >> 2);
      while (n < err_chk.df_block_instances) {
        for (int offset = 0; offset < maxOffset32; offset++) {
          memset(&data, 0, sizeof(data));
          /* Offset */
          df_err.input[0] = offset * 4;
          /* DF block ID */
          df_err.input[1] = blkId;
          /* DF block ID instance */
          df_err.input[2] = n;

          ret = read_ras_df_err_dump(socNum, df_err, &data);

          fatalPtr->ErrorRecord[socNum]
              .DfDumpData.LastTransAddr[n]
              .WdtData[offset] = data;
        }
        n++;
      }
    }
  }
}

void Manager::harvestDebugLogDump(
    const std::shared_ptr<FatalCperRecord> &fatalPtr, uint8_t socNum,
    uint8_t blkId, int64_t *apmlRetryCount, uint16_t &debugLogIdOffset) {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
  uint16_t retries = 0;
  uint16_t n = 0;
  uint16_t maxOffset32;
  uint32_t data;
  struct ras_df_err_chk err_chk;
  union ras_df_err_dump df_err = {0};

  while (ret != OOB_SUCCESS) {
    retries++;

    ret = read_ras_df_err_validity_check(socNum, blkId, &err_chk);

    if (ret == OOB_SUCCESS) {
      lg2::info("Socket: {SOCKET},Debug Log ID : {DBG_ID} read successful",
                "SOCKET", socNum, "DBG_ID", blkId);
      break;
    }

    if (retries > *apmlRetryCount) {
      lg2::error("Socket: {SOCKET},Debug Log ID : {DBG_ID} read failed",
                 "SOCKET", socNum, "DBG_ID", blkId);

      /*If 5Bh command fails ,0xBAADDA7A is written thrice in the PCIE
       * dump region*/
      fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] = blkId;
      fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
          BAD_DATA;
      fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
          BAD_DATA;
      fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
          BAD_DATA;

      break;
    }
  }
  if (ret == OOB_SUCCESS) {
    if (err_chk.df_block_instances != 0) {
      uint32_t DbgLogIdHeader =
          (static_cast<uint32_t>(err_chk.err_log_len) << 16) |
          (static_cast<uint32_t>(err_chk.df_block_instances) << 8) |
          static_cast<uint32_t>(blkId);

      fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
          DbgLogIdHeader;

      maxOffset32 =
          ((err_chk.err_log_len % 4) ? 1 : 0) + (err_chk.err_log_len >> 2);

      while (n < err_chk.df_block_instances) {
        bool apmlHang = false;

        for (int offset = 0; offset < maxOffset32; offset++) {
          if (apmlHang == false) {
            memset(&data, 0, sizeof(data));
            memset(&df_err, 0, sizeof(df_err));

            /* Offset */
            df_err.input[0] = offset * 4;
            /* DF block ID */
            df_err.input[1] = blkId;
            /* DF block ID instance */
            df_err.input[2] = n;

            ret = read_ras_df_err_dump(socNum, df_err, &data);

            if (ret != OOB_SUCCESS) {
              // retry
              uint16_t retryCount = *apmlRetryCount;

              while (retryCount > 0) {
                memset(&data, 0, sizeof(data));
                memset(&df_err, 0, sizeof(df_err));

                /* Offset */
                df_err.input[0] = offset * 4;
                /* DF block ID */
                df_err.input[1] = blkId;
                /* DF block ID instance */
                df_err.input[2] = n;

                ret = read_ras_df_err_dump(socNum, df_err, &data);

                if (ret == OOB_SUCCESS) {
                  break;
                }
                retryCount--;
                usleep(1000 * 1000);
              }

              if (ret != OOB_SUCCESS) {
                lg2::error("Failed to read debug log dump for "
                           "debug log ID : {BLK_ID}",
                           "BLK_ID", blkId);
                data = BAD_DATA;
                /*the Dump APML command fails in the middle of
                  the iterative loop, then write BAADDA7A for
                  the remaining iterations in the for loop*/
                apmlHang = true;
              }
            }
          }

          fatalPtr->ErrorRecord[socNum].DebugLogIdData[debugLogIdOffset++] =
              data;
        }
        n++;
      }
    }
  }
}

void Manager::harvestMcaDataBanks(uint8_t socNum, uint16_t numbanks,
                                  uint16_t bytespermca) {
  uint16_t n = 0;
  uint16_t maxOffset32;
  uint32_t buffer;
  struct mca_bank mca_dump;
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;
  bool ValidSignatureID = false;

  int syndOffsetLo = 0;
  int syndOffsetHi = 0;
  int ipidOffsetLo = 0;
  int ipidOffsetHi = 0;
  int statusOffsetLo = 0;
  int statusOffsetHi = 0;

  uint32_t mcaStatusLo = 0;
  uint32_t mcaStatusHi = 0;
  uint32_t mcaIpidLo = 0;
  uint32_t mcaIpidHi = 0;
  uint32_t mcaSyndLo = 0;
  uint32_t mcaSyndHi = 0;
  uint32_t mcaPspSynd1Lo = 0;
  uint32_t mcaPspSynd1Hi = 0;
  uint32_t mcaPspSynd2Lo = 0;
  uint32_t mcaPspSynd2Hi = 0;

  amd::ras::config::Manager::AttributeValue sigIdOffsetVal =
      configMgr.getAttribute("SigIdOffset");
  std::vector<std::string> *sigIDOffset =
      std::get_if<std::vector<std::string>>(&sigIdOffsetVal);

  amd::ras::config::Manager::AttributeValue apmlRetry =
      configMgr.getAttribute("ApmlRetries");
  int64_t *apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

  uint16_t sectionCount = 2;  // Standard section count is 2
  uint32_t errorSeverity = 1; // Error severity for fatal error is 1

  rcd->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
  std::memset(rcd->SectionDescriptor, 0,
              2 * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));

  rcd->ErrorRecord = new EFI_AMD_FATAL_ERROR_DATA[sectionCount];
  std::memset(rcd->ErrorRecord, 0, 2 * sizeof(EFI_AMD_FATAL_ERROR_DATA));

  ras::cper::util::dumpHeaderSection(rcd, sectionCount, errorSeverity, fatalErr,
                                     boardId, recordId);
  ras::cper::util::dumpErrorDescriptorSection(rcd, sectionCount, fatalErr,
                                              &errorSeverity, progId, familyId);
  ras::cper::util::dumpProcessorErrorSection(rcd, socNum, cpuId, cpuCount);
  ras::cper::util::dumpContextInfo(rcd, numbanks, bytespermca, socNum, ppin,
                                   uCode, cpuCount);

  for (int i = 0; i < cpuCount; i++) {
    uint8_t blkId;

    getLastTransAddr(rcd, i);

    uint16_t debugLogIdOffset = 0;

    for (blkId = 0; blkId < blockId.size(); blkId++) {
      harvestDebugLogDump(rcd, i, blockId[blkId], apmlRetryCount,
                          debugLogIdOffset);
    }
  }

  syndOffsetLo = std::stoul((*sigIDOffset)[0], nullptr, 16);
  syndOffsetHi = std::stoul((*sigIDOffset)[1], nullptr, 16);
  ipidOffsetLo = std::stoul((*sigIDOffset)[2], nullptr, 16);
  ipidOffsetHi = std::stoul((*sigIDOffset)[3], nullptr, 16);
  statusOffsetLo = std::stoul((*sigIDOffset)[4], nullptr, 16);
  statusOffsetHi = std::stoul((*sigIDOffset)[5], nullptr, 16);

  maxOffset32 = ((bytespermca % 4) ? 1 : 0) + (bytespermca >> 2);
  lg2::info("Number of Valid MCA bank: {NUMBANKS}", "NUMBANKS", numbanks);
  lg2::info("Number of 32 Bit Words:{MAX_OFFSET}", "MAX_OFFSET", maxOffset32);

  while (n < numbanks) {
    for (int offset = 0; offset < maxOffset32; offset++) {
      memset(&buffer, 0, sizeof(buffer));
      memset(&mca_dump, 0, sizeof(mca_dump));
      mca_dump.index = n;
      mca_dump.offset = offset * 4;

      ret = read_bmc_ras_mca_msr_dump(socNum, mca_dump, &buffer);

      if (ret != OOB_SUCCESS) {
        while (*apmlRetryCount > 0) {
          memset(&buffer, 0, sizeof(buffer));
          memset(&mca_dump, 0, sizeof(mca_dump));
          mca_dump.index = n;
          mca_dump.offset = offset * 4;

          ret = read_bmc_ras_mca_msr_dump(socNum, mca_dump, &buffer);

          if (ret == OOB_SUCCESS) {
            break;
          }
          (*apmlRetryCount)--;
          usleep(1000 * 1000);
        }
        if (ret != OOB_SUCCESS) {
          lg2::error("Socket {SOCKET} : Failed to get MCA bank data "
                     "from Bank:{N}, Offset:{OFFSET}",
                     "SOCKET", socNum, "N", n, "OFFSET", lg2::hex, offset);
          rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[offset] =
              BAD_DATA; // Write BAADDA7A pattern on error
          continue;
        }

      } // if (ret != OOB_SUCCESS)

      rcd->ErrorRecord[socNum].CrashDumpData[n].McaData[offset] = buffer;

      if (mca_dump.offset == statusOffsetLo) {
        mcaStatusLo = buffer;
      }
      if (mca_dump.offset == statusOffsetHi) {
        mcaStatusHi = buffer;

        /*Bit 23 and bit 25 of MCA_STATUS_HI
          should be set for a valid signature ID*/
        if ((mcaStatusHi & (1 << 25)) && (mcaStatusHi & (1 << 23))) {
          ValidSignatureID = true;
        }
      }
      if (mca_dump.offset == ipidOffsetLo) {
        mcaIpidLo = buffer;
      }
      if (mca_dump.offset == ipidOffsetHi) {
        mcaIpidHi = buffer;
      }
      if (mca_dump.offset == syndOffsetLo) {
        mcaSyndLo = buffer;
      }
      if (mca_dump.offset == syndOffsetHi) {
        mcaSyndHi = buffer;
      }
      if (mca_dump.offset == 80) {
        mcaPspSynd1Lo = buffer;
      }
      if (mca_dump.offset == 84) {
        mcaPspSynd1Hi = buffer;
      }
      if (mca_dump.offset == 88) {
        mcaPspSynd2Lo = buffer;
      }
      if (mca_dump.offset == 92) {
        mcaPspSynd2Hi = buffer;
      }
    } // for loop

    if (ValidSignatureID == true) {
      rcd->ErrorRecord[socNum].SignatureID[0] = mcaSyndLo;
      rcd->ErrorRecord[socNum].SignatureID[1] = mcaSyndHi;
      rcd->ErrorRecord[socNum].SignatureID[2] = mcaIpidLo;
      rcd->ErrorRecord[socNum].SignatureID[3] = mcaIpidHi;
      rcd->ErrorRecord[socNum].SignatureID[4] = mcaStatusLo;
      rcd->ErrorRecord[socNum].SignatureID[5] = mcaStatusHi;

      rcd->ErrorRecord[socNum].ProcError.ValidFields =
          rcd->ErrorRecord[socNum].ProcError.ValidFields | 0x4;

      ValidSignatureID = false;
    } else {
      mcaSyndLo = 0;
      mcaSyndHi = 0;
      mcaIpidLo = 0;
      mcaIpidHi = 0;
      mcaStatusLo = 0;
      mcaStatusHi = 0;
    }

    memcpy(rcd->SectionDescriptor[socNum].FruString, &mcaPspSynd2Hi, 4);
    memcpy(rcd->SectionDescriptor[socNum].FruString + 4, &mcaPspSynd2Lo, 4);
    memcpy(rcd->SectionDescriptor[socNum].FruString + 8, &mcaPspSynd1Hi, 4);
    memcpy(rcd->SectionDescriptor[socNum].FruString + 12, &mcaPspSynd1Lo, 4);

    rcd->SectionDescriptor[socNum].FruString[16] = '\0';

    n++;
  }
}

void Manager::harvestRuntimeErrors(uint8_t errorPollingType,
                                   struct ras_rt_valid_err_inst p0Inst,
                                   struct ras_rt_valid_err_inst p1Inst) {
  uint32_t *severity = nullptr;
  uint64_t *checkInfo = nullptr;
  uint32_t highestSeverity;
  uint32_t sectionDesSize;
  uint32_t sectionSize;

  uint16_t sectionCount = p0Inst.number_of_inst + p1Inst.number_of_inst;

  severity = new uint32_t[sectionCount];
  checkInfo = new uint64_t[sectionCount];

  if (errorPollingType == MCA_ERR) {
    std::unique_lock lock(mcaErrorHarvestMtx);

    mcaPtr->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
    memset(mcaPtr->SectionDescriptor, 0, sectionDesSize);

    mcaPtr->McaErrorInfo = new RUNTIME_ERROR_INFO[sectionCount];
    sectionSize = sizeof(RUNTIME_ERROR_INFO) * sectionCount;
    memset(mcaPtr->McaErrorInfo, 0, sectionSize);

    uint16_t sectionStart = 0;

    if (p0Inst.number_of_inst != 0) {
      dumpProcErrorSection(mcaPtr, 0, p0Inst, MCA_ERR, sectionStart, severity,
                           checkInfo);

      ras::cper::util::dumpProcErrorInfoSection(mcaPtr, p0Inst.number_of_inst,
                                                checkInfo, sectionStart,
                                                cpuCount, cpuId);
    }
    if (p1Inst.number_of_inst != 0) {
      sectionStart = sectionCount - p1Inst.number_of_inst;

      dumpProcErrorSection(mcaPtr, 1, p1Inst, MCA_ERR, sectionStart, severity,
                           checkInfo);
      ras::cper::util::dumpProcErrorInfoSection(mcaPtr, p1Inst.number_of_inst,
                                                checkInfo, sectionStart,
                                                cpuCount, cpuId);
    }

    ras::util::calculateErrorSeverity(severity, sectionCount, &highestSeverity,
                                      runtimeMcaErr);

    ras::cper::util::dumpHeaderSection(mcaPtr, sectionCount, highestSeverity,
                                       runtimeMcaErr, boardId, recordId);

    ras::cper::util::dumpErrorDescriptorSection(
        mcaPtr, sectionCount, runtimeMcaErr, severity, progId, familyId);

    ras::cper::util::createCperFile(mcaPtr, runtimeMcaErr, sectionCount,
                                    errCount);

    exportCrashdumpToDBus(errCount - 1, mcaPtr->Header.TimeStamp, objectServer,
                          systemBus);

    if (mcaPtr->SectionDescriptor != nullptr) {
      delete[] mcaPtr->SectionDescriptor;
      mcaPtr->SectionDescriptor = nullptr;
    }

    if (mcaPtr->McaErrorInfo != nullptr) {
      delete[] mcaPtr->McaErrorInfo;
      mcaPtr->McaErrorInfo = nullptr;
    }
  } else if (errorPollingType == DRAM_CECC_ERR) {
    std::unique_lock lock(dramErrorHarvestMtx);

    dramPtr->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
    memset(dramPtr->SectionDescriptor, 0, sectionDesSize);

    dramPtr->McaErrorInfo = new RUNTIME_ERROR_INFO[sectionCount];
    sectionSize = sizeof(RUNTIME_ERROR_INFO) * sectionCount;
    memset(dramPtr->McaErrorInfo, 0, sectionSize);

    uint16_t sectionStart = 0;

    if (p0Inst.number_of_inst != 0) {
      dumpProcErrorSection(dramPtr, 0, p0Inst, DRAM_CECC_ERR, sectionStart,
                           severity, checkInfo);
      ras::cper::util::dumpProcErrorInfoSection(dramPtr, p0Inst.number_of_inst,
                                                checkInfo, sectionStart,
                                                cpuCount, cpuId);
    }
    if (p1Inst.number_of_inst != 0) {
      sectionStart = sectionCount - p1Inst.number_of_inst;

      dumpProcErrorSection(mcaPtr, 1, p1Inst, DRAM_CECC_ERR, sectionStart,
                           severity, checkInfo);
      ras::cper::util::dumpProcErrorInfoSection(mcaPtr, p1Inst.number_of_inst,
                                                checkInfo, sectionStart,
                                                cpuCount, cpuId);
    }

    ras::util::calculateErrorSeverity(severity, sectionCount, &highestSeverity,
                                      runtimeDramErr);

    ras::cper::util::dumpHeaderSection(dramPtr, sectionCount, highestSeverity,
                                       runtimeDramErr, boardId, recordId);

    ras::cper::util::dumpErrorDescriptorSection(
        dramPtr, sectionCount, runtimeDramErr, severity, progId, familyId);

    ras::cper::util::createCperFile(dramPtr, runtimeDramErr, sectionCount,
                                    errCount);

    exportCrashdumpToDBus(errCount - 1, dramPtr->Header.TimeStamp, objectServer,
                          systemBus);

    if (dramPtr->SectionDescriptor != nullptr) {
      delete[] dramPtr->SectionDescriptor;
      dramPtr->SectionDescriptor = nullptr;
    }

    if (dramPtr->McaErrorInfo != nullptr) {
      delete[] dramPtr->McaErrorInfo;
      dramPtr->McaErrorInfo = nullptr;
    }
  } else if (errorPollingType == PCIE_ERR) {
    std::unique_lock lock(pcieErrorHarvestMtx);

    pciePtr->SectionDescriptor = new EFI_ERROR_SECTION_DESCRIPTOR[sectionCount];
    sectionDesSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR) * sectionCount;
    memset(pciePtr->SectionDescriptor, 0, sectionDesSize);

    pciePtr->PcieErrorData = new EFI_PCIE_ERROR_DATA[sectionCount];
    sectionSize = sizeof(EFI_PCIE_ERROR_DATA) * sectionCount;
    memset(pciePtr->PcieErrorData, 0, sectionSize);

    uint16_t sectionStart = 0;

    if (p0Inst.number_of_inst != 0) {
      dumpProcErrorSection(pciePtr, 0, p0Inst, PCIE_ERR, sectionStart, severity,
                           checkInfo);

      ras::cper::util::dumpPcieErrorInfoSection(pciePtr, sectionStart,
                                                p0Inst.number_of_inst);
    }
    if (p1Inst.number_of_inst != 0) {
      sectionStart = sectionCount - p1Inst.number_of_inst;

      dumpProcErrorSection(pciePtr, 0, p1Inst, PCIE_ERR, sectionStart, severity,
                           checkInfo);

      ras::cper::util::dumpPcieErrorInfoSection(pciePtr, sectionStart,
                                                p1Inst.number_of_inst);
    }

    ras::util::calculateErrorSeverity(severity, sectionCount, &highestSeverity,
                                      runtimeDramErr);

    ras::cper::util::dumpHeaderSection(pciePtr, sectionCount, highestSeverity,
                                       runtimePcieErr, boardId, recordId);

    ras::cper::util::dumpErrorDescriptorSection(
        pciePtr, sectionCount, runtimePcieErr, severity, progId, familyId);

    ras::cper::util::createCperFile(pciePtr, runtimePcieErr, sectionCount,
                                    errCount);

    exportCrashdumpToDBus(errCount - 1, pciePtr->Header.TimeStamp, objectServer,
                          systemBus);

    if (pciePtr->SectionDescriptor != nullptr) {
      delete[] pciePtr->SectionDescriptor;
      pciePtr->SectionDescriptor = nullptr;
    }

    if (pciePtr->PcieErrorData != nullptr) {
      delete[] pciePtr->PcieErrorData;
      pciePtr->PcieErrorData = nullptr;
    }
  }

  if (checkInfo != nullptr) {
    delete[] checkInfo;
    checkInfo = nullptr;
  }

  if (severity != nullptr) {
    delete[] severity;
    severity = nullptr;
  }
}

oob_status_t
Manager::runTimeErrValidityCheck(uint8_t soc_num,
                                 struct ras_rt_err_req_type rt_err_category,
                                 struct ras_rt_valid_err_inst *inst) {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  if (apmlInitialized == true) {
    ret = get_bmc_ras_run_time_err_validity_ck(soc_num, rt_err_category, inst);
    if (ret) {
      lg2::error("Failed to get bmc ras runtime error validity check");
    }
  }

  return ret;
}

void Manager::runTimeErrorInfoCheck(uint8_t errType, uint8_t reqType) {
  struct ras_rt_valid_err_inst p0_inst, p1_inst;
  struct ras_rt_err_req_type rt_err_category;

  oob_status_t p0_ret = OOB_MAILBOX_CMD_UNKNOWN;
  oob_status_t p1_ret = OOB_MAILBOX_CMD_UNKNOWN;

  rt_err_category.err_type = errType;
  rt_err_category.req_type = reqType;

  memset(&p0_inst, 0, sizeof(p0_inst));
  memset(&p1_inst, 0, sizeof(p1_inst));

  p0_ret = runTimeErrValidityCheck(0, rt_err_category, &p0_inst);

  if (cpuCount == 2) {
    p1_ret = runTimeErrValidityCheck(1, rt_err_category, &p1_inst);
  }

  if (((p0_ret == OOB_SUCCESS) && (p0_inst.number_of_inst > 0)) ||
      ((p1_ret == OOB_SUCCESS) && (p1_inst.number_of_inst > 0))) {
    if (errType == MCA_ERR) {
      if (mcaPtr == nullptr) {
        mcaPtr = std::make_shared<McaRuntimeCperRecord>();
      }
      harvestRuntimeErrors(errType, p0_inst, p1_inst);
    } else if (errType == DRAM_CECC_ERR) {
      if (reqType == POLLING_MODE) {
        if (p0_inst.number_of_inst != 0) {
          harvestDramCeccErrorCounters(p0_inst, 0);
        }
        if (p1_inst.number_of_inst != 0) {
          harvestDramCeccErrorCounters(p1_inst, 1);
        }
      } else if (reqType == INTERRUPT_MODE) {
        if (dramPtr == nullptr) {
          dramPtr = std::make_shared<McaRuntimeCperRecord>();
        }
        harvestRuntimeErrors(errType, p0_inst, p1_inst);
      }
    } else if (errType == PCIE_ERR) {
      if (pciePtr == nullptr) {
        pciePtr = std::make_shared<PcieRuntimeCperRecord>();
      }
      harvestRuntimeErrors(errType, p0_inst, p1_inst);
    }
  }
}

oob_status_t Manager::bmcRasOobConfig(struct oob_config_d_in oob_config) {
  lg2::info("BMC RAS OOB config");
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  for (int i = 0; i < cpuCount; i++) {
    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t *retryCount = std::get_if<int64_t>(&apmlRetry);

    while (*retryCount > 0) {
      --(*retryCount);
      ret = set_bmc_ras_oob_config(i, oob_config);

      if (ret == OOB_SUCCESS || ret == OOB_MAILBOX_CMD_UNKNOWN) {
        break;
      }
      sleep(1);
    }

    if (ret == OOB_SUCCESS) {
      lg2::info("BMC RAS oob configuration set successfully for the processor "
                "P{PROCESSOR}",
                "PROCESSOR", i);
    } else {
      lg2::error("Failed to set BMC RAS OOB configuration for the processor "
                 "P{PROCESSOR}",
                 "PROCESSOR", i);
      break;
    }
  }

  return ret;
}

oob_status_t Manager::setMcaOobConfig() {
  oob_status_t ret;
  struct oob_config_d_in oob_config;

  memset(&oob_config, 0, sizeof(oob_config));

  amd::ras::config::Manager::AttributeValue mcaPolling =
      configMgr.getAttribute("McaPollingEn");
  bool *mcaPollingEn = std::get_if<bool>(&mcaPolling);

  amd::ras::config::Manager::AttributeValue dramCeccPolling =
      configMgr.getAttribute("DramCeccPollingEn");
  bool *dramCeccPollingEn = std::get_if<bool>(&dramCeccPolling);

  if (*mcaPollingEn == true) {
    /* Core MCA OOB Error Reporting Enable */
    oob_config.core_mca_err_reporting_en = 1;
  }

  if (*dramCeccPollingEn == true) {
    /* DRAM CECC OOB Error Counter Mode */
    oob_config.core_mca_err_reporting_en = 1;
    oob_config.dram_cecc_oob_ec_mode = 1; /*Enabled in No leak mode*/
  }

  ret = bmcRasOobConfig(oob_config);

  return ret;
}

void Manager::mcaErrorPollingHandler(int64_t *pollingPeriod) {
  amd::ras::config::Manager::AttributeValue mcaPolling =
      configMgr.getAttribute("McaPollingEn");
  bool *mcaPollingEn = std::get_if<bool>(&mcaPolling);
  if (*mcaPollingEn == true) {
    runTimeErrorInfoCheck(MCA_ERR, POLLING_MODE);
  }
  if (McaErrorPollingEvent != nullptr) {
    delete McaErrorPollingEvent;
  }
  McaErrorPollingEvent = new boost::asio::deadline_timer(
      io, boost::posix_time::seconds(*pollingPeriod));

  McaErrorPollingEvent->async_wait([this](const boost::system::error_code ec) {
    if (ec) {
      lg2::error("fd handler error failed: {MSG}", "MSG", ec.message().c_str());
      return;
    }
    amd::ras::config::Manager::AttributeValue mcaPolling =
        configMgr.getAttribute("McaPollingPeriod");
    int64_t *mcaPollingPeriod = std::get_if<int64_t>(&mcaPolling);
    mcaErrorPollingHandler(mcaPollingPeriod);
  });
}

void Manager::dramCeccErrorPollingHandler(int64_t *pollingPeriod) {
  amd::ras::config::Manager::AttributeValue dramCeccPolling =
      configMgr.getAttribute("DramCeccPollingEn");
  bool *dramCeccPollingEn = std::get_if<bool>(&dramCeccPolling);

  if (*dramCeccPollingEn == true) {
    runTimeErrorInfoCheck(DRAM_CECC_ERR, POLLING_MODE);
  }

  if (DramCeccErrorPollingEvent != nullptr)
    delete DramCeccErrorPollingEvent;

  DramCeccErrorPollingEvent = new boost::asio::deadline_timer(
      io, boost::posix_time::seconds(*pollingPeriod));

  DramCeccErrorPollingEvent->async_wait(
      [this](const boost::system::error_code ec) {
        if (ec) {
          lg2::error("fd handler error failed: {MSG}", "MSG",
                     ec.message().c_str());
          return;
        }

        amd::ras::config::Manager::AttributeValue dramCeccPolling =
            configMgr.getAttribute("DramCeccPollingPeriod");
        int64_t *dramCeccPollingPeriod = std::get_if<int64_t>(&dramCeccPolling);

        dramCeccErrorPollingHandler(dramCeccPollingPeriod);
      });
}

void Manager::pcieAerErrorPollingHandler(int64_t *pollingPeriod) {
  amd::ras::config::Manager::AttributeValue pcieAerPolling =
      configMgr.getAttribute("PcieAerPollingEn");
  bool *pcieAerPollingEn = std::get_if<bool>(&pcieAerPolling);

  if (*pcieAerPollingEn == true) {
    runTimeErrorInfoCheck(PCIE_ERR, POLLING_MODE);
  }

  if (PcieAerErrorPollingEvent != nullptr)
    delete PcieAerErrorPollingEvent;

  PcieAerErrorPollingEvent = new boost::asio::deadline_timer(
      io, boost::posix_time::seconds(*pollingPeriod));

  PcieAerErrorPollingEvent->async_wait([this](
                                           const boost::system::error_code ec) {
    if (ec) {
      lg2::error("fd handler error failed: {MSG}", "MSG", ec.message().c_str());
      return;
    }

    amd::ras::config::Manager::AttributeValue pcieAerPolling =
        configMgr.getAttribute("PcieAerPollingPeriod");
    int64_t *pcieAerPollingPeriod = std::get_if<int64_t>(&pcieAerPolling);

    pcieAerErrorPollingHandler(pcieAerPollingPeriod);
  });
}

oob_status_t Manager::mcaErrThresholdEnable() {
  oob_status_t ret = OOB_NOT_SUPPORTED;
  struct run_time_threshold th;

  memset(&th, 0, sizeof(th));

  amd::ras::config::Manager::AttributeValue mcaThreshold =
      configMgr.getAttribute("McaThresholdEn");

  bool *mcaThresholdEn = std::get_if<bool>(&mcaThreshold);

  if (*mcaThresholdEn == true) {
    th.err_type = 0; /*00 = MCA error type*/

    amd::ras::config::Manager::AttributeValue mcaErrThresholdCount =
        configMgr.getAttribute("McaErrThresholdCnt");

    int64_t *mcaErrThresholdCnt = std::get_if<int64_t>(&mcaErrThresholdCount);

    th.err_count_th = *mcaErrThresholdCnt;
    th.max_intrupt_rate = 1;

    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));

    getOobRegisters(&oob_config);

    /* Core MCA Error Reporting Enable */
    oob_config.core_mca_err_reporting_en = 1;
    oob_config.mca_oob_misc0_ec_enable = 1;

    ret = bmcRasOobConfig(oob_config);

    if (ret == OOB_SUCCESS) {
      lg2::info("Setting MCA error threshold");
      ret = rasErrThresholdSet(th);
    }
  }

  amd::ras::config::Manager::AttributeValue dramCeccThreshold =
      configMgr.getAttribute("DramCeccThresholdEn");
  bool *dramCeccThresholdEn = std::get_if<bool>(&dramCeccThreshold);

  if (*dramCeccThresholdEn == true) {
    th.err_type = 1; /*01 = DRAM CECC error type*/

    amd::ras::config::Manager::AttributeValue dramCeccErrThresholdCount =
        configMgr.getAttribute("DramCeccErrThresholdCnt");
    int64_t *dramCeccThresholdCnt =
        std::get_if<int64_t>(&dramCeccErrThresholdCount);

    th.err_count_th = *dramCeccThresholdCnt;
    th.max_intrupt_rate = 1;

    struct oob_config_d_in oob_config;

    memset(&oob_config, 0, sizeof(oob_config));

    getOobRegisters(&oob_config);

    oob_config.dram_cecc_oob_ec_mode = 1;
    oob_config.mca_oob_misc0_ec_enable = 1;

    ret = bmcRasOobConfig(oob_config);

    if (ret == OOB_SUCCESS) {
      lg2::info("Setting Dram Cecc Error threshold");
      ret = rasErrThresholdSet(th);
    }
  }
  return ret;
}

oob_status_t Manager::rasErrThresholdSet(struct run_time_threshold th) {
  oob_status_t ret;

  for (int i = 0; i < cpuCount; i++) {
    amd::ras::config::Manager::AttributeValue apmlRetry =
        configMgr.getAttribute("ApmlRetries");
    int64_t *retryCount = std::get_if<int64_t>(&apmlRetry);

    while (*retryCount > 0) {
      --(*retryCount);
      ret = set_bmc_ras_err_threshold(i, th);

      if (ret != OOB_SUCCESS) {
        lg2::error("Failed to set error threshold for processor P0");
      } else {
        break;
      }

      sleep(1);
    }
  }
  return ret;
}

oob_status_t Manager::setPcieOobConfig() {
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  amd::ras::config::Manager::AttributeValue PcieAerPolling =
      configMgr.getAttribute("PcieAerPollingEn");
  bool *PcieAerPollingEn = std::get_if<bool>(&PcieAerPolling);

  if (*PcieAerPollingEn == true) {
    ret = setPcieOobRegisters();
  }
  return ret;
}

oob_status_t Manager::getOobRegisters(struct oob_config_d_in *oob_config) {
  lg2::info("getOobRegisters");
  oob_status_t ret;
  uint32_t d_out = 0;

  ret = get_bmc_ras_oob_config(0, &d_out);

  if (ret) {
    sd_journal_print(LOG_INFO, "Failed to get ras oob configuration \n");
  } else {
    oob_config->core_mca_err_reporting_en = (d_out >> MCA_ERR_REPORT_EN & 1);
    oob_config->dram_cecc_oob_ec_mode =
        (d_out >> DRAM_CECC_OOB_EC_MODE & TRIBBLE_BITS);
    oob_config->pcie_err_reporting_en = (d_out >> PCIE_ERR_REPORT_EN & 1);
    oob_config->mca_oob_misc0_ec_enable = (d_out & 1);
  }
  return ret;
}

oob_status_t Manager::setPcieOobRegisters() {
  oob_status_t ret;
  struct oob_config_d_in oob_config;

  memset(&oob_config, 0, sizeof(oob_config));

  getOobRegisters(&oob_config);

  /* PCIe OOB Error Reporting Enable */
  oob_config.pcie_err_reporting_en = 1;

  ret = bmcRasOobConfig(oob_config);

  return ret;
}

oob_status_t Manager::pcieErrThresholdEnable() {
  oob_status_t ret = OOB_NOT_SUPPORTED;
  struct run_time_threshold th;

  memset(&th, 0, sizeof(th));

  amd::ras::config::Manager::AttributeValue pcieAerThreshold =
      configMgr.getAttribute("PcieAerThresholdEn");
  bool *pcieAerThresholdEn = std::get_if<bool>(&pcieAerThreshold);

  if (*pcieAerThresholdEn) {
    setPcieOobRegisters();

    th.err_type = 2; /*00 = PCIE error type*/

    amd::ras::config::Manager::AttributeValue pcieAerErrThresholdCount =
        configMgr.getAttribute("PcieAerErrThresholdCnt");
    int64_t *pcieAerErrThresholdCnt =
        std::get_if<int64_t>(&pcieAerErrThresholdCount);

    th.err_count_th = *pcieAerErrThresholdCnt;
    th.max_intrupt_rate = 1;

    lg2::info("Setting PCIE error threshold");

    ret = rasErrThresholdSet(th);
  }
  return ret;
}

void Manager::runTimeErrorPolling() {
  oob_status_t ret;

  lg2::info("Setting MCA and DRAM OOB Config");

  ret = setMcaOobConfig();

  /*setMcaOobConfig is not supported for Genoa platform.
    Enable run time error polling only if SetMcaOobConfig command
    is supported for the platform*/
  if (ret != OOB_MAILBOX_CMD_UNKNOWN) {
    lg2::info("Setting PCIE OOB Config");

    setPcieOobConfig();

    lg2::info("Starting seprate threads to perform runtime error polling as "
              "per user settings");

    amd::ras::config::Manager::AttributeValue mcaPolling =
        configMgr.getAttribute("McaPollingPeriod");
    int64_t *mcaPollingPeriod = std::get_if<int64_t>(&mcaPolling);

    amd::ras::config::Manager::AttributeValue dramCeccPolling =
        configMgr.getAttribute("DramCeccPollingPeriod");
    int64_t *dramCeccPollingPeriod = std::get_if<int64_t>(&dramCeccPolling);

    amd::ras::config::Manager::AttributeValue pcieAerPolling =
        configMgr.getAttribute("PcieAerPollingPeriod");
    int64_t *pcieAerPollingPeriod = std::get_if<int64_t>(&pcieAerPolling);

    mcaErrorPollingHandler(mcaPollingPeriod);

    dramCeccErrorPollingHandler(dramCeccPollingPeriod);

    pcieAerErrorPollingHandler(pcieAerPollingPeriod);
  } else {
    lg2::error("Runtime error polling is not supported for this platform");
    return;
  }

  ret = mcaErrThresholdEnable();

  if (ret == OOB_MAILBOX_CMD_UNKNOWN) {
    lg2::error("Runtime error threshold is not supported for this platform");
  } else {
    pcieErrThresholdEnable();
  }
}

template <typename T>
void Manager::dumpProcErrorSection(const std::shared_ptr<T> &data,
                                   uint8_t soc_num,
                                   struct ras_rt_valid_err_inst inst,
                                   uint8_t category, uint16_t Section,
                                   uint32_t *Severity, uint64_t *CheckInfo) {
  uint16_t n = 0;
  struct run_time_err_d_in d_in;
  uint32_t d_out = 0;
  uint64_t mca_status_register = 0;
  uint32_t root_err_status = 0;
  uint32_t offset, baseOffset = 0;
  oob_status_t ret;

  uint32_t mcaPspSynd1Lo = 0;
  uint32_t mcaPspSynd1Hi = 0;
  uint32_t mcaPspSynd2Lo = 0;
  uint32_t mcaPspSynd2Hi = 0;

  amd::ras::config::Manager::AttributeValue apmlRetry =
      configMgr.getAttribute("ApmlRetries");
  int64_t *apmlRetryCount = std::get_if<int64_t>(&apmlRetry);

  lg2::info("Harvesting errors for category {CATEGORY}", "CATEGORY", category);

  std::shared_ptr<McaRuntimeCperRecord> ProcPtr;
  std::shared_ptr<PcieRuntimeCperRecord> PciePtr;

  if constexpr (std::is_same_v<T, McaRuntimeCperRecord>) {
    ProcPtr = std::static_pointer_cast<McaRuntimeCperRecord>(data);
  } else if constexpr (std::is_same_v<T, PcieRuntimeCperRecord>) {
    PciePtr = std::static_pointer_cast<PcieRuntimeCperRecord>(data);
  } else {
    return;
  }

  while (n < inst.number_of_inst) {
    if (category == 1) // For Dram Cecc error , the dump started from offset 4
    {
      baseOffset = 4;
    } else {
      baseOffset = 0;
    }

    int DumpIndex = 0;

    for (offset = baseOffset; offset < inst.number_bytes; offset = offset + 4) {
      memset(&d_in, 0, sizeof(d_in));
      memset(&d_out, 0, sizeof(d_out));
      d_in.offset = offset;
      d_in.category = category;
      d_in.valid_inst_index = n;

      ret = get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

      if (ret != OOB_SUCCESS) {
        // retry
        while (*apmlRetryCount > 0) {
          memset(&d_in, 0, sizeof(d_in));
          memset(&d_out, 0, sizeof(d_out));
          d_in.offset = offset;
          d_in.category = category;
          d_in.valid_inst_index = n;

          ret = get_bmc_ras_run_time_error_info(soc_num, d_in, &d_out);

          if (ret == OOB_SUCCESS) {
            break;
          }
          (*apmlRetryCount)--;
          usleep(1000 * 1000);
        }
      }
      if (ret != OOB_SUCCESS) {
        lg2::error(
            "Socket {SOCKET} : Failed to get runtime error info for instance.",
            "SOCKET", soc_num);
        if (ProcPtr) {
          ProcPtr->McaErrorInfo[Section].DumpData[DumpIndex] = BAD_DATA;
        } else if (PciePtr) {
          PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 0] =
              (BAD_DATA >> 24) & 0xFF;
          PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 1] =
              (BAD_DATA >> 16) & 0xFF;
          PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 2] =
              (BAD_DATA >> 8) & 0xFF;
          PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 3] =
              BAD_DATA & 0xFF;
        }
        continue;
      }
      if (ProcPtr) {
        ProcPtr->McaErrorInfo[Section].DumpData[DumpIndex] = d_out;

        if (d_in.offset == 8) {
          mca_status_register = mca_status_register | ((uint64_t)d_out);
        } else if (d_in.offset == 12) {
          mca_status_register = ((uint64_t)d_out << 32) | mca_status_register;
        }

        if (d_in.offset == 80 + baseOffset) {
          mcaPspSynd1Lo = d_out;
        } else if (d_in.offset == 84 + baseOffset) {
          mcaPspSynd1Hi = d_out;
        } else if (d_in.offset == 88 + baseOffset) {
          mcaPspSynd2Lo = d_out;
        } else if (d_in.offset == 92 + baseOffset) {
          mcaPspSynd2Hi = d_out;
        }
      } else if (PciePtr) {
        PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 0] =
            (d_out >> 24) & 0xFF;
        PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 1] =
            (d_out >> 16) & 0xFF;
        PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 2] =
            (d_out >> 8) & 0xFF;
        PciePtr->PcieErrorData[Section].AerInfo.PcieAer[DumpIndex * 4 + 3] =
            d_out & 0xFF;

        if (d_in.offset == 52) {
          root_err_status = d_out;
        }
      }
      DumpIndex++;

    } // for loop

    if ((category == 0) || (category == 1)) {

      memcpy(ProcPtr->SectionDescriptor[soc_num].FruString, &mcaPspSynd2Hi, 4);
      memcpy(ProcPtr->SectionDescriptor[soc_num].FruString + 4, &mcaPspSynd2Lo,
             4);
      memcpy(ProcPtr->SectionDescriptor[soc_num].FruString + 8, &mcaPspSynd1Hi,
             4);
      memcpy(ProcPtr->SectionDescriptor[soc_num].FruString + 12, &mcaPspSynd1Lo,
             4);

      ProcPtr->SectionDescriptor[soc_num].FruString[16] = '\0';

      CheckInfo[Section] = 0;
      CheckInfo[Section] |= ((mca_status_register >> 57) & 1ULL) << 19;
      CheckInfo[Section] |= ((mca_status_register >> 61) & 1ULL) << 20;
      CheckInfo[Section] |= ((mca_status_register >> 62) & 1ULL) << 23;
      CheckInfo[Section] |= (5ULL << 16);

      if (((mca_status_register & (1ULL << 61)) == 0) &&
          ((mca_status_register & (1ULL << 44)) == 0)) {
        Severity[Section] = 2; // Non fatal corrected
      } else if ((((mca_status_register & (1ULL << 61)) == 0) &&
                  ((mca_status_register & (1ULL << 44)) != 0)) ||
                 (((mca_status_register & (1ULL << 61)) != 0) &&
                  ((mca_status_register & (1ULL << 57)) == 0))) {
        Severity[Section] = 0; // Non datal uncorrected
      }
    } else if (category == 2) // PCIE error
    {
      if (root_err_status & (1 << 6)) {
        Severity[Section] = 1; // Fatal error
      } else if (root_err_status & (1 << 5)) {
        Severity[Section] = 0; // Non datal uncorrected
      } else if (root_err_status & 1) {
        Severity[Section] = 2; // Non fatal corrected
      }
    }
    n++;
    Section++;
  }
}

void Manager::harvestDramCeccErrorCounters(struct ras_rt_valid_err_inst inst,
                                           uint8_t socNum) {
  uint32_t d_out = 0;
  struct run_time_err_d_in d_in;
  oob_status_t ret = OOB_MAILBOX_CMD_UNKNOWN;

  amd::ras::config::Manager::AttributeValue apmlRetry =
      configMgr.getAttribute("ApmlRetries");
  int64_t *retryCount = std::get_if<int64_t>(&apmlRetry);

  if (inst.number_of_inst != 0) {
    uint16_t n = 0;
    while (n < inst.number_of_inst) {
      memset(&d_in, 0, sizeof(d_in));
      memset(&d_out, 0, sizeof(d_out));
      d_in.valid_inst_index = n;
      d_in.offset = 0;
      d_in.category = DRAM_CECC_ERR;

      ret = get_bmc_ras_run_time_error_info(socNum, d_in, &d_out);

      if (ret != OOB_SUCCESS) {
        // retry
        while (*retryCount > 0) {
          memset(&d_in, 0, sizeof(d_in));
          memset(&d_out, 0, sizeof(d_out));
          d_in.offset = 0;
          d_in.category = DRAM_CECC_ERR;
          d_in.valid_inst_index = n;

          ret = get_bmc_ras_run_time_error_info(socNum, d_in, &d_out);
          if (ret == OOB_SUCCESS) {
            break;
          }
          (*retryCount)--;
          usleep(1000 * 1000);
        }
      }
      n++;
    }

    if (ret == OOB_SUCCESS) {
      uint16_t error_count;
      uint8_t ch_num;
      uint8_t chip_sel_num;

      error_count = d_out & 0xFFFF;

      ch_num = (d_out >> 16) & 0xF;

      std::map<int, char> dimmPairSequence = {
          {0, 'C'}, {1, 'E'}, {2, 'F'}, {3, 'A'}, {4, 'B'},  {5, 'D'},
          {6, 'I'}, {7, 'K'}, {8, 'L'}, {9, 'G'}, {10, 'H'}, {11, 'J'}};

      char Channel = '\0';
      auto it = dimmPairSequence.find(ch_num);

      if (it != dimmPairSequence.end()) {
        Channel = it->second;
      }

      std::string soc_num_str = std::to_string(socNum);
      std::string DimmLabel = "P" + soc_num_str + "_DIMM_" + Channel;

      chip_sel_num = (d_out >> CHIP_SEL_NUM_POS) & 3;

      uint8_t DimmNumber = chip_sel_num >> 1;

      if (DimmNumber) {
        DimmLabel = DimmLabel + std::to_string(DimmNumber);
      }
      lg2::info("Dimm = {DIMM}", "DIMM", DimmLabel);
      lg2::info("Error count = {COUNT}", "COUNT", error_count);
    }
  }
}

} // namespace apml
} // namespace ras
