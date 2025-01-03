#ifdef APML
#include "apml_manager.hpp"
#endif
#include "util.hpp"
#include "util_cper.hpp"

#include <sdbusplus/asio/object_server.hpp>

#include <filesystem>

namespace ras {
namespace util {
namespace fs = std::filesystem;

constexpr int SEV_NON_FATAL_UNCORRECTED = 0;
constexpr int SEV_NON_FATAL_CORRECTED = 2;
static const std::string MAPPER_BUSNAME = "xyz.openbmc_project.ObjectMapper";
static const std::string MAPPER_PATH = "/xyz/openbmc_project/object_mapper";
static const std::string MAPPER_INTERFACE = "xyz.openbmc_project.ObjectMapper";

template <typename T>
T getProperty(sdbusplus::bus::bus &bus, const char *service, const char *path,
              const char *interface, const char *propertyName) {
  auto method = bus.new_method_call(service, path,
                                    "org.freedesktop.DBus.Properties", "Get");
  method.append(interface, propertyName);
  std::variant<T> value{};
  try {
    auto reply = bus.call(method);
    reply.read(value);
  } catch (const sdbusplus::exception::SdBusError &ex) {
    lg2::info("GetProperty call failed");
  }
  return std::get<T>(value);
}

void createFile(const std::string &directoryName, const std::string &fileName) {
  // Create the directory if it doesn't exist
  if (!fs::exists(directoryName)) {
    try {
      fs::create_directories(
          directoryName); // Create directory recursively if needed
    } catch (const fs::filesystem_error &e) {
      throw std::runtime_error("Failed to create directory: " +
                               std::string(e.what()));
    }
  }

  // Create or read the index file
  if (!fs::exists(fileName)) {
    try {
      std::ofstream file(fileName);
      if (file.is_open()) {
        file << "0"; // Initialize the file with "0"
        file.close();
      } else {
        throw std::runtime_error("Failed to create index file");
      }
    } catch (const std::exception &e) {
      throw std::runtime_error("Exception while creating index file: " +
                               std::string(e.what()));
    }
  }
}

void requestHostTransition(std::string command) {
  boost::system::error_code ec;
  boost::asio::io_context io;
  auto conn = std::make_shared<sdbusplus::asio::connection>(io);

  conn->async_method_call(
      [](boost::system::error_code ec) {
        if (ec) {
          lg2::error("Failed to trigger cold reset of the system\n");
        }
      },
      "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
      "org.freedesktop.DBus.Properties", "Set",
      "xyz.openbmc_project.State.Host", "RequestedHostTransition",
      std::variant<std::string>{command});
}

void triggerRsmrstReset() {
  boost::system::error_code ec;
  boost::asio::io_context io_conn;
  auto conn = std::make_shared<sdbusplus::asio::connection>(io_conn);

  conn->async_method_call(
      [](boost::system::error_code ec) {
        if (ec) {
          lg2::error("Failed to trigger cold reset of the system\n");
        }
      },
      "xyz.openbmc_project.State.Host",
      "/xyz/openbmc_project/control/host0/SOCReset",
      "xyz.openbmc_project.Control.Host.SOCReset", "SOCReset");

  sleep(1);
  sdbusplus::bus::bus bus = sdbusplus::bus::new_default();
  std::string CurrentHostState = getProperty<std::string>(
      bus, "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
      "xyz.openbmc_project.State.Host", "CurrentHostState");

  if (CurrentHostState.compare(
          "xyz.openbmc_project.State.Host.HostState.Off") == 0) {
    std::string command = "xyz.openbmc_project.State.Host.Transition.On";
    requestHostTransition(command);
  }
}

void triggerSysReset() {
  std::string command = "xyz.openbmc_project.State.Host.Transition.Reboot";

  requestHostTransition(command);
}

void triggerColdReset(const std::string *resetSignal) {
  if (*resetSignal == "RSMRST") {
    lg2::info("RSMRST reset triggered");
    triggerRsmrstReset();
  } else if (*resetSignal == "SYS_RST") {
    lg2::info("SYS_RST signal triggered");
    triggerSysReset();
  }
}

void triggerWarmReset() {
  oob_status_t ret;
  uint32_t ack_resp = 0;
  /* In a 2P config, it is recommended to only send this command to P0
  Hence, sending the Signal only to socket 0*/

#ifdef APML
  ret = reset_on_sync_flood(0, &ack_resp);

  if (ret) {
    lg2::error("Failed to request reset after sync flood");
  } else {
    lg2::info("Warm reset triggered");
  }
#endif
}

void rasRecoveryAction(uint8_t buf, const std::string *systemRecovery,
                       const std::string *resetSignal) {
  if (*systemRecovery == "WARM_RESET") {
    if ((buf & 0x4)) // SYS_MGMT_CTRL_ERR
    {
      triggerColdReset(resetSignal);
    } else {
      triggerWarmReset();
    }
  } else if (*systemRecovery == "COLD_RESET") {
    triggerColdReset(resetSignal);
  } else if (*systemRecovery == "NO_RESET") {
    lg2::info("NO RESET triggered");
  } else {
    lg2::error("CdumpResetPolicy is not valid");
  }
}

std::vector<uint32_t> hexstringToVector(const std::string &hexString) {
  std::vector<uint32_t> result;

  // Skip the "0x" prefix if present
  size_t start = (hexString.substr(0, 2) == "0x") ? 2 : 0;

  // Process the string in chunks of 8 characters (32 bits)
  for (size_t i = start; i < hexString.length(); i += 8) {
    std::string chunk = hexString.substr(i, 8);
    std::istringstream iss(chunk);
    uint32_t value = 0;
    iss >> std::hex >> value;
    if (iss) {
      result.push_back(value);
    } else {
      break;
    }
  }

  // Pad the result vector with leading zeros if necessary
  while (result.size() < 8) {
    result.insert(result.begin(), 0);
  }

  return result;
}

bool compareBitwiseAnd(const uint32_t *Var, const std::string &hexString) {
  std::vector<uint32_t> hexVector = hexstringToVector(hexString);
  std::vector<uint32_t> result(8);

  // Pad the Var array with leading zeros if necessary
  std::vector<uint32_t> varVector(8);

  std::copy(Var, Var + 8, varVector.begin());

  // Reverse the order of elements in varVector
  std::reverse(varVector.begin(), varVector.end());

  // Perform the bitwise AND operation
  for (size_t i = 0; i < 8; i++) {
    result[i] = varVector[i] & hexVector[i];
  }

  // Compare the result with the original hexVector
  return std::equal(result.begin(), result.end(), hexVector.begin(),
                    hexVector.end());
}

bool checkSignatureIdMatch(std::map<std::string, std::string> *configSigIdList,
                           const std::shared_ptr<FatalCperRecord> &rcd) {
  bool ret = false;
  int socNum = 0;
  uint32_t tempVar[2][8];

  for (socNum = 0; socNum < 2; socNum++) {
    std::memcpy(tempVar[socNum], rcd->ErrorRecord[socNum].SignatureID,
                sizeof(tempVar[socNum]));
  }

  for (socNum = 0; socNum < 2; socNum++) {
    bool equal = false;
    for (const auto &pair : *configSigIdList) {
      bool equal = compareBitwiseAnd(tempVar[socNum], pair.second);

      if (equal == true) {
        lg2::info(
            "Signature ID matched with the config ile signature ID list\n");
        ret = true;
        break;
      }
    }
    if (equal == true) {
      break;
    }
  }
  return ret;
}

/*The function returns the highest severity out of all Section Severity for CPER
  header Severity Order = Fatal > non-fatal uncorrected > corrected*/
bool calculateErrorSeverity(uint32_t *severity, uint16_t sectionCount,
                            uint32_t *highestSeverity,
                            const std::string &errorType) {
  bool rc = true;

  *highestSeverity = SEV_NON_FATAL_CORRECTED;

  for (int i = 0; i < sectionCount; i++) {
    if (severity[i] == 1) // Fatal Severity
    {
      if (errorType == runtimePcieErr) {
        *highestSeverity = 1;
        break;
      } else {
        lg2::error("Error Severity is fatal. This must be captured "
                   "in Crashdump CPER, not runtime CPER");
        rc = false;
      }
    } else if (severity[i] == SEV_NON_FATAL_UNCORRECTED) {
      *highestSeverity = SEV_NON_FATAL_UNCORRECTED;
      break;
    }
  }
  return rc;
}

bool checkDbusPath(std::string dbusPath) {
  bool FilePathExist = false;

  boost::asio::io_context Dbus;
  auto dbusconn = std::make_shared<sdbusplus::asio::connection>(Dbus);
  std::vector<std::string> crashDumpPaths;

  auto mesg =
      dbusconn->new_method_call(MAPPER_BUSNAME.data(), MAPPER_PATH.data(),
                                MAPPER_INTERFACE.data(), "GetSubTreePaths");

  static const std::vector<std::string> interfaces = {"com.amd.crashdump"};
  mesg.append("/", 0, interfaces);

  try {
    auto mapperReply = dbusconn->call(mesg);
    mapperReply.read(crashDumpPaths);
  } catch (sdbusplus::exception_t &e) {
    lg2::info("Failed to get D-BUS info {WHAT}", "WHAT", e.what());
  }

  for (const auto &objPath : crashDumpPaths) {
    if (dbusPath == objPath)
      FilePathExist = true;
  }

  return FilePathExist;
}

std::string findCperFilename(int number) {
  std::regex pattern(".*" + std::to_string(number) + "\\.cper");

  for (const auto &entry : std::filesystem::directory_iterator(RAS_DIR)) {
    std::string filename = entry.path().filename().string();
    if (std::regex_match(filename, pattern)) {
      return filename;
    }
  }

  return "";
}

} // namespace util
} // namespace ras
