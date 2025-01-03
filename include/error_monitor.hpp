/*
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http:www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#pragma once

#include "config_manager.hpp"
#include "crashdump_manager.hpp"
#include "oem_cper.hpp"

#include <boost/asio/io_context.hpp>

namespace ras {
struct CpuId {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

class Manager {
public:
  Manager() = delete;
  ~Manager() = default;
  Manager(const Manager &) = delete;
  Manager(Manager &&) = delete;
  Manager &operator=(Manager &&) = delete;
  Manager(amd::ras::config::Manager &);

  unsigned int boardId;
  uint8_t cpuCount;
  std::unique_ptr<CpuId[]> cpuId;
  int errCount = 0;
  uint32_t familyId;
  std::unique_ptr<std::string[]> inventoryPath;
  std::unique_ptr<uint32_t[]> uCode;
  std::unique_ptr<uint64_t[]> ppin;
  amd::ras::config::Manager &configMgr;
  std::shared_ptr<FatalCperRecord> rcd = NULL;
  std::shared_ptr<McaRuntimeCperRecord> mcaPtr = nullptr;
  std::shared_ptr<McaRuntimeCperRecord> dramPtr = nullptr;
  std::shared_ptr<PcieRuntimeCperRecord> pciePtr = nullptr;
  std::map<int, std::unique_ptr<CrashdumpInterface>> managers;

  /**
   * @brief Perform initial initilization for the error monitoring.
   *
   * This is a pure virtual function, intended to be implemented by derived
   * classes to perform any necessary initialization specific to the subclass.
   */
  virtual void init() = 0;
  virtual void configure() = 0;

  /**
   * @brief Exports crash dump information to DBus.
   *
   * @param[in] num error number index.
   * @param[in] timestamp The timestamp when the error occurred.
   * @param[in] objectServer A reference to the DBus object server to
   * interface with DBus.
   * @param[in] dbusConnection A shared pointer to the DBus connection to be
   * used.
   */
  void exportCrashdumpToDBus(int, const EFI_ERROR_TIME_STAMP &,
                             sdbusplus::asio::object_server &,
                             std::shared_ptr<sdbusplus::asio::connection> &);

  void createDbusInterface(sdbusplus::asio::object_server &,
                           std::shared_ptr<sdbusplus::asio::connection> &);

private:
  void getSocketInfo();
  void createIndexFile();
};

} // namespace ras
