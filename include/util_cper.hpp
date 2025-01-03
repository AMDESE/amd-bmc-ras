#pragma once

#include "error_monitor.hpp"

#include <memory>

static const std::string runtimeMcaErr = "RUNTIME_MCA_ERROR";
static const std::string runtimePcieErr = "RUNTIME_PCIE_ERROR";
static const std::string runtimeDramErr = "RUNTIME_DRAM_ERROR";
static const std::string fatalErr = "FATAL";

namespace ras {
namespace cper {
namespace util {

template <typename T> void calculateTimeStamp(const std::shared_ptr<T> &);

template <typename T>
void dumpHeaderSection(const std::shared_ptr<T> &, uint16_t, uint32_t,
                       const std::string &, unsigned int, uint64_t &);
template <typename T>
void dumpErrorDescriptorSection(const std::shared_ptr<T> &, uint16_t,
                                const std::string &, uint32_t *, uint8_t,
                                uint32_t);

void dumpProcessorErrorSection(const std::shared_ptr<FatalCperRecord> &,
                               uint8_t, const std::unique_ptr<CpuId[]> &,
                               uint8_t);

void dumpContextInfo(const std::shared_ptr<FatalCperRecord> &, uint16_t,
                     uint16_t, uint8_t, const std::unique_ptr<uint64_t[]> &,
                     const std::unique_ptr<uint32_t[]> &, uint8_t);

void dumpProcErrorInfoSection(const std::shared_ptr<McaRuntimeCperRecord> &,
                              uint16_t, uint64_t *, uint32_t, uint8_t,
                              const std::unique_ptr<CpuId[]> &);

void dumpPcieErrorInfoSection(const std::shared_ptr<PcieRuntimeCperRecord> &,
                              uint16_t, uint16_t);

template <typename T>
void createCperFile(const std::shared_ptr<T> &, const std::string &, uint16_t,
                    int &);
} // namespace util

} // namespace cper

} // namespace ras
