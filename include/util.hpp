#pragma once

#include "oem_cper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/server.hpp>

#include <fstream>
#include <regex>

namespace ras {
namespace util {
template <typename T>
T getProperty(sdbusplus::bus::bus &, const char *, const char *, const char *,
              const char *);

void createFile(const std::string &, const std::string &);

bool compareBitwiseAnd(const uint32_t *, const std::string &);

std::vector<uint32_t> hexstringToVector(const std::string &);

bool checkSignatureIdMatch(std::map<std::string, std::string> *,
                           const std::shared_ptr<FatalCperRecord> &);

void rasRecoveryAction(uint8_t, const std::string *, const std::string *);

bool calculateErrorSeverity(uint32_t *, uint16_t, uint32_t *,
                            const std::string &);

bool checkDbusPath(std::string);

std::string findCperFilename(int);

} // namespace util

} // namespace ras
