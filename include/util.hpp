#pragma once

#include "oem_cper.hpp"

#include <fstream>
#include <regex>

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
 *  @param[in] directoryName - Name of the directory to create or use.
 *  @param[in] fileName - Name of the file to create.
 *
 *  @return Throws a std::runtime_error on failure to create
 *  the directory or file.
 */
void createFile(const std::string&, const std::string&);

} // namespace util
} // namespace ras
} // namespace amd
