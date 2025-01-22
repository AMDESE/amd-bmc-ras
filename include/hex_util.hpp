#pragma once
#include <stdint.h>

#include <algorithm>
#include <iomanip>
#include <string>
#include <vector>

namespace amd
{
namespace ras
{
namespace hex
{
namespace util
{
std::vector<uint32_t> stringToVector(const std::string& hexString);

bool compareBitwiseAnd(const uint32_t* Var, const std::string& hexString);

} // namespace util
} // namespace hex
} // namespace ras
} // namespace amd
