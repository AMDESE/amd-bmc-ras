#include "hex_util.hpp"

namespace amd
{
namespace ras
{
namespace hex
{
namespace util
{

std::vector<uint32_t> stringToVector(const std::string& hexString)
{
    std::vector<uint32_t> result;

    // Skip the "0x" prefix if present
    size_t start = (hexString.substr(0, 2) == "0x") ? 2 : 0;

    // Process the string in chunks of 8 characters (32 bits)
    for (size_t i = start; i < hexString.length(); i += 8)

    {
        std::string chunk = hexString.substr(i, 8);
        std::istringstream iss(chunk);
        uint32_t value = 0;
        iss >> std::hex >> value;
        if (iss)
        {
            result.push_back(value);
        }
        else
        {
            break;
        }
    }

    // Pad the result vector with leading zeros if necessary
    while (result.size() < 8)
    {
        result.insert(result.begin(), 0);
    }

    return result;
}

bool compareBitwiseAnd(const uint32_t* Var, const std::string& hexString)
{
    std::vector<uint32_t> hexVector = stringToVector(hexString);
    std::vector<uint32_t> result(8);

    // Pad the Var array with leading zeros if necessary
    std::vector<uint32_t> varVector(8);

    std::copy(Var, Var + 8, varVector.begin());

    // Reverse the order of elements in varVector
    std::reverse(varVector.begin(), varVector.end());

    // Perform the bitwise AND operation
    for (size_t i = 0; i < 8; i++)
    {
        result[i] = varVector[i] & hexVector[i];
    }

    // Compare the result with the original hexVector
    return std::equal(result.begin(), result.end(), hexVector.begin(),
                      hexVector.end());
}

} // namespace util
} // namespace hex
} // namespace ras
} // namespace amd
