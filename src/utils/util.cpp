#ifdef APML
#include "apml_manager.hpp"
#endif
#include "oem_cper.hpp"
#include "util.hpp"

#include <filesystem>

namespace amd
{
namespace ras
{
namespace util
{
namespace fs = std::filesystem;

void createFile(const std::string& directoryName, const std::string& fileName)
{
    // Create the directory if it doesn't exist
    if (!fs::exists(directoryName))
    {
        try
        {
            fs::create_directories(
                directoryName); // Create directory recursively if needed
        }
        catch (const fs::filesystem_error& e)
        {
            throw std::runtime_error(
                "Failed to create directory: " + std::string(e.what()));
        }
    }

    // Create or read the index file
    if (!fs::exists(fileName))
    {
        try
        {
            std::ofstream file(fileName);
            if (file.is_open())
            {
                file << "0"; // Initialize the file with "0"
                file.close();
            }
            else
            {
                throw std::runtime_error("Failed to create index file");
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error("Exception while creating index file: " +
                                     std::string(e.what()));
        }
    }
}

} // namespace util
} // namespace ras
} // namespace amd
