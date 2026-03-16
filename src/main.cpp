#include "config_manager.hpp"
#ifdef APML
#include "apml_manager.hpp"
#endif
#include "base_manager.hpp"

#include <boost/asio.hpp>
#include <phosphor-logging/lg2.hpp>

int main(int argc, char* argv[])
{
    std::string node;

    if (argc != 2)
    {
        lg2::error("Invalid argument: Node is invalid");
    }

    node = argv[1];

    lg2::info("Start amd ras service for host : {NODE}", "NODE", node);

    // Setup ASIO I/O context for timers and GPIO events
    boost::asio::io_context io;

    amd::ras::config::Manager manager(node);

#ifdef APML
    amd::ras::Manager* errorMgr =
        new amd::ras::apml::Manager(manager, io, node);

    errorMgr->init();

    errorMgr->configure();
#endif

#ifdef PLDM
    // Log an error message if PLDM capabilities are not enabled
    lg2::error("TODO: PLDM RAS capabilities are yet to be enabled");
#endif

    io.run();

    return 0;
}
