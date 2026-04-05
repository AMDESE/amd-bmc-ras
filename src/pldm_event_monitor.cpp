#include "pldm_event_monitor.hpp"

#include <boost/asio/post.hpp>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message.hpp>

#include <cstdint>
#include <cstring>
#include <systemd/sd-bus.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>

#ifndef PLDM_EVENT_DBUS_MATCH
#ifndef PLDM_EVENT_INTERFACE
#define PLDM_EVENT_INTERFACE "xyz.openbmc_project.PLDM.Event"
#endif
#ifndef PLDM_EVENT_MEMBER
#define PLDM_EVENT_MEMBER "PldmMessagePollEvent"
#endif
#define PLDM_EVENT_DBUS_MATCH                                                  \
    "type='signal',interface='" PLDM_EVENT_INTERFACE "',member='" PLDM_EVENT_MEMBER "'"
#endif

#ifndef PLDM_EVENT_MESSAGE_SIGNATURE
#define PLDM_EVENT_MESSAGE_SIGNATURE "tysyyquqh"
#endif

#ifndef PLDM_EVENT_MAX_PAYLOAD
#define PLDM_EVENT_MAX_PAYLOAD (64U * 1024U * 1024U)
#endif

namespace amd
{
namespace ras
{
namespace
{

/** Copy payload from fd (memfd/regular file); cap size at maxPayload bytes. */
bool readEventPayload(int fd, size_t maxPayload, std::vector<uint8_t>& out)
{
    struct stat st
    {};
    if (::fstat(fd, &st) < 0)
    {
        lg2::error("PLDM event: fstat failed: {ERR}", "ERR", strerror(errno));
        return false;
    }

    if (!S_ISREG(st.st_mode))
    {
        std::vector<uint8_t> buf;
        buf.reserve(std::min(maxPayload, static_cast<size_t>(65536)));
        uint8_t chunk[8192];
        while (buf.size() < maxPayload)
        {
            const size_t space = maxPayload - buf.size();
            const size_t toRead = std::min(sizeof(chunk), space);
            const ssize_t n = ::read(fd, chunk, toRead);
            if (n > 0)
            {
                buf.insert(buf.end(), chunk, chunk + static_cast<size_t>(n));
            }
            else if (n == 0)
            {
                break;
            }
            else
            {
                if (errno == EINTR)
                {
                    continue;
                }
                lg2::error("PLDM event: read failed: {ERR}", "ERR",
                           strerror(errno));
                return false;
            }
        }
        out = std::move(buf);
        return true;
    }

    const auto fileSize = static_cast<size_t>(st.st_size);
    size_t copyLen = std::min(fileSize, maxPayload);
    if (fileSize > maxPayload)
    {
        lg2::warning(
            "PLDM event: payload {FSIZE} bytes exceeds cap {CAP}; copying first {CAP} bytes only",
            "FSIZE", fileSize, "CAP", maxPayload);
    }

    out.resize(copyLen);
    if (copyLen == 0)
    {
        return true;
    }

    void* p = ::mmap(nullptr, copyLen, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p != MAP_FAILED)
    {
        std::memcpy(out.data(), p, copyLen);
        ::munmap(p, copyLen);
        return true;
    }

    lg2::warning("PLDM event: mmap failed ({ERR}); using read", "ERR",
                 strerror(errno));
    if (::lseek(fd, 0, SEEK_SET) < 0)
    {
        return false;
    }
    size_t off = 0;
    while (off < copyLen)
    {
        const ssize_t n = ::read(fd, out.data() + off, copyLen - off);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
        }
        else if (n == 0)
        {
            out.resize(off);
            return true;
        }
        else if (errno != EINTR)
        {
            lg2::error("PLDM event: read fallback failed: {ERR}", "ERR",
                       strerror(errno));
            return false;
        }
    }
    return true;
}

} // namespace

PldmEventMonitor::PldmEventMonitor(boost::asio::io_context& io,
                                   sdbusplus::bus::bus& systemBus,
                                   OnEventBuffer onBuffer) :
    io_(io), onBuffer_(std::move(onBuffer))
{
    match_ = std::make_unique<sdbusplus::bus::match::match>(
        systemBus, PLDM_EVENT_DBUS_MATCH,
        [this](sdbusplus::message::message& msg) {
            sd_bus_message* m = msg.get();
            if (m == nullptr)
            {
                lg2::error("PLDM event: null sd_bus_message");
                return;
            }

            uint64_t a0 = 0;
            uint8_t a1 = 0;
            const char* a2 = nullptr;
            uint8_t a3 = 0;
            uint8_t a4 = 0;
            uint16_t a5 = 0;
            uint32_t a6 = 0;
            uint16_t a7 = 0;
            int eventFd = -1;

            const int r = sd_bus_message_read(m, PLDM_EVENT_MESSAGE_SIGNATURE,
                                              &a0, &a1, &a2, &a3, &a4, &a5,
                                              &a6, &a7, &eventFd);
            if (r < 0)
            {
                const std::string sigStr(PLDM_EVENT_MESSAGE_SIGNATURE);
                lg2::error(
                    "PLDM event: sd_bus_message_read failed: {ERR} (signature {SIG})",
                    "ERR", strerror(-r), "SIG", sigStr);
                return;
            }

            (void)a0;
            (void)a1;
            (void)a2;
            (void)a3;
            (void)a4;
            (void)a5;
            (void)a6;
            (void)a7;

            if (eventFd < 0)
            {
                lg2::error("PLDM event: invalid UNIX fd from signal");
                return;
            }

            std::vector<uint8_t> payload;
            if (!readEventPayload(eventFd, PLDM_EVENT_MAX_PAYLOAD, payload))
            {
                ::close(eventFd);
                return;
            }

            if (::close(eventFd) != 0)
            {
                lg2::warning("PLDM event: close(fd) failed: {ERR}", "ERR",
                             strerror(errno));
            }

            lg2::info("PLDM event: payload {BYTES} bytes", "BYTES",
                      payload.size());

            boost::asio::post(
                io_.get_executor(),
                [this, p = std::move(payload)]() mutable {
                    if (onBuffer_)
                    {
                        onBuffer_(std::move(p));
                    }
                });
        });

    // Copy match into std::string: lg2 constexpr header parsing rejects the raw
    // PLDM_EVENT_DBUS_MATCH literal (quotes / length) as a consteval argument.
    const std::string matchStr(PLDM_EVENT_DBUS_MATCH);
    lg2::info("PLDM RAS: subscribed to D-Bus match {MATCH}", "MATCH", matchStr);
}

PldmEventMonitor::~PldmEventMonitor()
{
    match_.reset();
}

} // namespace ras
} // namespace amd
