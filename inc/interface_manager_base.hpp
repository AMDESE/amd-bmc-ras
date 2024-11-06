#include "config_manager.hpp"
#include "ras.hpp"

class RasManagerBase : public RasConfiguration
{
  public:
    RasManagerBase(sdbusplus::asio::object_server& objectServer,
                   std::shared_ptr<sdbusplus::asio::connection>& systemBus,
                   boost::asio::io_service& io) :
        RasConfiguration(objectServer, systemBus), io(io),
        p0_apmlAlertEvent(io), p1_apmlAlertEvent(io)
    {}

    virtual void init() = 0;

    virtual void configure() = 0;

    virtual ~RasManagerBase();

    void p0AlertEventHandler();
    void p1AlertEventHandler();

  protected:
    boost::asio::io_service& io;
    uint8_t numOfCpu;
    CpuId* cpuId;
    uint32_t* uCode;
    uint64_t* ppin;
    std::string* inventoryPath;
    unsigned int boardId;
    uint8_t progId;
    int errCount = 0;
    boost::asio::posix::stream_descriptor p0_apmlAlertEvent;
    boost::asio::posix::stream_descriptor p1_apmlAlertEvent;
    gpiod::line p0_apmlAlertLine;
    gpiod::line p1_apmlAlertLine;

    void getNumberOfCpu();
    void getBoardId();
    void createIndexFile();
    void createConfigFile();
    void getMicrocodeRev();
    void getPpinFuse();
    template <typename T>
    T getProperty(sdbusplus::bus::bus&, const char*, const char*, const char*,
                  const char*);
    void requestGPIOEvents(const std::string&, const std::function<void()>&,
                           gpiod::line&,
                           boost::asio::posix::stream_descriptor&);
    void rasRecoveryAction(uint8_t);
    void triggerColdReset();
    void triggerRsmrstReset();
    void triggerSysReset();
    void requestHostTransition(std::string);

    virtual void interfaceActiveMonitor() = 0;
    virtual void getCpuId() = 0;
    virtual void findProgramId() = 0;
    virtual bool harvestFatalError(uint8_t) = 0;
};
