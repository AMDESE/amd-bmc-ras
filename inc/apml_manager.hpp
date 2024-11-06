#include "interface_manager_base.hpp"

class ApmlInterfaceManager : public RasManagerBase
{
  public:
    virtual void init();

    virtual void configure();

    ApmlInterfaceManager(
        sdbusplus::asio::object_server& objectServer,
        std::shared_ptr<sdbusplus::asio::connection>& systemBus,
        boost::asio::io_service& io) :
        RasManagerBase(objectServer, systemBus, io)
    {}

  protected:
    std::vector<uint8_t> blockId;
    uint32_t familyId;
    std::mutex harvest_in_progress_mtx;
    bool p0AlertProcessed = false;
    bool p1AlertProcessed = false;
    uint64_t recordId = 1;
    uint16_t debugLogIdOffset;
    uint32_t SignatureID[8];
    virtual void interfaceActiveMonitor();
    virtual void getCpuId();
    virtual void findProgramId();
    virtual bool harvestFatalError(uint8_t);

    void clearSbrmiAlertMask(uint8_t);

    void performPlatformInitialization();

    oob_status_t readRegister(uint8_t, uint32_t, uint8_t*);

    void writeRegister(uint8_t, uint32_t, uint32_t);
    bool compare_with_bitwise_AND(const uint32_t*, const std::string&);
    bool checkSignatureIdMatch();
    std::vector<uint32_t> hexstring_to_vector(const std::string&);
    bool harvestMcaValidityCheck(uint8_t, uint16_t*, uint16_t*);
    bool harvestMcaDataBanks(uint8_t, uint16_t, uint16_t);
    void updateCperRecord(const char*, uint16_t, uint16_t, uint8_t);
    void getLastTransAddr(EFI_AMD_FATAL_ERROR_DATA*, uint8_t);
    void dumpContextInfo(EFI_AMD_FATAL_ERROR_DATA*, uint8_t);
    void harvestDebugLogDump(EFI_AMD_FATAL_ERROR_DATA*, uint8_t, uint8_t);
};
