#include "ras.hpp"

class Configuration
{
private:
    static uint16_t apmlRetryCount;
    static uint16_t systemRecovery;
    static bool harvestuCodeVersionFlag;
    static bool harvestPpinFlag;
    static bool McaPollingEn;
    static bool DramCeccPollingEn;
    static bool PcieAerPollingEn;
    static bool McaThresholdEn;
    static bool DramCeccThresholdEn;
    static bool PcieAerThresholdEn;
    static uint16_t McaPollingPeriod;
    static uint16_t DramCeccPollingPeriod;
    static uint16_t PcieAerPollingPeriod;
    static uint16_t McaErrCounter;
    static uint16_t DramCeccErrCounter;
    static uint16_t PcieAerErrCounter;
    static std::vector<std::string> sigIDOffset;

public:
    Configuration();
    static void setApmlRetryCount(uint16_t);
    static uint16_t getApmlRetryCount();

    static void setSystemRecovery(uint16_t);
    static uint16_t getSystemRecovery();

    static void setHarvestuCodeVersionFlag(bool);
    static bool getHarvestuCodeVersionFlag();

    static void setHarvestPpinFlag(bool);
    static bool getHarvestPpinFlag();

    static void setMcaPollingEn(bool);
    static bool getMcaPollingEn();

    static void setDramCeccPollingEn(bool);
    static bool getDramCeccPollingEn();

    static void setPcieAerPollingEn(bool);
    static bool getPcieAerPollingEn();

    static void setMcaThresholdEn(bool);
    static bool getMcaThresholdEn();

    static void setDramCeccThresholdEn(bool);
    static bool getDramCeccThresholdEn();

    static void setPcieAerThresholdEn(bool);
    static bool getPcieAerThresholdEn();

    static void setMcaPollingPeriod(uint16_t);
    static uint16_t getMcaPollingPeriod();

    static void setDramCeccPollingPeriod(uint16_t);
    static uint16_t getDramCeccPollingPeriod();

    static void setPcieAerPollingPeriod(uint16_t);
    static uint16_t getPcieAerPollingPeriod();

    static void setMcaErrCounter(uint16_t);
    static uint16_t getMcaErrCounter();

    static void setDramCeccErrCounter(uint16_t);
    static uint16_t getDramCeccErrCounter();

    static void setPcieAerErrCounter(uint16_t);
    static uint16_t getPcieAerErrCounter();

    static void setSigIDOffset(std::vector<std::string>);
    static std::vector<std::string> getSigIDOffset();

};

