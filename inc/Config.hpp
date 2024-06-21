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
    static bool AifsArmed;
    static uint16_t McaPollingPeriod;
    static uint16_t DramCeccPollingPeriod;
    static uint16_t PcieAerPollingPeriod;
    static uint16_t McaErrThresholdCnt;
    static uint16_t DramCeccErrThresholdCnt;
    static uint16_t PcieAerErrThresholdCnt;
    static std::vector<std::string> sigIDOffset;
    static std::vector<std::pair<std::string, std::string>> P0_DimmLabels;
    static std::vector<std::pair<std::string, std::string>> P1_DimmLabels;
    static std::vector<std::pair<std::string, std::string>> AifsSignatureId;

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

    static void setAifsArmed(bool);
    static bool getAifsArmed();

    static void setMcaPollingPeriod(uint16_t);
    static uint16_t getMcaPollingPeriod();

    static void setDramCeccPollingPeriod(uint16_t);
    static uint16_t getDramCeccPollingPeriod();

    static void setPcieAerPollingPeriod(uint16_t);
    static uint16_t getPcieAerPollingPeriod();

    static void setMcaErrThresholdCnt(uint16_t);
    static uint16_t getMcaErrThresholdCnt();

    static void setDramCeccErrThresholdCnt(uint16_t);
    static uint16_t getDramCeccErrThresholdCnt();

    static void setPcieAerErrThresholdCnt(uint16_t);
    static uint16_t getPcieAerErrThresholdCnt();

    static void setResetSignal(std::string);
    static std::string getResetSignal();

    static void setSigIDOffset(std::vector<std::string>);
    static std::vector<std::string> getSigIDOffset();

    static std::vector<std::pair<std::string, std::string>>
        getAllP0_DimmLabels();
    static std::vector<std::pair<std::string, std::string>>
        getAllP1_DimmLabels();
    static std::vector<std::pair<std::string, std::string>>
        getAllAifsSignatureId();

    static void
        setAllP0_DimmLabels(std::vector<std::pair<std::string, std::string>>);
    static void
        setAllP1_DimmLabels(std::vector<std::pair<std::string, std::string>>);
    static void
        setAllAifsSignatureId(std::vector<std::pair<std::string, std::string>>);

    static std::string getP0_DimmLabels(const std::string&);
    static std::string getP1_DimmLabels(const std::string&);

    static void setP0_DimmLabels(const std::string&, const std::string&);
    static void setP1_DimmLabels(const std::string&, const std::string&);
    static void setAifsSignatureId(const nlohmann::json&);
};
