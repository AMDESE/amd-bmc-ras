#include "Config.hpp"

uint16_t Configuration::apmlRetryCount;
uint16_t Configuration::systemRecovery;
bool Configuration::harvestuCodeVersionFlag;
bool Configuration::harvestPpinFlag;
bool Configuration::McaPollingEn;
bool Configuration::DramCeccPollingEn;
bool Configuration::PcieAerPollingEn;
bool Configuration::McaThresholdEn;
bool Configuration::DramCeccThresholdEn;
bool Configuration::PcieAerThresholdEn;
bool Configuration::AifsArmed;
bool Configuration::DisableResetCounter;
uint16_t Configuration::McaPollingPeriod;
uint16_t Configuration::DramCeccPollingPeriod;
uint16_t Configuration::PcieAerPollingPeriod;
uint16_t Configuration::McaErrThresholdCnt;
uint16_t Configuration::DramCeccErrThresholdCnt;
uint16_t Configuration::PcieAerErrThresholdCnt;
std::string ResetSignal;
std::vector<std::string> Configuration::sigIDOffset = {
    "0x30", "0x34", "0x28", "0x2c", "0x08", "0x0c", "null", "null"};

std::vector<std::pair<std::string, std::string>> Configuration::P0_DimmLabels =
    {{"P0_DIMM_A", "null"},  {"P0_DIMM_A1", "null"}, {"P0_DIMM_B", "null"},
     {"P0_DIMM_B1", "null"}, {"P0_DIMM_C", "null"},  {"P0_DIMM_C1", "null"},
     {"P0_DIMM_D", "null"},  {"P0_DIMM_D1", "null"}, {"P0_DIMM_E", "null"},
     {"P0_DIMM_E1", "null"}, {"P0_DIMM_F", "null"},  {"P0_DIMM_F1", "null"},
     {"P0_DIMM_G", "null"},  {"P0_DIMM_G1", "null"}, {"P0_DIMM_H", "null"},
     {"P0_DIMM_H1", "null"}, {"P0_DIMM_I", "null"},  {"P0_DIMM_I1", "null"},
     {"P0_DIMM_J", "null"},  {"P0_DIMM_J1", "null"}, {"P0_DIMM_K", "null"},
     {"P0_DIMM_K1", "null"}, {"P0_DIMM_L", "null"},  {"P0_DIMM_L1", "null"}};

std::vector<std::pair<std::string, std::string>> Configuration::P1_DimmLabels =
    {{"P1_DIMM_A", "null"},  {"P1_DIMM_A1", "null"}, {"P1_DIMM_B", "null"},
     {"P1_DIMM_B1", "null"}, {"P1_DIMM_C", "null"},  {"P1_DIMM_C1", "null"},
     {"P1_DIMM_D", "null"},  {"P1_DIMM_D1", "null"}, {"P1_DIMM_E", "null"},
     {"P1_DIMM_E1", "null"}, {"P1_DIMM_F", "null"},  {"P1_DIMM_F1", "null"},
     {"P1_DIMM_G", "null"},  {"P1_DIMM_G1", "null"}, {"P1_DIMM_H", "null"},
     {"P1_DIMM_H1", "null"}, {"P1_DIMM_I", "null"},  {"P1_DIMM_I1", "null"},
     {"P1_DIMM_J", "null"},  {"P1_DIMM_J1", "null"}, {"P1_DIMM_K", "null"},
     {"P1_DIMM_K1", "null"}, {"P1_DIMM_L", "null"},  {"P1_DIMM_L1", "null"}};

std::vector<std::pair<std::string, std::string>>
    Configuration::AifsSignatureId = {
        {"EX-WDT", "0xaea0000000000108000500b020009a00000000004d000000"}};

void Configuration::setApmlRetryCount(uint16_t value)
{
    apmlRetryCount = value;
}
uint16_t Configuration::getApmlRetryCount()
{
    return apmlRetryCount;
}

void Configuration::setSystemRecovery(uint16_t value)
{
    systemRecovery = value;
}
uint16_t Configuration::getSystemRecovery()
{
    return systemRecovery;
}

void Configuration::setHarvestuCodeVersionFlag(bool value)
{
    harvestuCodeVersionFlag = value;
}
bool Configuration::getHarvestuCodeVersionFlag()
{
    return harvestuCodeVersionFlag;
}

void Configuration::setHarvestPpinFlag(bool value)
{
    harvestPpinFlag = value;
}
bool Configuration::getHarvestPpinFlag()
{
    return harvestPpinFlag;
}

void Configuration::setMcaPollingEn(bool value)
{
    McaPollingEn = value;
}
bool Configuration::getMcaPollingEn()
{
    return McaPollingEn;
}

void Configuration::setDramCeccPollingEn(bool value)
{
    DramCeccPollingEn = value;
}
bool Configuration::getDramCeccPollingEn()
{
    return DramCeccPollingEn;
}

void Configuration::setPcieAerPollingEn(bool value)
{
    PcieAerPollingEn = value;
}
bool Configuration::getPcieAerPollingEn()
{
    return PcieAerPollingEn;
}

void Configuration::setMcaThresholdEn(bool value)
{
    McaThresholdEn = value;
}
bool Configuration::getMcaThresholdEn()
{
    return McaThresholdEn;
}

void Configuration::setDramCeccThresholdEn(bool value)
{
    DramCeccThresholdEn = value;
}
bool Configuration::getDramCeccThresholdEn()
{
    return DramCeccThresholdEn;
}

void Configuration::setPcieAerThresholdEn(bool value)
{
    PcieAerThresholdEn = value;
}
bool Configuration::getPcieAerThresholdEn()
{
    return PcieAerThresholdEn;
}

void Configuration::setAifsArmed(bool value)
{
    AifsArmed = value;
}

bool Configuration::getAifsArmed()
{
    return AifsArmed;
}

void Configuration::setDisableResetCounter(bool value)
{
    DisableResetCounter = value;
}

bool Configuration::getDisableResetCounter()
{
    return DisableResetCounter;
}

void Configuration::setMcaPollingPeriod(uint16_t value)
{
    McaPollingPeriod = value;
}
uint16_t Configuration::getMcaPollingPeriod()
{
    return McaPollingPeriod;
}

void Configuration::setDramCeccPollingPeriod(uint16_t value)
{
    DramCeccPollingPeriod = value;
}
uint16_t Configuration::getDramCeccPollingPeriod()
{
    return DramCeccPollingPeriod;
}

void Configuration::setPcieAerPollingPeriod(uint16_t value)
{
    PcieAerPollingPeriod = value;
}
uint16_t Configuration::getPcieAerPollingPeriod()
{
    return PcieAerPollingPeriod;
}

void Configuration::setMcaErrThresholdCnt(uint16_t value)
{
    McaErrThresholdCnt = value;
}
uint16_t Configuration::getMcaErrThresholdCnt()
{
    return McaErrThresholdCnt;
}

void Configuration::setDramCeccErrThresholdCnt(uint16_t value)
{
    DramCeccErrThresholdCnt = value;
}
uint16_t Configuration::getDramCeccErrThresholdCnt()
{
    return DramCeccErrThresholdCnt;
}

void Configuration::setPcieAerErrThresholdCnt(uint16_t value)
{
    PcieAerErrThresholdCnt = value;
}
uint16_t Configuration::getPcieAerErrThresholdCnt()
{
    return PcieAerErrThresholdCnt;
}

void Configuration::setResetSignal(const std::string& value)
{
    ResetSignal = value;
}

std::string Configuration::getResetSignal()
{
    return ResetSignal;
}

void Configuration::setSigIDOffset(const std::vector<std::string>& value)
{
    sigIDOffset = value;
}

std::vector<std::string> Configuration::getSigIDOffset()
{
    return sigIDOffset;
}

std::string Configuration::getP0_DimmLabels(const std::string& key)
{
    auto it =
        std::find_if(P0_DimmLabels.begin(), P0_DimmLabels.end(),
                     [&key](const std::pair<std::string, std::string>& pair) {
                         return pair.first == key;
                     });

    if (it != P0_DimmLabels.end())
    {
        return it->second;
    }
    // Return an empty string if the key is not found
    return "";
}

std::string Configuration::getP1_DimmLabels(const std::string& key)
{
    auto it =
        std::find_if(P1_DimmLabels.begin(), P1_DimmLabels.end(),
                     [&key](const std::pair<std::string, std::string>& pair) {
                         return pair.first == key;
                     });

    if (it != P1_DimmLabels.end())
    {
        return it->second;
    }
    // Return an empty string if the key is not found
    return "";
}

void Configuration::setP0_DimmLabels(const std::string& key,
                                     const std::string& value)
{
    auto it =
        std::find_if(P0_DimmLabels.begin(), P0_DimmLabels.end(),
                     [&key](const std::pair<std::string, std::string>& pair) {
                         return pair.first == key;
                     });

    if (it != P0_DimmLabels.end())
    {
        it->second = value;
    }
}

void Configuration::setP1_DimmLabels(const std::string& key,
                                     const std::string& value)
{
    auto it =
        std::find_if(P1_DimmLabels.begin(), P1_DimmLabels.end(),
                     [&key](const std::pair<std::string, std::string>& pair) {
                         return pair.first == key;
                     });

    if (it != P1_DimmLabels.end())
    {
        it->second = value;
    }
}

void Configuration::setAifsSignatureId(
    const nlohmann::json& AifsSignatureIdData)
{
    AifsSignatureId.clear();

    for (const auto& item : AifsSignatureIdData)
    {
        if (item.size() == INDEX_2)
        {
            AifsSignatureId.emplace_back(item[INDEX_0], item[INDEX_1]);
        }
    }

    for (auto it = AifsSignatureIdData.begin(); it != AifsSignatureIdData.end();
         ++it)
    {
        const std::string& key = it.key();
        const std::string& value = it.value();

        AifsSignatureId.push_back(std::make_pair(key, value));
    }
}

std::vector<std::pair<std::string, std::string>>
    Configuration::getAllP0_DimmLabels()
{
    return P0_DimmLabels;
}

std::vector<std::pair<std::string, std::string>>
    Configuration::getAllP1_DimmLabels()
{
    return P1_DimmLabels;
}

std::vector<std::pair<std::string, std::string>>
    Configuration::getAllAifsSignatureId()
{
    return AifsSignatureId;
}

void Configuration::setAllP0_DimmLabels(
    const std::vector<std::pair<std::string, std::string>>& value)
{
    P0_DimmLabels = value;
}

void Configuration::setAllP1_DimmLabels(
    const std::vector<std::pair<std::string, std::string>>& value)
{
    P1_DimmLabels = value;
}

void Configuration::setAllAifsSignatureId(
    const std::vector<std::pair<std::string, std::string>>& value)
{
    AifsSignatureId = value;
}
