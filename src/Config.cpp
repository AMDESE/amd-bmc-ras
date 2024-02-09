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
uint16_t Configuration::McaPollingPeriod;
uint16_t Configuration::DramCeccPollingPeriod;
uint16_t Configuration::PcieAerPollingPeriod;
uint16_t Configuration::McaErrCounter;
uint16_t Configuration::DramCeccErrCounter;
uint16_t Configuration::PcieAerErrCounter;
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

void Configuration::setMcaErrCounter(uint16_t value)
{
    McaErrCounter = value;
}
uint16_t Configuration::getMcaErrCounter()
{
    return McaErrCounter;
}

void Configuration::setDramCeccErrCounter(uint16_t value)
{
    DramCeccErrCounter = value;
}
uint16_t Configuration::getDramCeccErrCounter()
{
    return DramCeccErrCounter;
}

void Configuration::setPcieAerErrCounter(uint16_t value)
{
    PcieAerErrCounter = value;
}
uint16_t Configuration::getPcieAerErrCounter()
{
    return PcieAerErrCounter;
}

void Configuration::setResetSignal(std::string value)
{
    ResetSignal = value;
}

std::string Configuration::getResetSignal()
{
    return ResetSignal;
}

void Configuration::setSigIDOffset(std::vector<std::string> value)
{
    sigIDOffset = value;
}

std::vector<std::string> Configuration::getSigIDOffset()
{
    return sigIDOffset;
}

std::string Configuration::getP0_DimmLabels(const std::string& key)
{
    for (const auto& pair : P0_DimmLabels)
    {
        if (pair.first == key)
        {
            return pair.second;
        }
    }
    // Return an empty string if the key is not found
    return "";
}

std::string Configuration::getP1_DimmLabels(const std::string& key)
{
    for (const auto& pair : P1_DimmLabels)
    {
        if (pair.first == key)
        {
            return pair.second;
        }
    }
    // Return an empty string if the key is not found
    return "";
}

void Configuration::setP0_DimmLabels(const std::string& key,
                                     const std::string& value)
{
    for (auto& pair : P0_DimmLabels)
    {
        if (pair.first == key)
        {
            pair.second = value;
            return;
        }
    }
}

void Configuration::setP1_DimmLabels(const std::string& key,
                                     const std::string& value)
{
    for (auto& pair : P1_DimmLabels)
    {
        if (pair.first == key)
        {
            pair.second = value;
            return;
        }
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

void Configuration::setAllP0_DimmLabels(
    std::vector<std::pair<std::string, std::string>> value)
{
    P0_DimmLabels = value;
}

void Configuration::setAllP1_DimmLabels(
    std::vector<std::pair<std::string, std::string>> value)
{
    P1_DimmLabels = value;
}
