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
std::vector<std::string> Configuration::sigIDOffset = {"0x30","0x34","0x28","0x2c","0x08","0x0c","null","null"};

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

void Configuration::setSigIDOffset(std::vector<std::string> value)
{
    sigIDOffset = value;
}

std::vector<std::string> Configuration::getSigIDOffset()
{
    return sigIDOffset;
}
