//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class CRLIssuingPointConfig extends PropConfigStore {

    public CRLIssuingPointConfig(ConfigStorage storage) {
        super(storage);
    }

    public CRLIssuingPointConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getAllowExtensions() throws EBaseException {
        return getBoolean("allowExtensions", false);
    }

    public void setAllowExtensions(boolean allowExtensions) {
        putBoolean("allowExtensions", allowExtensions);
    }

    public boolean getAlwaysUpdate() throws EBaseException {
        return getBoolean("alwaysUpdate", false);
    }

    public void setAlwaysUpdate(boolean alwaysUpdate) {
        putBoolean("alwaysUpdate", alwaysUpdate);
    }

    public int getAutoUpdateInterval() throws EBaseException {
        return getInteger("autoUpdateInterval", 0);
    }

    public void setAutoUpdateInterval(int autoUpdateInterval) {
        putInteger("autoUpdateInterval", autoUpdateInterval);
    }

    public boolean getCACertsOnly() throws EBaseException {
        return getBoolean("caCertsOnly", false);
    }

    public void setCACertsOnly(boolean caCertsOnly) {
        putBoolean("caCertsOnly", caCertsOnly);
    }

    public int getCacheUpdateInterval() throws EBaseException {
        return getInteger("cacheUpdateInterval", 0);
    }

    public void setCacheUpdateInterval(int cacheUpdateInterval) {
        putInteger("cacheUpdateInterval", cacheUpdateInterval);
    }

    public String getClassName() throws EBaseException {
        return getString("class");
    }

    public void setClassName(String className) {
        putString("class", className);
    }

    public String getDailyUpdates() throws EBaseException {
        return getString("dailyUpdates", null);
    }

    public void setDailyUpdates(String dailyUpdates) {
        putString("dailyUpdates", dailyUpdates);
    }

    public String getDescription() throws EBaseException {
        return getString("description");
    }

    public void setDescription(String description) {
        putString("description", description);
    }

    public boolean getEnable() throws EBaseException {
        return getBoolean("enable", true);
    }

    public void setEnable(boolean enable) {
        putBoolean("enable", enable);
    }

    public boolean getEnableCRLCache() throws EBaseException {
        return getBoolean("enableCRLCache", true);
    }

    public void setEnableCRLCache(boolean enableCRLCache) {
        putBoolean("enableCRLCache", enableCRLCache);
    }

    public boolean getEnableCRLUpdates() throws EBaseException {
        return getBoolean("enableCRLUpdates", true);
    }

    public void setEnableCRLUpdates(boolean enableCRLUpdates) {
        putBoolean("enableCRLUpdates", enableCRLUpdates);
    }

    public boolean getEnableCacheTesting() throws EBaseException {
        return getBoolean("enableCacheTesting", false);
    }

    public void setEnableCacheTesting(boolean enableCacheTesting) {
        putBoolean("enableCacheTesting", enableCacheTesting);
    }

    public boolean getEnableCacheRecovery() throws EBaseException {
        return getBoolean("enableCacheRecovery", false);
    }

    public void setEnableCacheRecovery(boolean enableCacheRecovery) {
        putBoolean("enableCacheRecovery", enableCacheRecovery);
    }

    public boolean getEnableDailyUpdates() throws EBaseException {
        return getBoolean("enableDailyUpdates", false);
    }

    public void setEnableDailyUpdates(boolean enableDailyUpdates) {
        putBoolean("enableDailyUpdates", enableDailyUpdates);
    }

    public boolean getEnableUpdateInterval() throws EBaseException {
        return getBoolean("enableUpdateInterval", true);
    }

    public void setEnableUpdateInterval(boolean enableUpdateInterval) {
        putBoolean("enableUpdateInterval", enableUpdateInterval);
    }

    public boolean getExtendedNextUpdate() throws EBaseException {
        return getBoolean("extendedNextUpdate", true);
    }

    public void setExtendedNextUpdate(boolean extendedNextUpdate) {
        putBoolean("extendedNextUpdate", extendedNextUpdate);
    }

    public boolean getIncludeExpiredCerts() throws EBaseException {
        return getBoolean("includeExpiredCerts", false);
    }

    public void setIncludeExpiredCerts(boolean includeExpiredCerts) {
        putBoolean("includeExpiredCerts", includeExpiredCerts);
    }

    public int getMinUpdateInterval() throws EBaseException {
        return getInteger("minUpdateInterval", 0);
    }

    public void setMinUpdateInterval(int minUpdateInterval) {
        putInteger("minUpdateInterval", minUpdateInterval);
    }

    public int getNextUpdateGracePeriod() throws EBaseException {
        return getInteger("nextUpdateGracePeriod", 0);
    }

    public void setNextUpdateGracePeriod(int nextUpdateGracePeriod) {
        putInteger("nextUpdateGracePeriod", nextUpdateGracePeriod);
    }

    public boolean getPublishOnStart() throws EBaseException {
        return getBoolean("publishOnStart", false);
    }

    public void setPublishOnStart(boolean publishOnStart) {
        putBoolean("publishOnStart", publishOnStart);
    }

    public boolean getSaveMemory() throws EBaseException {
        return getBoolean("saveMemory", false);
    }

    public void setSaveMemory(boolean saveMemory) {
        putBoolean("saveMemory", saveMemory);
    }

    public String getSigningAlgorithm() throws EBaseException {
        return getString("signingAlgorithm", null);
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        putString("signingAlgorithm", signingAlgorithm);
    }

    public int getUpdateSchema() throws EBaseException {
        return getInteger("updateSchema", 1);
    }

    public void setUpdateSchema(int updateSchema) {
        putInteger("updateSchema", updateSchema);
    }

    public boolean getNoCRLIfNoRevokedCert() throws EBaseException {
        return getBoolean("noCRLIfNoRevokedCert", false);
    }

    public void setNoCRLIfNoRevokedCert(boolean noCRLIfNoRevokedCert) {
        putBoolean("noCRLIfNoRevokedCert", noCRLIfNoRevokedCert);
    }

    public int getCountMod() throws EBaseException {
        return getInteger("countMod", 0);
    }

    public void setCountMod(int countMod) {
        putInteger("countMod", countMod);
    }

    public int getUnexpectedExceptionWaitTime() throws EBaseException {
        return getInteger("unexpectedExceptionWaitTime", 30);
    }

    public void setUnexpectedExceptionWaitTime(int unexpectedExceptionWaitTime) {
        putInteger("unexpectedExceptionWaitTime", unexpectedExceptionWaitTime);
    }

    public int getUnexpectedExceptionLoopMax() throws EBaseException {
        return getInteger("unexpectedExceptionLoopMax", 10);
    }

    public void setUnexpectedExceptionLoopMax(int unexpectedExceptionLoopMax) {
        putInteger("unexpectedExceptionLoopMax", unexpectedExceptionLoopMax);
    }

    public int getNextAsThisUpdateExtension() throws EBaseException {
        return getInteger("nextAsThisUpdateExtension", 0);
    }

    public void setNextAsThisUpdateExtension(int nextAsThisUpdateExtension) {
        putInteger("nextAsThisUpdateExtension", nextAsThisUpdateExtension);
    }

    public boolean getIncludeExpiredCertsOneExtraTime() throws EBaseException {
        return getBoolean("includeExpiredCertsOneExtraTime", false);
    }

    public void setIncludeExpiredCertsOneExtraTime(boolean includeExpiredCertsOneExtraTime) {
        putBoolean("includeExpiredCertsOneExtraTime", includeExpiredCertsOneExtraTime);
    }

    public boolean getProfileCertsOnly() throws EBaseException {
        return getBoolean("profileCertsOnly", false);
    }

    public void setProfileCertsOnly(boolean profileCertsOnly) {
        putBoolean("profileCertsOnly", profileCertsOnly);
    }

    public String getProfileList() throws EBaseException {
        return getString("profileList", null);
    }

    public void setProfileList(String profileList) {
        putString("profileList", profileList);
    }

    public String getPublishDN() throws EBaseException {
        return getString("publishDN", null);
    }

    public void setPublishDN(String publishDN) {
        putString("publishDN", publishDN);
    }

    public BigInteger getCRLBeginSerialNo() throws EBaseException {
        return getBigInteger("crlBeginSerialNo", null);
    }

    public void setCRLBeginSerialNo(BigInteger crlBeginSerialNo) {
        putBigInteger("crlBeginSerialNo", crlBeginSerialNo);
    }

    public BigInteger getCRLEndSerialNo() throws EBaseException {
        return getBigInteger("crlEndSerialNo", null);
    }

    public void setCRLEndSerialNo(BigInteger crlEndSerialNo) {
        putBigInteger("crlEndSerialNo", crlEndSerialNo);
    }

    public boolean getAutoUpdateIntervalEffectiveAtStart()  throws EBaseException {
        return getBoolean("autoUpdateInterval.effectiveAtStart",false);
    }

    public void setAutoUpdateIntervalEffectiveAtStart(Boolean updated) {
        putBoolean("autoUpdateInterval.effectiveAtStart",updated);
    }
}
