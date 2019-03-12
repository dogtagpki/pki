package com.netscape.cmscore.app;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import com.netscape.certsrv.apps.ICMSEngine;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

/**
 * Default engine stub for testing.
 */
public class CMSEngineDefaultStub implements ICMSEngine {
    public String getId() {
        return null;
    }

    public void setId(String id) throws EBaseException {
    }

    public void init(ISubsystem owner, IConfigStore config) throws EBaseException {
    }

    public void startup() throws EBaseException {
    }

    public void shutdown() {
    }

    public IConfigStore getConfigStore() {
        return null;
    }

    public int getPID() {
        return 0;
    }

    public void reinit(String id) throws EBaseException {
    }

    public int getCSState() {
        return 0;
    }

    public void setCSState(int mode) {
    }

    public boolean isPreOpMode() {
        return false;
    }

    public boolean isRunningMode() {
        return false;
    }

    public String getInstanceDir() {
        return null;
    }

    public Date getCurrentDate() {
        return null;
    }

    public boolean isInRunningState() {
        return false;
    }

    public Enumeration<String> getSubsystemNames() {
        return null;
    }

    public Enumeration<ISubsystem> getSubsystems() {
        return null;
    }

    public void setSubsystemEnabled(String id, boolean enabled) {
    };

    public ISubsystem getSubsystem(String name) {
        return null;
    }

    public void debug(byte data[]) {
    }

    public void debug(String msg) {
    }

    public void debug(int level, String msg) {
    }

    public void debug(Throwable e) {
    }

    public boolean debugOn() {
        return false;
    }

    public void debugStackTrace() {
    }

    public void traceHashKey(String type, String key) {
    }

    public void traceHashKey(String type, String key, String val) {
    }

    public void traceHashKey(String type, String key, String val, String def) {
    }

    public byte[] getPKCS7(Locale locale, IRequest req) {
        return new byte[0];
    }

    public String getUserMessage(Locale locale, String msgID) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p[]) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1, String p2) {
        return null;
    }

    public String getUserMessage(Locale locale, String msgID, String p1, String p2, String p3) {
        return null;
    }

    public String getLogMessage(String msgID, Object p[]) {
        return null;
    }

    public ICRLIssuingPointRecord createCRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate) {
        return null;
    }

    public String getCRLIssuingPointRecordName() {
        return null;
    }

    public String getEncodedCert(X509Certificate cert) {
        return null;
    }

    public LDAPConnection getBoundConnection(String id, String host, int port, int version, LDAPSSLSocketFactoryExt fac,
            String bindDN, String bindPW) throws LDAPException {
        return null;
    }

    public IPasswordCheck getPasswordChecker() {
        return null;
    }

    public ISharedToken getSharedTokenClass(String configName) {
        return null;
    }

    public void putPasswordCache(String tag, String pw) {
    }

    public String getEEHost() {
        return null;
    }

    public String getEENonSSLHost() {
        return null;
    }

    public String getEENonSSLIP() {
        return null;
    }

    public String getEENonSSLPort() {
        return null;
    }

    public String getEESSLHost() {
        return null;
    }

    public String getEESSLIP() {
        return null;
    }

    public String getEESSLPort() {
        return null;
    }

    public IMailNotification getMailNotification() {
        return null;
    }

    public IResender getResender(IAuthority authority, String nickname, String clientCiphers, IRemoteAuthority remote, int interval) {
        return null;
    }

    public void disableRequests() {
    }

    public void terminateRequests() {
    }

    public boolean areRequestsDisabled() {
        return false;
    }

    public IConfigStore createFileConfigStore(String path) throws EBaseException {
        return null;
    }

    public IArgBlock createArgBlock() {
        return null;
    }

    public boolean isRevoked(X509Certificate[] certificates) {
        return false;
    }

    public void setListOfVerifiedCerts(int size, long interval, long unknownStateInterval) {
    }

    public void forceShutdown() {
    }

    public void autoShutdown() {
    }

    public void checkForAndAutoShutdown() {
    }

    public IPasswordStore getPasswordStore() {
        return null;
    }

    public ISecurityDomainSessionTable getSecurityDomainSessionTable() {
        return null;
    }

    public void setConfigSDSessionId(String id) {
    }

    public String getConfigSDSessionId() {
        return null;
    }

    @Override
    public String getEEClientAuthSSLPort() {
        return null;
    }

    @Override
    public IArgBlock createArgBlock(String realm,
            Hashtable<String, String> httpReq) {
        return null;
    }

    @Override
    public IArgBlock createArgBlock(Hashtable<String, String> httpReq) {
        return null;
    }

    @Override
    public void sleepOneMinute() {
    }

    @Override
    public boolean isExcludedLdapAttrsEnabled() {
        return true;
    }

    @Override
    public boolean isExcludedLdapAttr(String key) {
        return false;
    }
}
