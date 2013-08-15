package com.netscape.cmscore.app;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.X509CertInfo;

import org.mozilla.jss.CryptoManager.CertificateUsage;
import org.mozilla.jss.util.PasswordCallback;

import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.apps.ICMSEngine;
import com.netscape.certsrv.apps.ICommandQueue;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.ICRLPrettyPrint;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtPrettyPrint;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IEmailTemplate;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.policy.IGeneralNameAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesConfig;
import com.netscape.certsrv.policy.ISubjAltNameConfig;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.net.ISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

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

    public long getStartupTime() {
        return 0;
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

    public ISubsystem getSubsystem(String name) {
        return null;
    }

    public ILogger getLogger() {
        return null;
    }

    public IAuditor getAuditor() {
        return null;
    }

    public ILogger getSignedAuditLogger() {
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

    public String getLogMessage(String msgID) {
        return null;
    }

    public String getLogMessage(String msgID, String p[]) {
        return null;
    }

    public String getLogMessage(String msgID, String p1) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8) {
        return null;
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8, String p9) {
        return null;
    }

    public IACL parseACL(String resACLs) throws EACLsException {
        return null;
    }

    public ICRLIssuingPointRecord createCRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate) {
        return null;
    }

    public String getCRLIssuingPointRecordName() {
        return null;
    }

    public String getFingerPrint(Certificate cert) throws CertificateEncodingException, NoSuchAlgorithmException {
        return null;
    }

    public String getFingerPrints(Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        return null;
    }/*
     * Returns the finger print of the given certificate.
     *
     * @param certDer DER byte array of certificate
     * @return finger print of certificate
     */

    public String getFingerPrints(byte[] certDer) throws NoSuchAlgorithmException {
        return null;
    }

    public IRepositoryRecord createRepositoryRecord() {
        return null;
    }

    public IPKIMessage getHttpPKIMessage() {
        return null;
    }

    public IRequestEncoder getHttpRequestEncoder() {
        return null;
    }

    public String BtoA(byte data[]) {
        return null;
    }

    public byte[] AtoB(String data) {
        return new byte[0];
    }

    public String getEncodedCert(X509Certificate cert) {
        return null;
    }

    public IPrettyPrintFormat getPrettyPrintFormat(String delimiter) {
        return null;
    }

    public IExtPrettyPrint getExtPrettyPrint(Extension e, int indent) {
        return null;
    }

    public ICertPrettyPrint getCertPrettyPrint(X509Certificate cert) {
        return null;
    }

    public ICRLPrettyPrint getCRLPrettyPrint(X509CRL crl) {
        return null;
    }

    public ICRLPrettyPrint getCRLCachePrettyPrint(ICRLIssuingPoint ip) {
        return null;
    }

    public ILdapConnInfo getLdapConnInfo(IConfigStore config) throws EBaseException, ELdapException {
        return null;
    }

    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory(String certNickname) {
        return null;
    }

    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory() {
        return null;
    }

    public ILdapAuthInfo getLdapAuthInfo() {
        return null;
    }

    public ILdapConnFactory getLdapBoundConnFactory() throws ELdapException {
        return null;
    }

    public LDAPConnection getBoundConnection(String host, int port, int version, LDAPSSLSocketFactoryExt fac,
            String bindDN, String bindPW) throws LDAPException {
        return null;
    }

    public ILdapConnFactory getLdapAnonConnFactory() throws ELdapException {
        return null;
    }

    public IPasswordCheck getPasswordChecker() {
        return null;
    }

    public void putPasswordCache(String tag, String pw) {
    }

    public PasswordCallback getPasswordCallback() {
        return null;
    }

    public String getServerCertNickname() {
        return null;
    }

    public void setServerCertNickname(String tokenName, String nickName) {
    }

    public void setServerCertNickname(String newName) {
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

    public String getAgentHost() {
        return null;
    }

    public String getAgentIP() {
        return null;
    }

    public String getAgentPort() {
        return null;
    }

    public String getAdminHost() {
        return null;
    }

    public String getAdminIP() {
        return null;
    }

    public String getAdminPort() {
        return null;
    }

    public boolean isSigningCert(X509Certificate cert) {
        return false;
    }

    public boolean isEncryptionCert(X509Certificate cert) {
        return false;
    }

    public X509CertInfo getDefaultX509CertInfo() {
        return null;
    }

    public IEmailFormProcessor getEmailFormProcessor() {
        return null;
    }

    public IEmailTemplate getEmailTemplate(String path) {
        return null;
    }

    public IMailNotification getMailNotification() {
        return null;
    }

    public IEmailResolverKeys getEmailResolverKeys() {
        return null;
    }

    public IEmailResolver getReqCertSANameEmailResolver() {
        return null;
    }

    public ObjectIdentifier checkOID(String attrName, String value) throws EBaseException {
        return null;
    }

    public GeneralName form_GeneralNameAsConstraints(String generalNameChoice, String value) throws EBaseException {
        return null;
    }

    public GeneralName form_GeneralName(String generalNameChoice, String value) throws EBaseException {
        return null;
    }

    public IGeneralNamesConfig createGeneralNamesConfig(String name, IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return null;
    }

    public IGeneralNameAsConstraintsConfig createGeneralNameAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured, boolean isPolicyEnabled) throws EBaseException {
        return null;
    }

    public IGeneralNamesAsConstraintsConfig createGeneralNamesAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured, boolean isPolicyEnabled) throws EBaseException {
        return null;
    }

    public ISubjAltNameConfig createSubjAltNameConfig(String name, IConfigStore config, boolean isValueConfigured)
            throws EBaseException {
        return null;
    }

    public IHttpConnection getHttpConnection(IRemoteAuthority authority, ISocketFactory factory) {
        return null;
    }

    public IHttpConnection getHttpConnection(IRemoteAuthority authority, ISocketFactory factory, int timeout) {
        return null;
    }

    public IResender getResender(IAuthority authority, String nickname, IRemoteAuthority remote, int interval) {
        return null;
    }

    public ICommandQueue getCommandQueue() {
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
    public boolean verifySystemCerts() {
        return false;
    }

    @Override
    public boolean verifySystemCertByTag(String tag) {
        return false;
    }

    @Override
    public boolean verifySystemCertByNickname(String nickname,
            String certificateUsage) {
        return false;
    }

    @Override
    public CertificateUsage getCertificateUsage(String certusage) {
        return null;
    }

    @Override
    public void getGeneralNameConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
    }

    @Override
    public void getGeneralNamesConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
    }

    @Override
    public void getGeneralNameConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
    }

    @Override
    public void getGeneralNamesConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
    }

    @Override
    public void getSubjAltNameConfigDefaultParams(String name,
            Vector<String> params) {
    }

    @Override
    public void getSubjAltNameConfigExtendedPluginInfo(String name,
            Vector<String> params) {
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
    public String getServerStatus() {
        return null;
    }
}
