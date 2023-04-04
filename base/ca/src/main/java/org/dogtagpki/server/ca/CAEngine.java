// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.legacy.ca.CAPolicy;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.AuthorityMonitor;
import com.netscape.ca.CANotify;
import com.netscape.ca.CAService;
import com.netscape.ca.CRLConfig;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CRLIssuingPointConfig;
import com.netscape.ca.CertificateAuthority;
import com.netscape.ca.KeyRetriever;
import com.netscape.ca.KeyRetrieverRunner;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Nonces;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.publish.CRLPublisher;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.certsrv.util.AsyncLoader;
import com.netscape.cms.authentication.CAAuthSubsystem;
import com.netscape.cms.request.RequestScheduler;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.VerifiedCert;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.CertStatusUpdateTask;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.ReplicaIDRepository;
import com.netscape.cmscore.dbs.RetrieveModificationsTask;
import com.netscape.cmscore.dbs.SerialNumberUpdateTask;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.ldap.LdapRequestListener;
import com.netscape.cmscore.ldap.PublishingConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.listeners.ListenerPlugin;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ldap.LDAPPostReadControl;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPConstraints;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;

public class CAEngine extends CMSEngine {

    static CAEngine instance;

    protected CertificateRepository certificateRepository;
    protected CRLRepository crlRepository;
    protected ReplicaIDRepository replicaIDRepository;

    protected CAPolicy caPolicy;
    protected CAService caService;

    protected CertificateVersion defaultCertVersion;
    protected long defaultCertValidity;
    protected boolean enablePastCATime;
    protected boolean enablePastCATime_caCert;
    protected boolean enableOCSP;

    protected int fastSigning = CertificateAuthority.FASTSIGNING_DISABLED;

    protected boolean allowExtCASignedAgentCerts = false;
    protected boolean enableNonces = true;
    protected int maxNonces = 100;

    protected Hashtable<String, ListenerPlugin> listenerPlugins = new Hashtable<>();

    protected boolean ocspResponderByName = true;
    protected CRLPublisher crlPublisher;
    protected CAPublisherProcessor publisherProcessor;

    protected Map<String, CRLIssuingPoint> crlIssuingPoints = new HashMap<>();

    // for CMC shared secret operations
    protected org.mozilla.jss.crypto.X509Certificate issuanceProtectionCert;
    protected PublicKey issuanceProtectionPublicKey;
    protected PrivateKey issuanceProtectionPrivateKey;

    public RequestListener certIssuedListener;
    public RequestListener certRevokedListener;
    public RequestListener requestInQueueListener;

    public RetrieveModificationsTask retrieveModificationsTask;
    public CertStatusUpdateTask certStatusUpdateTask;
    public SerialNumberUpdateTask serialNumberUpdateTask;

    protected LdapBoundConnFactory connectionFactory;

    public static Map<AuthorityID, CertificateAuthority> authorities =
            Collections.synchronizedSortedMap(new TreeMap<AuthorityID, CertificateAuthority>());

    public Map<AuthorityID, Thread> keyRetrievers =
            Collections.synchronizedSortedMap(new TreeMap<AuthorityID, Thread>());

    // Track authority updates to avoid race conditions and unnecessary reloads due to replication
    public static TreeMap<AuthorityID, BigInteger> entryUSNs = new TreeMap<>();
    public static TreeMap<AuthorityID, String> nsUniqueIds = new TreeMap<>();

    // Track authority deletions
    public static TreeSet<String> deletedNsUniqueIds = new TreeSet<>();

    protected AsyncLoader loader = new AsyncLoader(10 /* 10s timeout */);
    protected boolean foundHostCA;
    protected AuthorityMonitor authorityMonitor;
    protected boolean enableAuthorityMonitor = true;

    public CAEngine() {
        super("CA");
        instance = this;
    }

    public static CAEngine getInstance() {
        return instance;
    }

    @Override
    public CAEngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new CAEngineConfig(storage);
    }

    @Override
    public CAEngineConfig getConfig() {
        return (CAEngineConfig) mConfig;
    }

    @Override
    public void initDatabase() throws Exception {

        connectionFactory = new LdapBoundConnFactory("CertificateAuthority");
        connectionFactory.setCMSEngine(this);

        CAEngineConfig config = getConfig();
        PKISocketConfig socketConfig = config.getSocketConfig();
        LDAPConfig ldapConfig = config.getInternalDBConfig();

        connectionFactory.init(socketConfig, ldapConfig, getPasswordStore());
    }

    public CertRequestRepository getCertRequestRepository() {
        return (CertRequestRepository) requestRepository;
    }

    /**
     * Retrieves the certificate repository where all the locally
     * issued certificates are kept.
     *
     * @return certificate repository
     */
    public CertificateRepository getCertificateRepository() {
        return certificateRepository;
    }

    public CRLRepository getCRLRepository() {
        return crlRepository;
    }

    public ReplicaIDRepository getReplicaIDRepository() {
        return replicaIDRepository;
    }

    public CAPolicy getCAPolicy() {
        return caPolicy;
    }

    /**
     * Retrieves the CA service object that is responsible for
     * processing requests.
     *
     * @return CA service object
     */
    public CAService getCAService() {
        return caService;
    }

    /**
     * Retrieves the default certificate version.
     *
     * @return the default version certificate
     */
    public CertificateVersion getDefaultCertVersion() {
        return defaultCertVersion;
    }

    /**
     * Retrieves the default validity period.
     *
     * @return the default validity length in days
     */
    public long getDefaultCertValidity() {
        return defaultCertValidity;
    }

    /**
     * Is this CA allowed to issue non-ca certificates that have
     * validty past the CA's own validity.
     *
     * @return true if allows certificates to have validity longer than CA's
     */
    public boolean getEnablePastCATime() {
        return enablePastCATime;
    }

    /**
     * Is this CA allowed to issue CA certificate that have
     * validty past the CA's own validity.
     *
     * @return true if allows CA certificates to have validity longer than CA's
     */
    public boolean getEnablePastCATime_caCert() {
        return enablePastCATime_caCert;
    }

    public boolean getEnableOCSP() {
        return enableOCSP;
    }

    /**
     * Allows certificates to have validities that are longer
     * than this certificate authority's.
     *
     * @param enablePastCATime if equals "true", it allows certificates
     *            to have validity longer than CA's certificate validity
     */
    public void setEnablePastCATime(String enablePastCATime) {
        this.enablePastCATime = enablePastCATime.equals("true");
    }

    public int getFastSigning() {
        return fastSigning;
    }

    public boolean getAllowExtCASignedAgentCerts() {
        return allowExtCASignedAgentCerts;
    }

    public boolean getEnableNonces() {
        return enableNonces;
    }

    public int getMaxNonces() {
        return maxNonces;
    }

    public boolean getOCSPResponderByName() {
        return ocspResponderByName;
    }

    public CRLPublisher getCRLPublisher() {
        return crlPublisher;
    }

    /**
     * Retrieves the publishing processor of this certificate authority.
     *
     * @return CA's publishing processor
     */
    public CAPublisherProcessor getPublisherProcessor() {
        return publisherProcessor;
    }

    public Collection<CRLIssuingPoint> getCRLIssuingPoints() {
        return crlIssuingPoints.values();
    }

    public CRLIssuingPoint getMasterCRLIssuingPoint() {
        return crlIssuingPoints.get(CertificateAuthority.PROP_MASTER_CRL);
    }

    /**
     * Retrieves the CRL issuing point by id.
     * <P>
     *
     * @param id string id of the CRL issuing point
     * @return CRL issuing point
     */
    public CRLIssuingPoint getCRLIssuingPoint(String id) {
        return crlIssuingPoints.get(id);
    }

    public void addCRLIssuingPoint(String id, CRLIssuingPoint crlIssuingPoint) {
        crlIssuingPoints.put(id, crlIssuingPoint);
    }

    public CRLIssuingPoint removeCRLIssuingPoint(String id) {
        return crlIssuingPoints.remove(id);
    }

    /**
     * Get Issuance Protection Certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getIssuanceProtectionCert() {
        return issuanceProtectionCert;
    }

    /**
     * Get Issuance Protection Public Key
     */
    public PublicKey getIssuanceProtectionPublicKey() {
        return issuanceProtectionPublicKey;
    }

    /**
     * Get Issuance Protection Private Key
     */
    public PrivateKey getIssuanceProtectionPrivateKey() {
        return issuanceProtectionPrivateKey;
    }

    /**
     * Retrieves the request listener for issued certificates.
     *
     * @return the request listener for issued certificates
     */
    public RequestListener getCertIssuedListener() {
        return certIssuedListener;
    }

    /**
     * Retrieves the request listener for revoked certificates.
     *
     * @return the request listener for revoked certificates
     */
    public RequestListener getCertRevokedListener() {
        return certRevokedListener;
    }

    /**
     * Retrieves the request in queue listener.
     *
     * @return the request in queue listener
     */
    public RequestListener getRequestInQueueListener() {
        return requestInQueueListener;
    }

    public AsyncLoader getLoader() {
        return loader;
    }

    public LdapBoundConnFactory getConnectionFactory() {
        return connectionFactory;
    }

    public void initAuthSubsystem() throws Exception {
        AuthenticationConfig authConfig = config.getAuthenticationConfig();
        authSubsystem = new CAAuthSubsystem();
        authSubsystem.setCMSEngine(this);
        authSubsystem.init(authConfig);
        authSubsystem.startup();
    }

    public void initListeners() throws Exception {

        logger.info("CAEngine: Initializing CA listeners");

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore listenersConfig = caConfig.getSubStore(CertificateAuthority.PROP_LISTENER_SUBSTORE, ConfigStore.class);
        if (listenersConfig == null) return;

        logger.info("CAEngine: Loading listener plugins");

        ConfigStore pluginsConfig = listenersConfig.getSubStore(CertificateAuthority.PROP_IMPL, ConfigStore.class);
        Enumeration<String> pluginNames = pluginsConfig.getSubStoreNames().elements();

        while (pluginNames.hasMoreElements()) {
            String id = pluginNames.nextElement();
            String listenerClassName = pluginsConfig.getString(id + "." + CertificateAuthority.PROP_CLASS);
            logger.info("CAEngine: - " + id + ": " + listenerClassName);

            ListenerPlugin plugin = new ListenerPlugin(id, listenerClassName);
            listenerPlugins.put(id, plugin);
        }

        logger.info("CAEngine: Creating listener instances");

        ConfigStore instancesConfig = listenersConfig.getSubStore(CertificateAuthority.PROP_INSTANCE, ConfigStore.class);
        Enumeration<String> instanceNames = instancesConfig.getSubStoreNames().elements();

        while (instanceNames.hasMoreElements()) {
            String id = instanceNames.nextElement();

            ConfigStore instanceConfig = instancesConfig.getSubStore(id, ConfigStore.class);
            String pluginName = instancesConfig.getString(id + "." + CertificateAuthority.PROP_PLUGIN);
            logger.info("CAEngine: - " + id + ": " + pluginName);

            ListenerPlugin plugin = listenerPlugins.get(pluginName);

            if (plugin == null) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_CA_ERROR_LISTENER", pluginName));
                throw new Exception("Invalid plugin name for " + id + " listener: " + pluginName);
            }

            String className = plugin.getClassPath();
            RequestListener listener = (RequestListener) Class.forName(className).getDeclaredConstructor().newInstance();

            listener.setCMSEngine(this);
            // listener.init(id, pluginName, instanceConfig);
            listener.init(hostCA, instanceConfig);
            // registerRequestListener(id, (IRequestListener) listener);
        }
    }

    public void initCRLPublisher() throws Exception {

        logger.info("CAEngine: Initializing CRL publisher");

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore crlPublisherConfig = caConfig.getSubStore("crlPublisher", ConfigStore.class);
        if (crlPublisherConfig == null || crlPublisherConfig.size() == 0) {
            return;
        }

        String className = crlPublisherConfig.getString("class");
        if (className == null) {
            return;
        }

        logger.info("CAEngine: - class: " + className);

        Class<CRLPublisher> publisherClass = (Class<CRLPublisher>) Class.forName(className);
        crlPublisher = publisherClass.getDeclaredConstructor().newInstance();
        crlPublisher.init(hostCA, crlPublisherConfig);
    }

    public void initPublisherProcessor() throws Exception {

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        PublishingConfig publishingConfig = caConfig.getPublishingConfig();
        if (publishingConfig == null || publishingConfig.size() == 0) {
            logger.info("CAEngine: Publisher processor disabled");
            return;
        }

        logger.info("CAEngine: Initializing publisher processor");

        CertificateAuthority hostCA = getCA();

        publisherProcessor = new CAPublisherProcessor(CertificateAuthority.ID + "pp");

        if (publishingConfig.isEnabled()) {
            LdapRequestListener listener = new LdapRequestListener();
            listener.setPublisherProcessor(publisherProcessor);
            publisherProcessor.setRequestListener(listener);
        }

        publisherProcessor.init(hostCA, publishingConfig);
    }

    public void initCRLIssuingPoints() throws Exception {

        logger.info("CAEngine: Initializing CRL issuing points");
        // note CRL framework depends on DBS, CRYPTO and PUBLISHING
        // being functional.

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        CRLConfig crlConfig = caConfig.getCRLConfig();

        if (crlConfig == null || crlConfig.size() <= 0) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_NO_MASTER_CRL"));
            // throw new ECAException(CAResources.NO_CONFIG_FOR_MASTER_CRL);
            return;
        }

        Enumeration<String> ipIDs = crlConfig.getSubStoreNames().elements();

        if (ipIDs == null || !ipIDs.hasMoreElements()) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_NO_MASTER_CRL_SUBSTORE"));
            // throw new ECAException(CAResources.NO_CONFIG_FOR_MASTER_CRL);
            return;
        }

        CertificateAuthority hostCA = getCA();

        while (ipIDs.hasMoreElements()) {
            String id = ipIDs.nextElement();
            logger.info("CAEngine: - " + id);

            CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(id);
            String className = ipConfig.getClassName();
            Class<CRLIssuingPoint> clazz = (Class<CRLIssuingPoint>) Class.forName(className);

            CRLIssuingPoint issuingPoint = clazz.getDeclaredConstructor().newInstance();
            issuingPoint.init(hostCA, id, ipConfig);

            crlIssuingPoints.put(id, issuingPoint);
        }
    }

    /**
     * Sets the CA Issuance Protection cert
     */
    public void initIssuanceProtectionCert() throws Exception {

        logger.info("CAEngine: Initializing CA issuance protection cert");

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        String certNickName = caConfig.getString("cert.issuance_protection.nickname", null);
        logger.info("CAEngine: - cert.issuance_protection.nickname: " + certNickName);

        if (certNickName == null) {
            certNickName = caConfig.getString("cert.subsystem.nickname");
            logger.info("CAEngine: - cert.subsystem.nickname: " + certNickName);
        }

        CryptoManager cm = CryptoManager.getInstance();
        issuanceProtectionCert = cm.findCertByNickname(certNickName);

        logger.info("CAEngine: Loading public and private keys for " + certNickName);
        issuanceProtectionPublicKey = issuanceProtectionCert.getPublicKey();
        issuanceProtectionPrivateKey = cm.findPrivKeyByCert(issuanceProtectionCert);
    }

    public void initAuthorityMonitor() throws Exception {

        if (!(enableAuthorityMonitor && haveAuthorityContainer())) {
            return;
        }

        CertificateAuthority hostCA = getCA();

        authorityMonitor = new AuthorityMonitor();
        new Thread(authorityMonitor, "AuthorityMonitor").start();

        try {
            logger.info("CAEngine: Waiting for authorities to load");
            // block until the expected number of authorities
            // have been loaded (based on numSubordinates of
            // container entry), or watchdog times it out (in case
            // numSubordinates is larger than the number of entries
            // we can see, e.g. replication conflict entries).
            loader.awaitLoadDone();

        } catch (InterruptedException e) {
            logger.warn("CAEngine: Caught InterruptedException "
                    + "while waiting for initial load of authorities.");
            logger.warn("CAEngine: You may have replication conflict entries or "
                    + "extraneous data under " + getAuthorityBaseDN());
        }

        if (!foundHostCA) {
            logger.debug("CAEngine: No entry for host authority");
            logger.debug("CAEngine: Adding entry for host authority");
            addCA(addHostAuthorityEntry(), hostCA);
        }
    }

    public void initCertIssuedListener() throws Exception {

        logger.info("CAEngine: Initializing certificate issued listener");

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore listenerConfig = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        if (listenerConfig == null || listenerConfig.size() == 0) {
            return;
        }

        String className = listenerConfig.getString(
                "certificateIssuedListenerClassName",
                "com.netscape.cms.listeners.CertificateIssuedListener");

        certIssuedListener = (RequestListener) Class.forName(className).getDeclaredConstructor().newInstance();
        certIssuedListener.setCMSEngine(this);
        certIssuedListener.init(hostCA, listenerConfig);
    }

    public void initCertRevokedListener() throws Exception {

        logger.info("CAEngine: Initializing cert revoked listener");

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore listenerConfig = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        if (listenerConfig == null || listenerConfig.size() == 0) {
            return;
        }

        String className = listenerConfig.getString(
                "certificateIssuedListenerClassName",
                "com.netscape.cms.listeners.CertificateRevokedListener");

        certRevokedListener = (RequestListener) Class.forName(className).getDeclaredConstructor().newInstance();
        certRevokedListener.setCMSEngine(this);
        certRevokedListener.init(hostCA, listenerConfig);
    }

    public void initRequestInQueueListener() throws Exception {

        logger.info("CAEngine: Initializing request in queue listener");

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore listenerConfig = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        if (listenerConfig == null || listenerConfig.size() == 0) {
            return;
        }

        String className = listenerConfig.getString(
                "certificateIssuedListenerClassName",
                "com.netscape.cms.listeners.RequestInQListener");

        requestInQueueListener = (RequestListener) Class.forName(className).getDeclaredConstructor().newInstance();
        requestInQueueListener.setCMSEngine(this);
        requestInQueueListener.init(hostCA, listenerConfig);
    }

    public void startCertStatusUpdate() throws Exception {

        logger.info("CAEngine: Cert status update task:");

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        int interval = caConfig.getInteger("certStatusUpdateInterval", 10 * 60);
        logger.info("CAEngine: - interval: " + interval + " seconds");

        boolean listenToCloneModifications = caConfig.getBoolean("listenToCloneModifications", false);
        logger.info("CAEngine: - listen to clone modification: " + listenToCloneModifications);

        int pageSize = caConfig.getInteger(CertificateRepository.PROP_TRANS_PAGESIZE, 200);
        logger.info("CAEngine: - page size: " + pageSize);

        int maxRecords = caConfig.getInteger(CertificateRepository.PROP_TRANS_MAXRECORDS, 1000000);
        logger.info("CAEngine: - max records: " + maxRecords);

        if (certStatusUpdateTask != null) {
            certStatusUpdateTask.stop();
        }

        if (retrieveModificationsTask != null) {
            retrieveModificationsTask.stop();
        }

        if (interval == 0) {
            logger.info("CAEngine: Cert status update task is disabled");
            return;
        }

        if (listenToCloneModifications) {
            logger.info("CAEngine: Starting retrieve modifications task");
            retrieveModificationsTask = new RetrieveModificationsTask(certificateRepository);
            retrieveModificationsTask.start();
        }

        logger.info("CAEngine: Starting cert status update task");
        certStatusUpdateTask = new CertStatusUpdateTask(
                certificateRepository,
                interval,
                pageSize,
                maxRecords);
        certStatusUpdateTask.start();
    }

    public void startSerialNumberUpdateTask() throws Exception {

        logger.info("CAEngine: Serial number update task:");

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        int interval = caConfig.getInteger("serialNumberUpdateInterval", 10 * 60);
        logger.info("CAEngine: - interval: " + interval + " seconds");

        if (serialNumberUpdateTask != null) {
            serialNumberUpdateTask.stop();
        }

        if (interval <= 0) {
            logger.info("CAEngine: Serial number update task is disabled");
            return;
        }

        logger.info("CAEngine: Starting serial number update task");

        serialNumberUpdateTask = new SerialNumberUpdateTask(
                certificateRepository,
                requestRepository,
                interval);
        serialNumberUpdateTask.start();
    }

    @Override
    public void initSubsystems() throws Exception {

        CertificateAuthority hostCA = getCA();

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        logger.info("CAEngine: Loading CA configuration");

        int certVersion = caConfig.getInteger(CertificateAuthority.PROP_X509CERT_VERSION, CertificateVersion.V3);
        if (certVersion != CertificateVersion.V1 && certVersion != CertificateVersion.V3) {
            throw new ECAException(CMS.getUserMessage("CMS_CA_X509CERT_VERSION_NOT_SUPPORTED"));
        }

        defaultCertVersion = new CertificateVersion(certVersion - 1);
        logger.info("CAEngine: - default cert version: " + defaultCertVersion);

        int certValidity = caConfig.getInteger(CertificateAuthority.PROP_DEF_VALIDITY, 2 * 365);
        defaultCertValidity = certValidity * CertificateAuthority.DAY; // in milliseconds
        logger.info("CAEngine: - default cert validity (days): " + certValidity);

        enablePastCATime = caConfig.getBoolean(CertificateAuthority.PROP_ENABLE_PAST_CATIME, false);
        logger.info("CAEngine: - enable past CA time: " + enablePastCATime);

        enablePastCATime_caCert = caConfig.getBoolean(CertificateAuthority.PROP_ENABLE_PAST_CATIME_CACERT, false);
        logger.info("CAEngine: - enable past CA time for CA certs: " + enablePastCATime_caCert);

        enableOCSP = caConfig.getBoolean(CertificateAuthority.PROP_ENABLE_OCSP, true);

        String fastSigning = caConfig.getString(CertificateAuthority.PROP_FAST_SIGNING, "");
        logger.info("CAEngine: - fast signing: " + fastSigning);

        if (fastSigning.equals("enabled") || fastSigning.equals("enable")) {
            this.fastSigning = CertificateAuthority.FASTSIGNING_ENABLED;
        } else {
            this.fastSigning = CertificateAuthority.FASTSIGNING_DISABLED;
        }

        allowExtCASignedAgentCerts = caConfig.getBoolean("allowExtCASignedAgentCerts", false);
        logger.info("CAEngine: - allowExtCASignedAgentCerts: " + allowExtCASignedAgentCerts);

        enableNonces = caConfig.getBoolean("enableNonces", true);
        logger.info("CAEngine: - enable nonces: " + enableNonces);

        maxNonces = caConfig.getInteger("maxNumberOfNonces", 100);
        logger.info("CAEngine: - max nonces: " + maxNonces);

        logger.info("CAEngine: Initializing CA policy");
        ConfigStore caPolicyConfig = caConfig.getSubStore(CertificateAuthority.PROP_POLICY, ConfigStore.class);
        caPolicy = new CAPolicy();
        caPolicy.init(hostCA, caPolicyConfig);

        logger.info("CAEngine: Initializing CA service");
        caService = new CAService(hostCA);

        logger.info("CAEngine: Initializing CA request notifier");
        requestNotifier = new CANotify();
        requestNotifier.setCMSEngine(this);

        logger.info("CAEngine: Initializing CA pending request notifier");
        pendingNotifier = new RequestNotifier();
        pendingNotifier.setCMSEngine(this);

        logger.info("CAEngine: Initializing CA request queue");

        int increment = caConfig.getInteger("reqdbInc", 5);
        logger.info("CAEngine: - increment: " + increment);

        String schedulerClass = caConfig.getString("requestSchedulerClass", null);
        logger.info("CAEngine: - scheduler: " + schedulerClass);

        enableAuthorityMonitor = caConfig.getBoolean("authorityMonitor.enable", enableAuthorityMonitor);
        logger.info("CAEngine: - enable AuthorityMonitor: " + enableAuthorityMonitor);

        SecureRandom secureRandom = getJSSSubsystem().getRandomNumberGenerator();

        requestRepository = new CertRequestRepository(secureRandom, dbSubsystem);
        requestRepository.setCMSEngine(this);
        requestRepository.init();

        requestQueue = new RequestQueue(
                dbSubsystem,
                requestRepository,
                caPolicy,
                caService,
                requestNotifier,
                pendingNotifier);

        if (schedulerClass != null) {
            RequestScheduler scheduler = (RequestScheduler) Class.forName(schedulerClass).getDeclaredConstructor().newInstance();
            requestQueue.setRequestScheduler(scheduler);
        }

        if (!isPreOpMode()) {
            logger.info("CAEngine: Starting CA services");

            startCertStatusUpdate();

            boolean consistencyCheck = caConfig.getBoolean("ConsistencyCheck", false);
            logger.info("CAEngine: - consistency check: " + consistencyCheck);

            certificateRepository.setConsistencyCheck(consistencyCheck);

            startSerialNumberUpdateTask();

            ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
            caService.init(connectorsConfig);

            initListeners();

            logger.info("CAEngine: Configuring OCSP responder");

            ocspResponderByName = caConfig.getBoolean("byName", true);
            logger.info("CAEngine: - by name: " + ocspResponderByName);

            initCRLPublisher();
            initPublisherProcessor();
        }

        super.initSubsystems();
    }

    @Override
    public void initSubsystem(Subsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof CertificateAuthority || subsystem instanceof CrossCertPairSubsystem) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);

        if (subsystem instanceof CertificateAuthority) {
            initCRLIssuingPoints();
            initIssuanceProtectionCert();
            initAuthorityMonitor();

        }
    }

    public X509Certificate[] getCertChain(X509Certificate cert) throws Exception {

        CertificateAuthority ca = getCA();
        CertificateChain caChain = ca.getCACertChain();
        X509Certificate[] caCerts = caChain.getChain();

        if (CertUtils.certInCertChain(caCerts, cert)) {
            return Arrays.copyOf(caCerts, caCerts.length);
        }

        X509Certificate[] certChain = new X509Certificate[caCerts.length + 1];
        certChain[0] = cert;
        System.arraycopy(caCerts, 0, certChain, 1, caCerts.length);

        return certChain;
    }

    public void startPublisherProcessor() throws Exception {

        // Note that CMS411 only support ca cert publishing to ldap.
        // If ldap publishing is not enabled while publishing isenabled
        // there will be a lot of problem.

        if (!publisherProcessor.isCertPublishingEnabled()) {
            logger.info("CertificateAuthority: Publisher processor disabled");
            return;
        }

        logger.info("CertificateAuthority: Starting publisher processor");

        CertificateAuthority hostCA = getCA();
        publisherProcessor.publishCACert(hostCA.getCACert());
    }

    @Override
    public void startupSubsystems() throws Exception {

        if (!isPreOpMode()) {

            caService.startup();
            recoverRequestQueue();

            startPublisherProcessor();
            initCertIssuedListener();
            initCertRevokedListener();
            initRequestInQueueListener();
        }

        super.startupSubsystems();

        if (!isPreOpMode()) {
            logger.debug("CAEngine: Checking cert request serial number ranges");
            requestRepository.checkRanges();

            logger.debug("CAEngine: Checking cert serial number ranges");
            certificateRepository.checkRanges();
        }
    }

    public boolean haveAuthorityContainer() throws EBaseException {

        LDAPConnection conn = null;

        try {
            conn = connectionFactory.getConn(true);
            LDAPSearchResults results = conn.search(
                    getAuthorityBaseDN(),
                    LDAPConnection.SCOPE_BASE,
                    null,
                    null,
                    false);
            return results != null;

        } catch (LDAPException e) {
            return false;

        } finally {
            connectionFactory.returnConn(conn);
        }
    }

    /**
     * Returns the main/host CA.
     */
    public CertificateAuthority getCA() {
        return (CertificateAuthority) getSubsystem(CertificateAuthority.ID);
    }

    /**
     * Enumerate all authorities (including host authority)
     */
    public List<CertificateAuthority> getCAs() {
        List<CertificateAuthority> list = new ArrayList<>();
        synchronized (authorities) {
            list.addAll(authorities.values());
        }
        return list;
    }

    /**
     * Get authority by ID.
     *
     * @param aid The ID of the CA to retrieve, or null
     *             to retreive the host authority.
     *
     * @return the authority, or null if not found
     */
    public CertificateAuthority getCA(AuthorityID aid) {
        return aid == null ? getCA() : authorities.get(aid);
    }

    public CertificateAuthority getCA(X500Name dn) {

        for (CertificateAuthority ca : getCAs()) {
            if (ca.getX500Name().equals(dn))
                return ca;
        }

        return null;
    }

    public void addCA(AuthorityID aid, CertificateAuthority ca) {
        authorities.put(aid, ca);
    }

    public void removeCA(AuthorityID aid) {
        authorities.remove(aid);
        entryUSNs.remove(aid);
        nsUniqueIds.remove(aid);
    }

    public void ensureAuthorityDNAvailable(X500Name dn)
            throws IssuerUnavailableException {

        for (CertificateAuthority ca : getCAs()) {
            if (ca.getX500Name().equals(dn))
                throw new IssuerUnavailableException(
                    "DN '" + dn + "' is used by an existing authority");
        }
    }

    /**
     * Create a CA signed by a parent CA.
     *
     * This method DOES NOT add the new CA to CAEngine; it is the
     * caller's responsibility.
     */
    public CertificateAuthority createCA(
            CertificateAuthority parentCA,
            AuthToken authToken,
            String subjectDN,
            String description)
            throws Exception {

        parentCA.ensureReady();

        // check requested DN
        X500Name subjectX500Name = new X500Name(subjectDN);
        ensureAuthorityDNAvailable(subjectX500Name);

        // generate authority ID and nickname
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();
        logger.info("CAEngine: Creating authority " + aidString);

        CertificateAuthority hostCA = getCA();
        String nickname = hostCA.getNickname() + " " + aidString;
        logger.info("CAEngine: - nickname: " + nickname);

        // build database entry
        String dn = "cn=" + aidString + "," + getAuthorityBaseDN();
        logger.info("CAEngine: - authority record: " + dn);

        String parentDNString = parentCA.getX500Name().toLdapDNString();

        String keyHost = mConfig.getHostname() + ":" + getEESSLPort();
        logger.info("CAEngine: - key host: " + keyHost);

        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", nickname),
            new LDAPAttribute("authorityKeyHost", keyHost),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", subjectDN),
            new LDAPAttribute("authorityParentDN", parentDNString)
        };

        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        if (parentCA.getAuthorityID() != null) {
            attrSet.add(new LDAPAttribute("authorityParentID", parentCA.getAuthorityID().toString()));
        }

        if (description != null) {
            logger.info("CAEngine: - description: " + description);
            attrSet.add(new LDAPAttribute("description", description));
        }

        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);
        addAuthorityEntry(aid, ldapEntry);

        X509CertImpl cert = null;

        try {
            logger.info("CAEngine: Generating signing certificate");
            cert = parentCA.generateSigningCert(subjectX500Name, authToken);

            logger.info("CAEngine: Importing signing certificate into NSS database");
            CryptoManager cryptoManager = CryptoManager.getInstance();
            cryptoManager.importCertPackage(cert.getEncoded(), nickname);

        } catch (Exception e) {
            logger.error("Unable to generate signing certificate: " + e.getMessage(), e);

            // something went wrong; delete just-added entry
            deleteAuthorityEntry(aid);

            throw e;
        }

        CertificateAuthority ca = new CertificateAuthority(
            subjectX500Name,
            aid,
            parentCA.getAuthorityID(),
            cert.getSerialNumber(),
            nickname,
            Collections.singleton(keyHost),
            description,
            true);

        CAEngineConfig engineConfig = getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        ca.setCMSEngine(this);
        ca.init(caConfig);

        updateAuthoritySerialNumber(aid, cert.getSerialNumber());

        return ca;
    }

    /**
     * Create a new certificate authority.
     *
     * @param subjectDN Subject DN for new CA
     * @param parentAID ID of parent CA
     * @param description Optional string description of CA
     */
    public CertificateAuthority createCA(
            AuthorityID parentAID,
            AuthToken authToken,
            String subjectDN,
            String description)
            throws Exception {

        CertificateAuthority parentCA = getCA(parentAID);

        if (parentCA == null) {
            throw new CANotFoundException("Parent CA \"" + parentAID + "\" does not exist");
        }

        CertificateAuthority ca = createCA(parentCA, authToken, subjectDN, description);
        authorities.put(ca.getAuthorityID(), ca);

        return ca;
    }

    public void startKeyRetriever(CertificateAuthority ca) throws EBaseException {

        AuthorityID authorityID = ca.getAuthorityID();

        if (authorityID == null) {
            // Only the host authority should ever see a
            // null authorityID, e.g. during two-step
            // installation of externally-signed CA.
            logger.info("CertificateAuthority: Do not start KeyRetriever for host CA");
            return;
        }

        if (keyRetrievers.containsKey(authorityID)) {
            logger.info("CertificateAuthority: KeyRetriever already running for authority " + authorityID);
            return;
        }

        logger.info("CertificateAuthority: Starting KeyRetriever for authority " + authorityID);

        CAEngineConfig engineConfig = getConfig();

        String className = engineConfig.getString("features.authority.keyRetrieverClass", null);
        if (className == null) {
            logger.info("CertificateAuthority: Key retriever not configured");
            return;
        }

        ConfigStore keyRetrieverConfig = engineConfig.getSubStore("features.authority.keyRetrieverConfig", ConfigStore.class);

        KeyRetriever keyRetriever;
        try {
            Class<? extends KeyRetriever> clazz = Class.forName(className).asSubclass(KeyRetriever.class);

            // If there is an accessible constructor that takes
            // a ConfigStore, invoke that; otherwise invoke
            // the nullary constructor.

            try {
                keyRetriever = clazz.getDeclaredConstructor(ConfigStore.class).newInstance(keyRetrieverConfig);

            } catch (NoSuchMethodException | SecurityException | IllegalAccessException e) {
                keyRetriever = clazz.getDeclaredConstructor().newInstance();
            }

        } catch (Exception e) {
            logger.error("Unable to create key retriever: " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        KeyRetrieverRunner runner = new KeyRetrieverRunner(keyRetriever, ca);
        Thread thread = new Thread(runner, "KeyRetriever-" + authorityID);
        thread.start();

        keyRetrievers.put(authorityID, thread);
    }

    public void removeKeyRetriever(AuthorityID aid) {
        keyRetrievers.remove(aid);
    }

    public String getAuthorityBaseDN() {
        return "ou=authorities,ou=" + id + "," + dbSubsystem.getBaseDN();
    }

    public boolean entryUSNPluginEnabled() throws Exception {

        LDAPConnection conn = connectionFactory.getConn();

        try {
            LDAPSearchResults results = conn.search(
                    "cn=usn,cn=plugins,cn=config",
                    LDAPConnection.SCOPE_BASE,
                    "(nsslapd-pluginEnabled=on)",
                    null,
                    false);

            return results != null && results.hasMoreElements();

        } catch (LDAPException e) {
            return false;

        } finally {
            connectionFactory.returnConn(conn);
        }
    }

    public LDAPConstraints getUpdateConstraints() {
        String[] attrs = {"entryUSN", "nsUniqueId"};
        LDAPConstraints cons = new LDAPConstraints();
        LDAPPostReadControl control = new LDAPPostReadControl(true, attrs);
        cons.setServerControls(control);
        return cons;
    }

    public synchronized void trackUpdate(AuthorityID aid, LDAPControl[] responseControls) {

        LDAPPostReadControl control = (LDAPPostReadControl)
            LDAPUtil.getControl(LDAPPostReadControl.class, responseControls);

        LDAPEntry entry = control.getEntry();

        LDAPAttribute attr = entry.getAttribute("entryUSN");
        if (attr != null) {
            BigInteger entryUSN = new BigInteger(attr.getStringValueArray()[0]);
            logger.debug("CAEngine: tracking entryUSN: " + entryUSN);
            entryUSNs.put(aid, entryUSN);
        }

        attr = entry.getAttribute("nsUniqueId");
        if (attr != null) {
            String nsUniqueId = attr.getStringValueArray()[0];
            logger.info("CAEngine: tracking nsUniqueId: " + nsUniqueId);
            nsUniqueIds.put(aid, nsUniqueId);
        }
    }

    public synchronized void addAuthorityEntry(AuthorityID aid, LDAPEntry entry) throws EBaseException {

        LDAPConnection conn = connectionFactory.getConn();
        LDAPControl[] responseControls;

        try {
            conn.add(entry, getUpdateConstraints());
            responseControls = conn.getResponseControls();

        } catch (LDAPException e) {
            throw new ELdapException("Unable to add authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        trackUpdate(aid, responseControls);
    }

    public synchronized void modifyAuthorityEntry(AuthorityID aid, LDAPModificationSet mods) throws EBaseException {

        String dn = "cn=" + aid + "," + getAuthorityBaseDN();
        LDAPConnection conn = connectionFactory.getConn();
        LDAPControl[] responseControls;

        try {
            conn.modify(dn, mods, getUpdateConstraints());
            responseControls = conn.getResponseControls();

        } catch (LDAPException e) {
            throw new ELdapException("Unable to modify authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        trackUpdate(aid, responseControls);
    }

    public synchronized void deleteAuthorityEntry(AuthorityID aid) throws EBaseException {

        String dn = "cn=" + aid + "," + getAuthorityBaseDN();
        LDAPConnection conn = connectionFactory.getConn();

        try {
            conn.delete(dn);

        } catch (LDAPException e) {
            throw new ELdapException("Unable to delete authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        String nsUniqueId = nsUniqueIds.get(aid);
        if (nsUniqueId != null) {
            deletedNsUniqueIds.add(nsUniqueId);
        }

        removeCA(aid);
    }

    public synchronized void readAuthority(LDAPEntry entry) throws Exception {

        CertificateAuthority hostCA = getCA();

        String nsUniqueId = entry.getAttribute("nsUniqueId").getStringValueArray()[0];
        if (deletedNsUniqueIds.contains(nsUniqueId)) {
            logger.warn("CAEngine: ignoring entry with nsUniqueId '"
                    + nsUniqueId + "' due to deletion");
            return;
        }

        logger.info("CAEngine: Loading authority record " + entry.getDN());

        LDAPAttribute aidAttr = entry.getAttribute("authorityID");
        LDAPAttribute nickAttr = entry.getAttribute("authorityKeyNickname");
        LDAPAttribute keyHostsAttr = entry.getAttribute("authorityKeyHost");
        LDAPAttribute dnAttr = entry.getAttribute("authorityDN");
        LDAPAttribute parentAIDAttr = entry.getAttribute("authorityParentID");
        LDAPAttribute parentDNAttr = entry.getAttribute("authorityParentDN");
        LDAPAttribute serialAttr = entry.getAttribute("authoritySerial");

        if (aidAttr == null || nickAttr == null || dnAttr == null) {
            logger.warn("Malformed authority object; required attribute(s) missing: " + entry.getDN());
            return;
        }

        AuthorityID aid = new AuthorityID(aidAttr.getStringValues().nextElement());

        X500Name dn = null;
        try {
            dn = new X500Name(dnAttr.getStringValues().nextElement());
        } catch (IOException e) {
            logger.warn("Malformed authority object; invalid authorityDN: " + entry.getDN() + ": " + e.getMessage(), e);
        }

        String desc = null;
        LDAPAttribute descAttr = entry.getAttribute("description");
        if (descAttr != null) {
            desc = descAttr.getStringValues().nextElement();
        }

        // Determine if it is the host authority's entry, by
        // comparing DNs.  DNs must be serialized in case different
        // encodings are used for AVA values, e.g. PrintableString
        // from LDAP vs UTF8String in certificate.

        if (dn.toString().equals(hostCA.getX500Name().toString())) {
            logger.info("CAEngine: Updating host CA");
            foundHostCA = true;

            logger.info("CAEngine: - ID: " + aid);
            hostCA.setAuthorityID(aid);

            logger.info("CAEngine: - description: " + desc);
            hostCA.setAuthorityDescription(desc);

            addCA(aid, hostCA);

            return;
        }

        BigInteger newEntryUSN = null;
        LDAPAttribute entryUSNAttr = entry.getAttribute("entryUSN");

        if (entryUSNAttr == null) {
            logger.debug("CAEngine: no entryUSN");
            if (!entryUSNPluginEnabled()) {
                logger.warn("CAEngine: dirsrv USN plugin is not enabled; skipping entry");
                logger.warn("Lightweight authority entry has no"
                        + " entryUSN attribute and USN plugin not enabled;"
                        + " skipping.  Enable dirsrv USN plugin.");
                return;

            }
            logger.debug("CAEngine: dirsrv USN plugin is enabled; continuing");
            // entryUSN plugin is enabled, but no entryUSN attribute. We
            // can proceed because future modifications will result in the
            // entryUSN attribute being added.

        } else {
            newEntryUSN = new BigInteger(entryUSNAttr.getStringValueArray()[0]);
            logger.debug("CAEngine: new entryUSN: " + newEntryUSN);
        }

        BigInteger knownEntryUSN = entryUSNs.get(aid);
        if (newEntryUSN != null && knownEntryUSN != null) {
            logger.debug("CAEngine: known entryUSN: " + knownEntryUSN);
            if (newEntryUSN.compareTo(knownEntryUSN) <= 0) {
                logger.debug("CAEngine: data is current");
                return;
            }
        }

        @SuppressWarnings("unused")
        X500Name parentDN = null;
        if (parentDNAttr != null) {
            try {
                parentDN = new X500Name(parentDNAttr.getStringValues().nextElement());
            } catch (IOException e) {
                logger.warn("Malformed authority object; invalid authorityParentDN: " + entry.getDN() + ": " + e.getMessage(), e);
                return;
            }
        }

        String keyNick = nickAttr.getStringValues().nextElement();

        Collection<String> keyHosts;
        if (keyHostsAttr == null) {
            keyHosts = Collections.emptyList();
        } else {
            Enumeration<String> keyHostsEnum = keyHostsAttr.getStringValues();
            keyHosts = Collections.list(keyHostsEnum);
        }

        AuthorityID parentAID = null;
        if (parentAIDAttr != null) {
            parentAID = new AuthorityID(parentAIDAttr.getStringValues().nextElement());
        }

        BigInteger serial = null;
        if (serialAttr != null) {
            serial = new BigInteger(serialAttr.getStringValueArray()[0]);
        }

        boolean enabled = true;
        LDAPAttribute enabledAttr = entry.getAttribute("authorityEnabled");
        if (enabledAttr != null) {
            String enabledString = enabledAttr.getStringValues().nextElement();
            enabled = enabledString.equalsIgnoreCase("TRUE");
        }

        try {
            CertificateAuthority ca = new CertificateAuthority(
                dn, aid, parentAID, serial,
                keyNick, keyHosts, desc, enabled);

            CAEngineConfig engineConfig = getConfig();
            CAConfig caConfig = engineConfig.getCAConfig();
            ca.setCMSEngine(this);
            ca.init(caConfig);

            addCA(aid, ca);
            entryUSNs.put(aid, newEntryUSN);
            nsUniqueIds.put(aid, nsUniqueId);

        } catch (Exception e) {
            logger.warn("CAEngine: Error initializing lightweight CA: " + e.getMessage(), e);
        }
    }

    /**
     * Add an LDAP entry for the host authority.
     *
     * This method also sets the authorityID and authorityDescription
     * fields.
     *
     * It is the caller's responsibility to add the returned
     * AuthorityID to the CAEngine.
     */
    public AuthorityID addHostAuthorityEntry() throws EBaseException {

        CertificateAuthority hostCA = getCA();

        // generate authority ID
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();

        // build database entry
        String dn = "cn=" + aidString + "," + getAuthorityBaseDN();
        String dnString = null;
        try {
            dnString = hostCA.getX500Name().toLdapDNString();

        } catch (IOException e) {
            throw new EBaseException("Unable to convert issuer DN to string: " + e.getMessage(), e);
        }

        String desc = "Host authority";
        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", hostCA.getNickname()),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", dnString),
            new LDAPAttribute("description", desc)
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);

        addAuthorityEntry(aid, ldapEntry);

        hostCA.setAuthorityID(aid);
        hostCA.setAuthorityDescription(desc);

        return aid;
    }

    public void updateAuthoritySerialNumber(AuthorityID aid, BigInteger serialNumber) throws Exception {

        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(LDAPModification.REPLACE, new LDAPAttribute(
                "authoritySerial",
                serialNumber.toString()));

        modifyAuthorityEntry(aid, mods);
    }

    /**
     * Update authority attributes.
     *
     * Pass null values to exclude an attribute from the update.
     *
     * If a passed value matches the current value, it is excluded
     * from the update.
     *
     * To remove optional string values, pass the empty string.
     *
     * @param enabled Whether CA is enabled or disabled
     * @param desc Description; null or empty removes it
     */
    public void modifyAuthority(
            CertificateAuthority ca,
            Boolean enabled,
            String desc) throws EBaseException {

        CertificateAuthority hostCA = getCA();

        if (ca == hostCA && enabled != null && !enabled) {
            throw new CATypeException("Cannot disable the host CA");
        }

        LDAPModificationSet mods = new LDAPModificationSet();

        boolean nextEnabled = ca.getAuthorityEnabled();
        if (enabled != null && enabled.booleanValue() != ca.getAuthorityEnabled()) {
            mods.add(LDAPModification.REPLACE,
                    new LDAPAttribute("authorityEnabled", enabled ? "TRUE" : "FALSE"));
            nextEnabled = enabled;
        }

        String nextDesc = ca.getAuthorityDescription();
        if (desc != null) {

            if (!desc.isEmpty()
                    && ca.getAuthorityDescription() != null
                    && !desc.equals(ca.getAuthorityDescription())) {

                mods.add(LDAPModification.REPLACE,
                        new LDAPAttribute("description", desc));
                nextDesc = desc;

            } else if (desc.isEmpty() && ca.getAuthorityDescription() != null) {

                mods.add(LDAPModification.DELETE,
                        new LDAPAttribute("description", ca.getAuthorityDescription()));
                nextDesc = null;

            } else if (!desc.isEmpty() && ca.getAuthorityDescription() == null) {

                mods.add(LDAPModification.ADD,
                        new LDAPAttribute("description", desc));
                nextDesc = desc;
            }
        }

        if (mods.size() > 0) {
            modifyAuthorityEntry(ca.getAuthorityID(), mods);

            // update was successful; update CA's state
            ca.setAuthorityEnabled(nextEnabled);
            ca.setAuthorityDescription(nextDesc);
        }
    }

    public void addAuthorityKeyHost(CertificateAuthority ca, String host) throws Exception {

        if (ca.getAuthorityKeyHosts().contains(host)) {
            // already there; nothing to do
            return;
        }

        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(LDAPModification.ADD,
            new LDAPAttribute("authorityKeyHost", host));
        modifyAuthorityEntry(ca.getAuthorityID(), mods);

        ca.getAuthorityKeyHosts().add(host);
    }

    public ProfileSubsystem getProfileSubsystem() {
        return (ProfileSubsystem) getSubsystem(ProfileSubsystem.ID);
    }

    public ProfileSubsystem getProfileSubsystem(String name) {
        if (StringUtils.isEmpty(name)) {
            name = ProfileSubsystem.ID;
        }
        return (ProfileSubsystem) getSubsystem(name);
    }

    public void initCertificateRepository() throws Exception {

        logger.info("CAEngine: Initializing cert repository");

        ConfigStore caConfig = mConfig.getSubStore(CertificateAuthority.ID, ConfigStore.class);
        int increment = caConfig.getInteger(CertificateRepository.PROP_INCREMENT, 5);
        logger.info("CAEngine: - increment: " + increment);

        SecureRandom secureRandom = jssSubsystem.getRandomNumberGenerator();

        certificateRepository = new CertificateRepository(secureRandom, dbSubsystem);
        certificateRepository.setCMSEngine(this);
        certificateRepository.init();
    }

    public void initCrlDatabase() throws Exception {

        logger.info("CAEngine: Initializing CRL repository");

        crlRepository = new CRLRepository(dbSubsystem);
        crlRepository.setCMSEngine(this);
        crlRepository.init();
    }

    public void initReplicaIDRepository() throws Exception {

        logger.info("CAEngine: Initializing replica ID repository");

        replicaIDRepository = new ReplicaIDRepository(dbSubsystem);
        replicaIDRepository.setCMSEngine(this);
        replicaIDRepository.init();
    }

    @Override
    public void init() throws Exception {
        initCertificateRepository();
        initCrlDatabase();
        initReplicaIDRepository();
        super.init();
    }

    @Override
    public boolean isRevoked(X509Certificate[] certificates) {

        if (certificates == null) {
            return false;
        }

        X509CertImpl cert = (X509CertImpl) certificates[0];
        int result = VerifiedCert.UNKNOWN;

        if (mVCList != null) {
            result = mVCList.check(cert);
        }

        if (result == VerifiedCert.REVOKED) {
            return true;
        }

        if (result == VerifiedCert.NOT_REVOKED || result == VerifiedCert.CHECKED) {
            return false;
        }

        boolean revoked = false;

        try {
            if (certificateRepository.isCertificateRevoked(cert) != null) {
                revoked = true;
                if (mVCList != null) {
                    mVCList.update(cert, VerifiedCert.REVOKED);
                }

            } else {
                if (mVCList != null) {
                    mVCList.update(cert, VerifiedCert.NOT_REVOKED);
                }
            }

        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_AUTH_AGENT_REVO_STATUS"), e);
        }

        return revoked;
    }

    public ISharedToken createSharedTokenPlugin() {

        String configName = "cmc.sharedSecret.class";
        String className;

        try {
            className = mConfig.getString(configName);
        } catch (Exception e) {
            logger.error("Unable to get " + configName + ": " + e.getMessage(), e);
            return null;
        }

        logger.debug("CAEngine: shared secret plugin class:" + className);

        try {
            return (ISharedToken) Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            logger.error("Unable to create shared secret plugin: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Retrieves the next available serial number.
     *
     * @return next available serial number
     */
    public String getStartSerial() {
        try {
            BigInteger serial = certificateRepository.peekNextSerialNumber();

            if (serial == null) {
                return "";
            }

            return serial.toString(16);

        } catch (EBaseException e) {
            // shouldn't get here.
            return "";
        }
    }

    /**
     * Sets the next available serial number.
     *
     * @param serial next available serial number
     * @exception EBaseException failed to set next available serial number
     */
    public void setStartSerial(String serial) throws EBaseException {
        certificateRepository.setTheSerialNumber(new BigInteger(serial));
    }

    /**
     * Retrieves the last serial number that can be used for
     * certificate issuance in this certificate authority.
     *
     * @return the last serial number
     */
    public String getMaxSerial() {
        BigInteger serial = certificateRepository.getMaxSerial();

        if (serial != null) {
            return serial.toString(certificateRepository.getRadix());
        }

        return "";
    }

    /**
     * Sets the last serial number that can be used for
     * certificate issuance in this certificate authority.
     *
     * @param serial the last serial number
     * @exception EBaseException failed to set the last serial number
     */
    public void setMaxSerial(String serial) throws EBaseException {
        BigInteger maxSerial = new BigInteger(serial, certificateRepository.getRadix());
        certificateRepository.setMaxSerial(maxSerial);
    }

    public Map<Object, Long> getNonces(HttpServletRequest request, String name) {

        // Create a new session or use an existing one.
        HttpSession session = request.getSession(true);
        if (session == null) {
            throw new PKIException("Unable to create session.");
        }

        // Lock the session to prevent concurrent access.
        // http://yet-another-dev.blogspot.com/2009/08/synchronizing-httpsession.html

        Object lock = request.getSession().getId().intern();
        synchronized (lock) {

            // Find the existing storage in the session.
            @SuppressWarnings("unchecked")
            Map<Object, Long> nonces = (Map<Object, Long>)session.getAttribute("nonces-"+name);

            if (nonces == null) {
                // If not present, create a new storage.
                nonces = Collections.synchronizedMap(new Nonces(getMaxNonces()));

                // Put the storage in the session.
                session.setAttribute("nonces-"+name, nonces);
            }

            return nonces;
        }
    }

    public PKCS10 parsePKCS10(Locale locale, String certreq) throws Exception {

        logger.debug("CAEngine: Parsing PKCS #10 request");

        if (certreq == null) {
            logger.error("CAEngine: Missing PKCS #10 request");
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }

        logger.debug(certreq);

        byte[] data = CertUtil.parseCSR(certreq);

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken savedToken = null;
        boolean sigver = true;

        try {
            sigver = config.getBoolean("ca.requestVerify.enabled", true);

            if (sigver) {
                logger.debug("CAEngine: signature verification enabled");
                String tokenName = config.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                savedToken = cm.getThreadToken();
                CryptoToken signToken = CryptoUtil.getCryptoToken(tokenName);

                logger.debug("CAEngine: setting thread token");
                cm.setThreadToken(signToken);
                return new PKCS10(data);
            }

            logger.debug("CAEngine: signature verification disabled");
            return new PKCS10(data, sigver);

        } catch (Exception e) {
            logger.error("Unable to parse PKCS #10 request: " + e.getMessage(), e);
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);

        } finally {
            if (sigver) {
                logger.debug("CAEngine: restoring thread token");
                cm.setThreadToken(savedToken);
            }
        }
    }

    @Override
    public void shutdownDatabase() {

        if (connectionFactory == null) return;

        try {
            connectionFactory.shutdown();
        } catch (Exception e) {
            logger.warn("CAEngine: Unable to shut down connection factory: " + e.getMessage(), e);
        }
    }

    @Override
    protected void shutdownSubsystems() {

        super.shutdownSubsystems();

        for (CRLIssuingPoint crlIssuingPoint : crlIssuingPoints.values()) {
            crlIssuingPoint.shutdown();
        }
        crlIssuingPoints.clear();

        CRLIssuingPoint masterCRLIssuingPoint = getMasterCRLIssuingPoint();

        if (masterCRLIssuingPoint != null) {
            masterCRLIssuingPoint.shutdown();
        }

        if (serialNumberUpdateTask != null) {
            serialNumberUpdateTask.stop();
        }

        if (certStatusUpdateTask != null) {
            certStatusUpdateTask.stop();
        }

        if (retrieveModificationsTask != null) {
            retrieveModificationsTask.stop();
        }

        if (certificateRepository != null) {
            certificateRepository.shutdown();
        }

        if (publisherProcessor != null) {
            publisherProcessor.shutdown();
        }
    }

    public void shutdownAuthorityMonitor() {

        if (authorityMonitor != null) {
            authorityMonitor.shutdown();
        }

        loader.shutdown();
    }

    @Override
    public void shutdown() {
        shutdownAuthorityMonitor();
        super.shutdown();
    }
}
