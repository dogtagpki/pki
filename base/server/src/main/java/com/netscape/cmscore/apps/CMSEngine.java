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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.PKIClientSocketListener;
import org.dogtagpki.server.PKIServerSocketListener;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.notification.MailNotification;
import com.netscape.cms.password.PasswordChecker;
import com.netscape.cms.servlet.common.CMSGateway;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.VerifiedCert;
import com.netscape.cmscore.authentication.VerifiedCerts;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.cert.OidLoaderSubsystem;
import com.netscape.cmscore.cert.X500NameSubsystem;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.jobs.JobsSchedulerConfig;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAnonConnFactory;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.logging.LogSubsystem;
import com.netscape.cmscore.logging.LoggerConfig;
import com.netscape.cmscore.logging.LoggersConfig;
import com.netscape.cmscore.logging.LoggingConfig;
import com.netscape.cmscore.registry.PluginRegistry;
import com.netscape.cmscore.request.RecoverThread;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.security.JssSubsystemConfig;
import com.netscape.cmscore.security.PWsdrCache;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmscore.session.LDAPSecurityDomainSessionTable;
import com.netscape.cmscore.session.MemorySecurityDomainSessionTable;
import com.netscape.cmscore.session.SessionTimer;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;
import com.netscape.cmsutil.util.NuxwdogUtil;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

public class CMSEngine {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSEngine.class);

    private static final String SERVER_XML = "server.xml";

    public String id;   // subsystem ID (e.g. ca, kra)
    public String name; // subsystem name (e.g. CA, KRA)

    public String instanceDir; /* path to instance <server-root>/cert-<instance-name> */
    private String instanceId;
    private int pid;

    protected EngineConfig config;
    protected EngineConfig mConfig;
    protected ServerConfig serverConfig;

    // AutoSD : AutoShutdown
    private String mAutoSD_CrumbFile = null;
    private boolean mAutoSD_Restart = false;
    private int mAutoSD_RestartMax = 3;
    private int mAutoSD_RestartCount = 0;
    private PrivateKey mSigningKey = null;
    private byte[] mSigningData = null;
    private long mStartupTime = 0;
    private boolean isStarted = false;
    private PasswordStore mPasswordStore = null;
    private SecurityDomainSessionTable mSecurityDomainSessionTable = null;
    private Timer mSDTimer = null;
    private String mServerCertNickname = null;
    private boolean ready;

    private Debug debug = new Debug();

    private PluginRegistry pluginRegistry = new PluginRegistry();
    protected Auditor auditor;
    protected LogSubsystem logSubsystem;

    protected PKIClientSocketListener clientSocketListener;
    protected PKIServerSocketListener serverSocketListener;

    protected JssSubsystem jssSubsystem;
    protected DBSubsystem dbSubsystem;

    protected RequestRepository requestRepository;
    protected RequestQueue requestQueue;

    protected UGSubsystem ugSubsystem;
    protected OidLoaderSubsystem oidLoaderSubsystem;
    protected X500NameSubsystem x500NameSubsystem;
    protected RequestSubsystem requestSubsystem = new RequestSubsystem();
    protected AuthSubsystem authSubsystem;
    protected AuthzSubsystem authzSubsystem;
    protected CMSGateway gateway;
    protected JobsScheduler jobsScheduler;

    public final Map<String, SubsystemInfoConfig> subsystemInfos = new LinkedHashMap<>();
    public final Map<String, Subsystem> subsystems = new LinkedHashMap<>();

    public String unsecurePort;
    public String securePort;

    protected RequestNotifier requestNotifier;
    protected RequestNotifier pendingNotifier;

    private Map<String, SubsystemListener> subsystemListeners = new LinkedHashMap<>();

    private static final int PW_OK =0;
    //private static final int PW_BAD_SETUP = 1;
    private static final int PW_INVALID_CREDENTIALS = 2;
    private static final int PW_CANNOT_CONNECT = 3;
    private static final int PW_MAX_ATTEMPTS = 3;

    protected SSLCertificateApprovalCallback approvalCallback;

    public CMSEngine(String name) {
        this.id = name.toLowerCase();
        this.name = name;

        logger.info("Creating " + name + " engine");
    }

    public SSLCertificateApprovalCallback getApprovalCallback() {
        return approvalCallback;
    }

    public void setApprovalCallback(SSLCertificateApprovalCallback approvalCallback) {
        this.approvalCallback = approvalCallback;
    }

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public PluginRegistry getPluginRegistry() {
        return pluginRegistry;
    }

    public LogSubsystem getLogSubsystem() {
        return logSubsystem;
    }

    public Auditor getAuditor() {
        return auditor;
    }

    public PKIClientSocketListener getClientSocketListener() {
        return clientSocketListener;
    }

    public PKIServerSocketListener getServerSocketListener() {
        return serverSocketListener;
    }

    public JssSubsystem getJSSSubsystem() {
        return jssSubsystem;
    }

    public DBSubsystem getDBSubsystem() {
        return dbSubsystem;
    }

    public RequestRepository getRequestRepository() {
        return requestRepository;
    }

    public void setRequestRepository(RequestRepository requestRepository) {
        this.requestRepository = requestRepository;
    }

    public RequestQueue getRequestQueue() {
        return requestQueue;
    }

    public void setRequestQueue(RequestQueue requestQueue) {
        this.requestQueue = requestQueue;
    }

    public UGSubsystem getUGSubsystem() {
        return ugSubsystem;
    }

    public OidLoaderSubsystem getOIDLoaderSubsystem() {
        return oidLoaderSubsystem;
    }

    public X500NameSubsystem getX500NameSubsystem() {
        return x500NameSubsystem;
    }

    public RequestSubsystem getRequestSubsystem() {
        return requestSubsystem;
    }

    public AuthSubsystem getAuthSubsystem() {
        return authSubsystem;
    }

    public AuthzSubsystem getAuthzSubsystem() {
        return authzSubsystem;
    }

    public CMSGateway getCMSGateway() {
        return gateway;
    }

    public JobsScheduler getJobsScheduler() {
        return jobsScheduler;
    }

    /**
     * get request notifier
     */
    public RequestNotifier getRequestNotifier() {
        return requestNotifier;
    }

    public void setRequestNotifier(RequestNotifier requestNotifier) {
        this.requestNotifier = requestNotifier;
    }

    /**
     * Retrieves all request listeners.
     *
     * @return name enumeration of all request listeners
     */
    public Enumeration<String> getRequestListenerNames() {
        return requestNotifier.getListenerNames();
    }

    /**
     * Retrieves the request listener by name.
     *
     * @param name request listener name
     * @return the request listener
     */
    public RequestListener getRequestListener(String name) {
        return requestNotifier.getListener(name);
    }

    /**
     * Registers a request listener.
     */
    public void registerRequestListener(RequestListener listener) {
        requestNotifier.registerListener(listener);
    }

    /**
     * Registers a request listener.
     *
     * @param name under request listener is going to be registered
     * @param listener request listener to be registered
     */
    public void registerRequestListener(String name, RequestListener listener) {
        requestNotifier.registerListener(name, listener);
    }

    /**
     * Removes a request listener.
     *
     * @param listener request listener to be removed
     */
    public void removeRequestListener(RequestListener listener) {
        requestNotifier.removeListener(listener);
    }

    /**
     * removes listener with a name.
     */
    public void removeRequestListener(String name) {
        requestNotifier.removeListener(name);
    }

    public RequestNotifier getPendingNotifier() {
        return pendingNotifier;
    }

    public void setPendingNotifier(RequestNotifier pendingNotifier) {
        this.pendingNotifier = pendingNotifier;
    }

    /**
     * get listener from listener list
     */
    public RequestListener getPendingListener(String name) {
        return pendingNotifier.getListener(name);
    }

    /**
     * register listener for pending requests
     */
    public void registerPendingListener(RequestListener listener) {
        pendingNotifier.registerListener(listener);
    }

    /**
     * register listener for pending requests with a name.
     */
    public void registerPendingListener(String name, RequestListener listener) {
        pendingNotifier.registerListener(name, listener);
    }

    public void loadConfig(String path) throws Exception {
        ConfigStorage storage = new FileConfigStorage(path);
        config = createConfig(storage);
        config.load();

        instanceId = CMS.getInstanceID();

        mConfig = config;
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new EngineConfig(storage);
    }

    public synchronized PasswordStore getPasswordStore() throws EBaseException {
        if (mPasswordStore == null) {
            try {
                PasswordStoreConfig psc = mConfig.getPasswordStoreConfig();
                mPasswordStore = CMS.createPasswordStore(psc);
            } catch (Exception e) {
                throw new EBaseException(
                    "Failed to initialise password store: " + e.getMessage(), e);
            }
        }
        return mPasswordStore;
    }

    public void initDebug() throws Exception {

        ConfigStore debugConfig = config.getSubStore(Debug.ID, ConfigStore.class);
        debug.init(debugConfig);

        String subsystemConfDir = CMS.getInstanceDir() + File.separator + "conf" + File.separator + id;
        String loggingProperties = subsystemConfDir + File.separator + "logging.properties";

        File file = new File(loggingProperties);
        if (!file.exists()) return;

        logger.info("CMSEngine: Loading " + loggingProperties);
        Properties properties = new Properties();
        properties.load(new FileReader(file));

        for (String key : properties.stringPropertyNames()) {
            String value = properties.getProperty(key);

            logger.info("CMSEngine: - " + key + ": " + value);
            if (!key.endsWith(".level")) continue;

            String loggerName = key.substring(0, key.length() - 6);
            java.util.logging.Level level = java.util.logging.Level.parse(value);

            Logger.getLogger(loggerName).setLevel(level);
        }
    }

    public void initSubsystemListeners() throws Exception {

        logger.info("CMSEngine: Initializing subsystem listeners");

        ConfigStore listenersConfig = config.getSubStore("listeners", ConfigStore.class);

        if (listenersConfig.size() == 0) {
            listenersConfig = config.getSubStore("startupNotifiers", ConfigStore.class);

            if (listenersConfig.size() > 0) {
                String configPath = instanceDir + "/conf/" + id + "/CS.cfg";
                logger.warn("The 'startupNotifiers' property in " + configPath + " has been deprecated. Use 'listeners' instead.");
            }
        }

        String ids = listenersConfig.getString("list", null);
        if (ids == null) return;

        for (String id : ids.split(",")) {
            id = id.trim();
            if (id.isEmpty()) continue;

            ConfigStore instanceConfig = listenersConfig.getSubStore(id, ConfigStore.class);
            String className = instanceConfig.getString("class");
            logger.info("CMSEngine: Initializing subsystem listener " + id + ": " + className);

            Class<? extends SubsystemListener> clazz =
                Class.forName(className).asSubclass(SubsystemListener.class);

            SubsystemListener listener = clazz.getDeclaredConstructor().newInstance();
            listener.init(instanceConfig);

            subsystemListeners.put(id, listener);
        }
    }

    public void initPasswordStore() throws Exception {

        int state = config.getState();
        if (state == 0) {
            return;
        }

        logger.info("CMSEngine: initializing password store");

        // create and initialize mPasswordStore
        getPasswordStore();
    }

    public void testLDAPConnections() throws Exception {

        int state = config.getState();
        if (state == 0) {
            return;
        }

        boolean skipLdapConnectionTest = config.getBoolean("cms.password.skipLdapConnTest", true);
        logger.debug("CMSEngine: skip LDAP connection test: " + skipLdapConnectionTest);

        if (skipLdapConnectionTest) {
            logger.debug("CMSEngine: Skipping LDAP connection test");
            return;
        }

        logger.info("CMSEngine: Checking LDAP connections");

        boolean skipPublishingCheck = config.getBoolean("cms.password.ignore.publishing.failure", true);
        String pwList = config.getString("cms.passwordlist", "internaldb,replicationdb");
        String tags[] = StringUtils.split(pwList, ",");
        LDAPConfig ldapConfig = config.getInternalDBConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        for (String tag : tags) {

            logger.info("CMSEngine: Checking LDAP connections for " + tag);

            String binddn;
            String authType;
            LDAPConnectionConfig connConfig;

            if (tag.equals("internaldb")) {

                authType = authConfig.getAuthType();
                logger.debug("CMSEngine: auth type: " + authType);

                if (!authType.equals(LdapAuthInfo.LDAP_BASICAUTH_STR)) {
                    continue;
                }

                connConfig = ldapConfig.getConnectionConfig();

                binddn = authConfig.getBindDN();

            } else if (tag.equals("replicationdb")) {

                authType = authConfig.getAuthType();
                logger.debug("CMSEngine: auth type: " + authType);

                if (!authType.equals(LdapAuthInfo.LDAP_BASICAUTH_STR)) {
                    continue;
                }

                connConfig = ldapConfig.getConnectionConfig();

                binddn = "cn=Replication Manager masterAgreement1-" + config.getHostname() + "-" +
                        CMS.getInstanceID() + ",cn=config";

            } else if (tags.equals("CA LDAP Publishing")) {

                LDAPConfig publishConfig = config.getSubStore("ca.publish.ldappublish.ldap", LDAPConfig.class);
                LDAPAuthenticationConfig publishAuthConfig = publishConfig.getAuthenticationConfig();

                authType = publishAuthConfig.getAuthType();
                logger.debug("CMSEngine: auth type: " + authType);

                if (!authType.equals(LdapAuthInfo.LDAP_BASICAUTH_STR)) {
                    continue;
                }

                connConfig = publishConfig.getConnectionConfig();

                binddn = publishAuthConfig.getBindDN();

            } else {
                /*
                 * This section assumes a generic format of
                 * <authPrefix>.ldap.xxx
                 * where <authPrefix> is specified under the tag substore
                 *
                 * e.g.  if tag = "externalLDAP"
                 *   cms.passwordlist=...,externalLDAP
                 *   externalLDAP.authPrefix=auths.instance.UserDirEnrollment
                 *
                 *   auths.instance.UserDirEnrollment.ldap.ldapauth.authtype=BasicAuth
                 *   auths.instance.UserDirEnrollment.ldap.ldapauth.bindDN=cn=Corporate Directory Manager
                 *   auths.instance.UserDirEnrollment.ldap.ldapauth.bindPWPrompt=externalLDAP
                 *   auths.instance.UserDirEnrollment.ldap.ldapconn.host=host.example.com
                 *   auths.instance.UserDirEnrollment.ldap.ldapconn.port=389
                 *   auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn=false
                 */
                String authPrefix = config.getString(tag + ".authPrefix", null);
                logger.debug("CMSEngine: auth prefix: " + authPrefix);

                if (authPrefix == null) {
                    continue;
                }

                LDAPConfig prefixConfig = config.getSubStore(authPrefix + ".ldap", LDAPConfig.class);
                LDAPAuthenticationConfig prefixAuthConfig = prefixConfig.getAuthenticationConfig();

                authType = prefixAuthConfig.getAuthType();
                logger.debug("CMSEngine: auth type: " + authType);

                if (!authType.equals(LdapAuthInfo.LDAP_BASICAUTH_STR)) {
                    continue;
                }

                connConfig = prefixConfig.getConnectionConfig();

                try {
                    binddn = prefixAuthConfig.getBindDN();
                } catch (EPropertyNotFound e) {
                    logger.debug("CMSEngine.initializePasswordStore(): binddn not found...skipping");
                    continue;
                }
            }

            int iteration = 0;
            int result = PW_INVALID_CREDENTIALS;

            do {
                String passwd = mPasswordStore.getPassword(tag, iteration);
                result = testLDAPConnection(tag, connConfig, binddn, passwd);
                iteration++;
            } while ((result == PW_INVALID_CREDENTIALS) && (iteration < PW_MAX_ATTEMPTS));

            if (result != PW_OK) {
                if ((result == PW_INVALID_CREDENTIALS) && (tag.equals("replicationdb"))) {
                    logger.warn(
                        "CMSEngine: LDAP connection test failed for replicationdb " +
                        "with NO_SUCH_USER. This may not be a latest instance. Ignoring ..");

                } else if (skipPublishingCheck && (result == PW_CANNOT_CONNECT) && (tag.equals("CA LDAP Publishing"))) {
                    logger.warn(
                        "CMSEngine: Unable to connect to the publishing database to check password, " +
                        "but continuing to start up. Please check if publishing is operational.");
                } else {
                    // password test failed
                    logger.error("CMSEngine: LDAP connection test failed: " + result);
                    throw new EBaseException("LDAP connection test failed. Is the database up?");
                }
            }
        }
    }

    public int testLDAPConnection(String name, LDAPConnectionConfig connConfig, String binddn, String pwd) throws EBaseException {

        int ret = PW_OK;

        if (StringUtils.isEmpty(pwd)) {
            return PW_INVALID_CREDENTIALS;
        }

        String host = connConfig.getHostname();
        int port = connConfig.getPort();

        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setSecure(connConfig.isSecure());
        socketFactory.init(socketConfig);

        LDAPConnection conn = new LDAPConnection(socketFactory);

        try {
            logger.info("CMSEngine: verifying connection to " + host + ":" + port + " as " + binddn);
            conn.connect(host, port, binddn, pwd);

        } catch (LDAPException e) {

            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.INVALID_CREDENTIALS:
                logger.debug("CMSEngine: invalid credentials");
                ret = PW_INVALID_CREDENTIALS;
                break;
            default:
                logger.debug("CMSEngine: unable to connect to " + name + ": " + e.getMessage());
                ret = PW_CANNOT_CONNECT;
                break;
            }

        } finally {
            try {
                if (conn != null) conn.disconnect();
            } catch (Exception e) {
                logger.warn("CMSEngine: unable to disconnect from " + host + ":" + port);
            }
        }

        return ret;
    }

    public void initSecurityProvider() {

        Security.addProvider(new org.mozilla.jss.netscape.security.provider.CMS());

        logger.info("CMSEngine: security providers:");
        for (Provider provider : Security.getProviders()) {
            logger.info("CMSEngine: - " + provider);
        }
    }

    public void initDatabase() throws Exception {
    }

    public void initPluginRegistry() throws Exception {
        ConfigStore pluginRegistryConfig = config.getSubStore(PluginRegistry.ID, ConfigStore.class);
        String defaultRegistryFile = instanceDir + "/conf/" + id + "/registry.cfg";
        pluginRegistry.init(pluginRegistryConfig, defaultRegistryFile);
        pluginRegistry.startup();
    }

    public void initAuditor() throws Exception {
        auditor = new Auditor();
        auditor.init();
    }

    public void initLogSubsystem() throws Exception {
        LoggingConfig logConfig = config.getLoggingConfig();
        logSubsystem = new LogSubsystem();
        logSubsystem.setCMSEngine(this);
        logSubsystem.init(logConfig);
        logSubsystem.startup();
    }

    public void initClientSocketListener() {
        clientSocketListener = new PKIClientSocketListener();
        clientSocketListener.setCMSEngine(this);
    }

    public void initServerSocketListener() {
        serverSocketListener = new PKIServerSocketListener();
        serverSocketListener.setCMSEngine(this);
    }

    public void initJssSubsystem() throws Exception {
        JssSubsystemConfig jssConfig = config.getJssSubsystemConfig();
        jssSubsystem = new JssSubsystem();
        jssSubsystem.setCMSEngine(this);
        jssSubsystem.init(jssConfig);
        jssSubsystem.startup();
    }

    public void initDBSubsystem() throws Exception {

        DatabaseConfig dbConfig = config.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        PKISocketConfig socketConfig = config.getSocketConfig();
        PasswordStore passwordStore = getPasswordStore();

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setApprovalCallback(approvalCallback);

        socketFactory.setSecure(connConfig.isSecure());
        if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(authConfig.getAuthType())) {
            socketFactory.setClientCertNickname(authConfig.getClientCertNickname());
        }

        socketFactory.init(socketConfig);

        dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(config);
        dbSubsystem.setSocketFactory(socketFactory);
        dbSubsystem.init(dbConfig, ldapConfig, passwordStore);
    }

    public void initUGSubsystem() throws Exception {

        ugSubsystem = new UGSubsystem();
        ugSubsystem.setCMSEngine(this);

        UGSubsystemConfig ugConfig = config.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        PKISocketConfig socketConfig = config.getSocketConfig();
        PasswordStore passwordStore = getPasswordStore();

        ugSubsystem.init(ldapConfig, socketConfig, passwordStore);
    }

    public void initOIDLoaderSubsystem() throws Exception {
        ConfigStore oidLoaderConfig = config.getSubStore(OidLoaderSubsystem.ID, ConfigStore.class);
        oidLoaderSubsystem = new OidLoaderSubsystem();
        oidLoaderSubsystem.setCMSEngine(this);
        oidLoaderSubsystem.init(oidLoaderConfig);
        oidLoaderSubsystem.startup();
    }

    public void initX500NameSubsystem() throws Exception {
        ConfigStore x500NameConfig = config.getSubStore(X500NameSubsystem.ID, ConfigStore.class);
        x500NameSubsystem = new X500NameSubsystem();
        x500NameSubsystem.setCMSEngine(this);
        x500NameSubsystem.init(x500NameConfig);
        x500NameSubsystem.startup();
    }

    public void initRequestSubsystem() throws Exception {
        ConfigStore requestConfig = config.getSubStore(RequestSubsystem.ID, ConfigStore.class);
        requestSubsystem.init(requestConfig, dbSubsystem);
        requestSubsystem.startup();
    }

    public void initAuthSubsystem() throws Exception {
        AuthenticationConfig authConfig = config.getAuthenticationConfig();
        authSubsystem = new AuthSubsystem();
        authSubsystem.setCMSEngine(this);
        authSubsystem.init(authConfig);
        authSubsystem.startup();
    }

    public void initAuthzSubsystem() throws Exception {
        ConfigStore authzConfig = config.getSubStore(AuthzSubsystem.ID, ConfigStore.class);
        authzSubsystem = new AuthzSubsystem();
        authzSubsystem.setCMSEngine(this);
        authzSubsystem.init(authzConfig);
        authzSubsystem.startup();
    }

    public void initCMSGateway() throws Exception {
        gateway = new CMSGateway();
        gateway.setCMSEngine(this);
        gateway.init();
    }

    public void initJobsScheduler() throws Exception {
        JobsSchedulerConfig jobsSchedulerConfig = config.getJobsSchedulerConfig();
        jobsScheduler = new JobsScheduler();
        jobsScheduler.setCMSEngine(this);
        jobsScheduler.init(jobsSchedulerConfig);
        jobsScheduler.startup();
    }

    public void configurePorts() throws Exception {

        String path = instanceDir + File.separator + "conf" + File.separator + SERVER_XML;

        serverConfig = ServerConfig.load(path);
        unsecurePort = serverConfig.getUnsecurePort();
        securePort = serverConfig.getSecurePort();

        String port = config.getString("proxy.securePort", "");
        if (!port.equals("")) {
            securePort = port;
        }

        port = config.getString("proxy.unsecurePort", "");
        if (!port.equals("")) {
            unsecurePort = port;
        }
    }

    public void initSecurityDomain() throws Exception {

        int state = config.getState();
        if (state == 0) {
            return;
        }

        String sd = config.getString("securitydomain.select", "");
        if (!sd.equals("new")) {
            return;
        }

        // monitor security domain sessions

        // my default is 1 day
        String source = config.getString("securitydomain.source", "memory");
        String flushInterval = config.getString("securitydomain.flushinterval", "86400000");
        String checkInterval = config.getString("securitydomain.checkinterval", "5000");

        if (source.equals("ldap")) {
            LDAPSecurityDomainSessionTable sessionTable = new LDAPSecurityDomainSessionTable(Long.parseLong(flushInterval));
            sessionTable.setCMSEngine(this);
            sessionTable.init();
            mSecurityDomainSessionTable = sessionTable;

        } else {
            mSecurityDomainSessionTable = new MemorySecurityDomainSessionTable(Long.parseLong(flushInterval));
        }

        SessionTimer task = new SessionTimer(mSecurityDomainSessionTable);
        task.setCMSEngine(this);

        mSDTimer = new Timer();
        mSDTimer.schedule(task, 5, Long.parseLong(checkInterval));
    }

    /**
     * initialize all static, dynamic and final static subsystems.
     *
     * @exception Exception if any error occur in subsystems during
     *                initialization.
     */
    public void init() throws Exception {

        logger.info("Initializing " + name + " subsystem");
        loadSubsystems();
        initSubsystems();

        // The ports must be configured here to avoid problems
        // when installing a clone of an existing clone.
        // https://github.com/dogtagpki/pki/issues/3330
        configurePorts();
    }

    public ConfigStore loadConfigStore(String path) throws EBaseException {
        try {
            /* if the file is not there, create one */
            File f = new File(path);
            f.createNewFile();

            ConfigStorage storage = new FileConfigStorage(path);
            ConfigStore cs = new ConfigStore(storage);
            cs.load();
            return cs;

        } catch (Exception e) {
            logger.error("Cannot create file: " + path + ": " + e.getMessage(), e);
            throw new EBaseException("Cannot create file: " + path + ": " + e.getMessage(), e);
        }
    }

    public boolean isPreOpMode() {
        if (getCSState() == CMS.PRE_OP_MODE)
            return true;
        return false;
    }

    public boolean isRunningMode() {
        if (getCSState() == CMS.RUNNING_MODE)
            return true;
        return false;
    }

    public void setCSState(int mode) {
        mConfig.setState(mode);
    }

    public int getCSState() {
        int mode = 0;
        try {
            mode = mConfig.getState();
        } catch (Exception e) {
        }
        return mode;
    }

    public SecurityDomainSessionTable getSecurityDomainSessionTable() {
        return mSecurityDomainSessionTable;
    }

    public String getEENonSSLPort() {
        return unsecurePort;
    }

    public String getEESSLPort() {
        return securePort;
    }

    public String getEEClientAuthSSLPort() {
        return securePort;
    }

    public String getAgentPort() {
        return securePort;
    }

    public String getAdminPort() {
        return securePort;
    }

    public Collection<Subsystem> getSubsystems() {
        return subsystems.values();
    }

    public Subsystem getSubsystem(String name) {
        return subsystems.get(name);
    }

    /**
     * load subsystems
     */
    protected void loadSubsystems() throws Exception {

        subsystemInfos.clear();
        subsystems.clear();

        SubsystemsConfig subsystemsConfig = mConfig.getSubsystemsConfig();

        for (String subsystemNumber : subsystemsConfig.getSubsystemNames()) {
            SubsystemInfoConfig subsystemInfoConfig = subsystemsConfig.getSubsystemInfoConfig(subsystemNumber);
            String id = subsystemInfoConfig.getID();
            logger.info("CMSEngine: Loading " + id + " subsystem");

            String className = subsystemInfoConfig.getClassName();

            Subsystem subsystem = (Subsystem) Class.forName(className).getDeclaredConstructor().newInstance();
            subsystem.setCMSEngine(this);
            subsystems.put(id, subsystem);
            subsystemInfos.put(id, subsystemInfoConfig);
        }
    }

    public void initSubsystem(Subsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof SelfTestSubsystem) {
            // skip SelfTestSubsystem during installation
            if (isPreOpMode()) return;
        }

        subsystem.init(subsystemConfig);
    }

    public void initSubsystems() throws Exception {

        for (String id : subsystems.keySet()) {
            logger.info("CMSEngine: Initializing " + id + " subsystem");

            Subsystem subsystem = subsystems.get(id);
            SubsystemInfoConfig subsystemInfo = subsystemInfos.get(id);

            subsystem.setId(id);

            if (!subsystemInfo.isEnabled()) {
                logger.info("CMSEngine: " + id + " subsystem is disabled");
                continue;
            }

            ConfigStore subsystemConfig = mConfig.getSubStore(id, ConfigStore.class);
            initSubsystem(subsystem, subsystemConfig);
        }
    }

    public void configureAutoShutdown() throws Exception {

        if (isPreOpMode()) {
            return;
        }

        logger.info("CMSEngine: Configuring auto shutdown");

        /*
         * autoShutdown.allowed=false
         * autoShutdown.crumbFile=[pki_instance_path]/logs/autoShutdown.crumb
         * autoShutdown.restart.enable=false
         * autoShutdown.restart.max=3
         * autoShutdown.restart.count=0
         */

        mAutoSD_Restart = config.getBoolean("autoShutdown.restart.enable", false);
        logger.debug("CMSEngine: restart at autoShutdown: " + mAutoSD_Restart);

        if (mAutoSD_Restart) {
            mAutoSD_RestartMax = config.getInteger("autoShutdown.restart.max", 3);
            logger.debug("CMSEngine: restart max: " + mAutoSD_RestartMax);

            mAutoSD_RestartCount = config.getInteger("autoShutdown.restart.count", 0);
            logger.debug("CMSEngine: current restart count: " + mAutoSD_RestartCount);

        } else { //!mAutoSD_Restart

            mAutoSD_CrumbFile = config.getString("autoShutdown.crumbFile",
                instanceDir + "/logs/autoShutdown.crumb");
            logger.info("CMSEngine: auto-shutdown crumb file: " + mAutoSD_CrumbFile);

            File crumb = new File(mAutoSD_CrumbFile);
            if (crumb.exists()) {
                logger.info("CMSEngine: deleting auto-shutdown crumb file: " + mAutoSD_CrumbFile);
                crumb.delete();
            }
        }

        /*
         * establish signing key reference using audit signing cert
         * for HSM failover detection
         */
        LoggersConfig loggersConfig = config.getLoggingConfig().getLoggersConfig();
        LoggerConfig loggerConfig = loggersConfig.getLoggerConfig("SignedAudit");

        if (!loggerConfig.getLogSigning()) {
            // skip log signing setup
            return;
        }

        String mSAuditCertNickName = loggerConfig.getString("signedAuditCertNickname");
        logger.debug("CMSEngine: audit signing cert: " + mSAuditCertNickName);

        CryptoManager mManager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate cert = mManager.findCertByNickname(mSAuditCertNickName);

        mSigningKey = mManager.findPrivKeyByCert(cert);
        mSigningData = cert.getPublicKey().getEncoded();
    }

    public void configureServerCertNickname() throws EBaseException {

        if (id.equals("ca") || id.equals("ocsp") ||
                id.equals("kra") || id.equals("tks")) {

            logger.info("CMSEngine: Configuring servlet certificate nickname");
            ConfigStore serverCertStore = mConfig.getSubStore(id + "." + "sslserver", ConfigStore.class);

            if (serverCertStore != null && serverCertStore.size() > 0) {
                String nickName = serverCertStore.getString("nickname");
                String tokenName = serverCertStore.getString("tokenname");

                if (tokenName != null && tokenName.length() > 0 &&
                        nickName != null && nickName.length() > 0) {
                    setServerCertNickname(tokenName, nickName);
                    logger.debug("CMSEngine: server certificate nickname: " + tokenName + ":" + nickName);

                } else if (nickName != null && nickName.length() > 0) {
                    setServerCertNickname(nickName);
                    logger.debug("CMSEngine: server certificate nickName: " + nickName);

                } else {
                    logger.warn("Unable to configure server certificate nickname");
                }
            }
        }
    }

    /**
     * sign some known data to determine if signing key is botched;
     * if so, proceed to graceful shutdown
     */
    public void checkForAndAutoShutdown() {
        String method= "CMSEngine: checkForAndAutoShutdown: ";
        logger.debug(method + "begins");

        try {
            boolean allowShutdown  = mConfig.getBoolean("autoShutdown.allowed", false);
            if ((!allowShutdown) || (mSigningKey == null) ||
                    (mSigningData == null)) {
                logger.debug(method + "autoShutdown not allowed");
                return;
            }
            logger.debug(method + "autoShutdown allowed");
            CryptoToken token =
                ((org.mozilla.jss.pkcs11.PK11PrivKey) mSigningKey).getOwningToken();
            SignatureAlgorithm signAlg = Cert.mapAlgorithmToJss("SHA256withRSA");
            Signature signer = token.getSignatureContext(signAlg);

            signer.initSign(mSigningKey);
            signer.update(mSigningData);
            byte[] result = signer.sign();
            logger.debug(method + " signining successful: " + new String(result));
        } catch (SignatureException e) {

            //Let's write to the error console in case we are in a bad memory situation
            //This will be the most likely to work, giving us a record of the signing failure
            System.err.println(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString()));

            logger.warn(method + "autoShutdown for " + e.getMessage(), e);

            autoShutdown();
        } catch (Exception e) {
            logger.warn(method + "continue for " + e.getMessage(), e);
        }
        logger.debug(method + "passed; continue");
    }

    /**
     * Resends requests
     *
     * New non-blocking recover method.
     */
    public void recoverRequestQueue() {

        if (!isRunningMode()) return;

        RecoverThread t = new RecoverThread(requestQueue);
        t.start();
    }

    protected void startupSubsystems() throws Exception {

        for (Subsystem subsystem : subsystems.values()) {

            if (subsystem instanceof SelfTestSubsystem) {
                // skip SelfTestSubsystem during installation
                if (isPreOpMode()) return;
            }

            logger.info("CMSEngine: Starting " + subsystem.getId() + " subsystem");
            subsystem.startup();
        }

        // global admin servlet. (anywhere else more fit for this ?)
    }

    public void notifySubsystemStarted() {

        for (String name : subsystemListeners.keySet()) {
            SubsystemListener notifier = subsystemListeners.get(name);
            try {
                notifier.subsystemStarted();
            } catch (Exception e) {
                logger.warn("Unable to notify '" + name + "': " + e.getMessage(), e);
            }
        }
    }

    public void start() throws Exception {

        logger.info("Starting " + name + " engine");

        ready = false;

        instanceDir = CMS.getInstanceDir();
        String serverConfDir = instanceDir + File.separator + "conf";
        String subsystemConfDir = serverConfDir + File.separator + id;

        String path = subsystemConfDir + File.separator + "CS.cfg";
        loadConfig(path);

        initSequence();

        ready = true;
        isStarted = true;

        mStartupTime = System.currentTimeMillis();

        logger.info(name + " engine started");
        // Register TomcatJSS socket listener
        TomcatJSS tomcatJss = TomcatJSS.getInstance();
        if(serverSocketListener == null) {
            serverSocketListener = new PKIServerSocketListener();
        }
        tomcatJss.addSocketListener(serverSocketListener);

        notifySubsystemStarted();

        Collection<Thread> threads = Thread.getAllStackTraces().keySet();
        logger.info("CMSEngine: Threads:");
        for (Thread thread : threads) {
            logger.info("CMSEngine: - " + thread.getName());
        }
    }

    protected void initSequence() throws Exception {
        initDebug();
        initPasswordStore();
        initSubsystemListeners();
        initSecurityProvider();
        initPluginRegistry();
        initAuditor();
        initLogSubsystem();

        initClientSocketListener();
        initServerSocketListener();

        testLDAPConnections();
        initDatabase();

        initJssSubsystem();
        initDBSubsystem();
        initUGSubsystem();
        initOIDLoaderSubsystem();
        initX500NameSubsystem();
        // skip TP subsystem;
        // problem in needing dbsubsystem in constructor. and it's not used.
        initRequestSubsystem();

        init();

        startupSubsystems();

        initAuthSubsystem();
        initAuthzSubsystem();
        initCMSGateway();
        initJobsScheduler();

        configureAutoShutdown();
        configureServerCertNickname();

        initSecurityDomain();
    }

    public boolean isInRunningState() {
        return isStarted;
    }

    public String getServerCertNickname() {
        return mServerCertNickname;
    }

    public void setServerCertNickname(String tokenName, String
            nickName) {
        String newName = null;

        if (CryptoUtil.isInternalToken(tokenName))
            newName = nickName;
        else {
            if (tokenName.equals("") && nickName.equals("")) {
                return; // not sure the logic
            }
            newName = tokenName + ":" + nickName;
        }
        setServerCertNickname(newName);
    }

    public void setServerCertNickname(String newName) {
        mServerCertNickname = newName;
    }

    public LdapAnonConnFactory createLdapAnonConnFactory(
            String id,
            LDAPConfig ldapConfig
            ) throws EBaseException {

        LDAPConnectionConfig ldapConnConfig = ldapConfig.getConnectionConfig();
        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setSecure(ldapConnConfig.isSecure());
        socketFactory.init(socketConfig);

        LdapAnonConnFactory connFactory = new LdapAnonConnFactory(id);
        connFactory.setSocketFactory(socketFactory);
        connFactory.init(ldapConfig);

        return connFactory;
    }

    public LdapAnonConnFactory createLdapAnonConnFactory(
            String id,
            int minConns,
            int maxConns,
            LdapConnInfo connInfo
            ) throws EBaseException {

        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setSecure(connInfo.getSecure());
        socketFactory.init(socketConfig);

        LdapAnonConnFactory connFactory = new LdapAnonConnFactory(
                id,
                minConns,
                maxConns,
                connInfo);
        connFactory.setSocketFactory(socketFactory);
        connFactory.init();

        return connFactory;
    }

    public LdapBoundConnFactory createLdapBoundConnFactory(
            String id,
            LDAPConfig ldapConfig
            ) throws EBaseException {

        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setApprovalCallback(approvalCallback);
        socketFactory.setSecure(connConfig.isSecure());
        if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(authConfig.getAuthType())) {
            socketFactory.setClientCertNickname(authConfig.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnFactory connFactory = new LdapBoundConnFactory(id);
        connFactory.setSocketFactory(socketFactory);
        connFactory.setPasswordStore(getPasswordStore());
        connFactory.init(ldapConfig);

        return connFactory;
    }

    public LdapBoundConnFactory createLdapBoundConnFactory(
            String id,
            int minConns,
            int maxConns,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo
            ) throws EBaseException {

        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setAuditor(auditor);
        socketFactory.addSocketListener(clientSocketListener);
        socketFactory.setApprovalCallback(approvalCallback);
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnFactory connFactory = new LdapBoundConnFactory(
                id,
                minConns,
                maxConns,
                connInfo,
                authInfo);
        connFactory.setSocketFactory(socketFactory);
        connFactory.setPasswordStore(getPasswordStore());
        connFactory.init();

        return connFactory;
    }

    public MailNotification getMailNotification() {
        try {
            String className = mConfig.getString("notificationClassName", MailNotification.class.getName());
            MailNotification notification = (MailNotification) Class.forName(className).getDeclaredConstructor().newInstance();

            ConfigStore cs = config.getSubStore(MailNotification.PROP_SMTP_SUBSTORE, ConfigStore.class);
            String host = cs.getString(MailNotification.PROP_HOST);
            logger.debug("CMSEngine: SMTP host: " + host);

            notification.setHost(host);

            return notification;

        } catch (Exception e) {
            logger.warn("CMSEngine: Unable to create mail notification: " + e.getMessage(), e);
            return null;
        }
    }

    public PasswordChecker getPasswordChecker() {
        try {
            String className = mConfig.getString("passwordCheckerClass",
                    "com.netscape.cms.password.PasswordChecker");
            PasswordChecker check = (PasswordChecker) Class.forName(className).getDeclaredConstructor().newInstance();
            check.setMinSize(mConfig.getInteger("passwordChecker.minSize", 8));
            check.setMinUpperLetter(mConfig.getInteger("passwordChecker.minUpperLetter", 0));
            check.setMinLowerLetter(mConfig.getInteger("passwordChecker.minLowerLetter", 0));
            check.setMinNumber(mConfig.getInteger("passwordChecker.minNumber", 0));
            check.setMinSpecialChar(mConfig.getInteger("passwordChecker.minSpecialChar", 0));
            check.setSeqLength(mConfig.getInteger("passwordChecker.seqLength", 0));
            check.setMaxRepeatedChar(mConfig.getInteger("passwordChecker.maxRepeatedChar", 0));
            check.setCracklibCheck(mConfig.getBoolean("passwordChecker.cracklibCheck", false));

            return check;
        } catch (Exception e) {
            return null;
        }
    }

    public void disableRequests() {
        CommandQueue.mShuttingDown = true;
    }

    public boolean areRequestsDisabled() {
        return CommandQueue.mShuttingDown;
    }

    public void terminateRequests() {
        Enumeration<CMSRequest> e = CommandQueue.mCommandQueue.keys();

        while (e.hasMoreElements()) {
            Object thisRequest = e.nextElement();

            HttpServlet thisServlet = (HttpServlet) CommandQueue.mCommandQueue.get(thisRequest);

            if (thisServlet != null) {
                CommandQueue.mCommandQueue.remove(thisRequest);
                thisServlet.destroy();
            }
        }
    }

    public static boolean isNT() {
        return (File.separator.equals("\\"));
    }

    private void shutdownHttpServer(boolean restart) {
        try {
            String cmds[] = null;
            String cmd = "stop";
            if (restart) {
                cmd = "restart";
            }

            cmds = new String[3];
            cmds[0] = "/usr/bin/systemctl";
            cmds[1] = cmd;
            if (NuxwdogUtil.startedByNuxwdog()) {
                cmds[2] = "pki-tomcatd-nuxwdog@" + instanceId + ".service";
            } else {
                cmds[2] = "pki-tomcatd@" + instanceId + ".service";
            }

            Process process = Runtime.getRuntime().exec(cmds);

            process.waitFor();

        } catch (IOException e) {
            logger.warn("Unable to shutdown HTTP server: " + e.getMessage(), e);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    } // end shutdownHttpServer

    public void shutdownJobsScheduler() {
        if (jobsScheduler == null) return;
        jobsScheduler.shutdown();
    }

    public void shutdownAuthzSubsystem() {
        if (authzSubsystem == null) return;
        authzSubsystem.shutdown();
    }

    public void shutdownAuthSubsystem() {
        if (authSubsystem == null) return;
        authSubsystem.shutdown();
    }

    public void shutdownRequestSubsystem() {
        if (requestSubsystem == null) return;
        requestSubsystem.shutdown();
    }

    public void shutdownX500NameSubsystem() {
        if (x500NameSubsystem == null) return;
        x500NameSubsystem.shutdown();
    }

    public void shutdownOIDLoaderSubsystem() {
        if (oidLoaderSubsystem == null) return;
        oidLoaderSubsystem.shutdown();
    }

    public void shutdownUGSubsystem() {
        if (ugSubsystem == null) return;
        ugSubsystem.shutdown();
    }

    public void shutdownDBSubsystem() {
        if (dbSubsystem == null) return;
        dbSubsystem.shutdown();
    }

    public void shutdownJSSSubsystem() {
        if (jssSubsystem == null) return;
        jssSubsystem.shutdown();
    }

    public void shutdownLogSubsystem() {
        if (logSubsystem == null) return;
        logSubsystem.shutdown();
    }

    public void shutdownDatabase() {
    }

    public void shutdownPluginRegistry() {
        if (pluginRegistry == null) return;
        pluginRegistry.shutdown();
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     */
    public void shutdown() {

        isStarted = false;
        if (serverSocketListener != null) {
            // De-Register TomcatJSS socket listener
            TomcatJSS tomcatJss = TomcatJSS.getInstance();
            tomcatJss.removeSocketListener(serverSocketListener);
        }
        logger.info("Shutting down " + name + " subsystem");

        /*
                CommandQueue commandQueue = new CommandQueue();
                Thread t1 = new Thread(commandQueue);

                t1.setDaemon(true);
                t1.start();

                // wait for command queue to emptied before proceeding to shutting down subsystems
                Date time = new Date();
                long startTime = time.getTime();
                long timeOut = time.getTime();

                while (t1.isAlive() && ((timeOut - startTime) < (60 * 1000))) //wait for 1 minute
                {
                    try {
                        Thread.currentThread().sleep(5000); // sleep for 5 sec
                    }catch (java.lang.InterruptedException e) {
                    }
                    timeOut = time.getTime();
                }
                terminateRequests();
        */

        shutdownJobsScheduler();
        shutdownAuthzSubsystem();
        shutdownAuthSubsystem();

        shutdownSubsystems();

        if (mSDTimer != null) {
            mSDTimer.cancel();
        }

        if (mSecurityDomainSessionTable != null) {
            mSecurityDomainSessionTable.shutdown();
        }

        shutdownRequestSubsystem();
        shutdownX500NameSubsystem();
        shutdownOIDLoaderSubsystem();
        shutdownUGSubsystem();
        shutdownDBSubsystem();
        shutdownJSSSubsystem();
        shutdownLogSubsystem();
        shutdownDatabase();
        shutdownPluginRegistry();
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     * Added extra call to shutdown the web server.
     */
    public void forceShutdown() {
        logger.debug("CMSEngine.forceShutdown()");
        autoShutdown(false /*no restart*/);
    }

    public void autoShutdown() {
        autoShutdown(mAutoSD_Restart /* controlled by config */);
    }

    public void autoShutdown(boolean restart) {

        logger.info("CMSEngine: Shutting down " + name + " subsystem");

        logger.debug("CMSEngine: restart: " + restart);

        // update restart tracker so we don't go into infinite restart loop
        if (restart) {
            logger.debug("CMSEngine: checking autoShutdown.restart trackers");
            if (mAutoSD_RestartCount >= mAutoSD_RestartMax) {
                mAutoSD_Restart = false;
                mConfig.putBoolean("autoShutdown.restart.enable", mAutoSD_Restart);
                logger.debug("CMSEngine: autoShutdown.restart.max reached, disabled autoShutdown.restart.enable");
            } else {
                mAutoSD_RestartCount++;
                mConfig.putInteger("autoShutdown.restart.count", mAutoSD_RestartCount);
                logger.debug("CMSEngine: autoShutdown.restart.max not reached, increment autoShutdown.restart.count");
            }
            try {
                mConfig.commit(false);
            } catch (EBaseException e) {
                logger.warn("Unable to store configuration: " + e.getMessage(), e);
            }
        } else {
            // leave a crumb file to be monitored by external monitor
            File crumb = new File(mAutoSD_CrumbFile);
            try {
                crumb.createNewFile();
            } catch (IOException e) {
                logger.warn("Create autoShutdown crumb file failed on " + mAutoSD_CrumbFile + ": " + e.getMessage(), e);
                logger.warn("Nothing to do, keep shutting down");
            }
        }

/* cfu: not sure why it's doing a commandQueue but not registering any
 * service to wait on... what does this do to wait on an empty queue?
 *
        CommandQueue commandQueue = new CommandQueue();
        Thread t1 = new Thread(commandQueue);

        t1.setDaemon(true);
        t1.start();

        // wait for command queue to emptied before proceeding to shutting down subsystems
        Date time = new Date();
        long startTime = time.getTime();
        long timeOut = time.getTime();

        while (t1.isAlive() && ((timeOut - startTime) < (60 * 1000))) //wait for 1 minute
        {
            try {
                Thread.sleep(5000); // sleep for 5 sec
            } catch (java.lang.InterruptedException e) {
            }
            timeOut = time.getTime();
        }
*/

        if (areRequestsDisabled() == false) {
            disableRequests();
        }
        terminateRequests();
        shutdown();

        shutdownHttpServer(restart);
    }

    public void disableSubsystem() {

        logger.info("CMSEngine: Disabling " + name + " subsystem");

        try {
            ProcessBuilder pb = new ProcessBuilder("pki-server", "subsystem-disable", "-i", instanceId, id);
            logger.debug("Command: " + String.join(" ", pb.command()));

            Process process = pb.inheritIO().start();
            int rc = process.waitFor();

            if (rc != 0) {
                logger.error("CMSEngine: Unable to disable " + name + " subsystem. RC: " + rc);
            }

        } catch (Exception e) {
            logger.error("CMSEngine: Unable to disable " + name + " subsystem: " + e.getMessage(), e);
        }
    }

    protected void shutdownSubsystems() {

        // reverse list of subsystems
        List<Subsystem> list = new ArrayList<>();
        list.addAll(subsystems.values());
        Collections.reverse(list);

        for (Subsystem subsystem : list) {
            logger.debug("CMSEngine: Stopping " + subsystem.getId() + " subsystem");
            subsystem.shutdown();
        }
    }

    /**
     * returns the main config store
     */
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    public EngineConfig getConfig() {
        return mConfig;
    }

    public ServerConfig getServerConfig() {
        return serverConfig;
    }

    /**
     * get time server started up
     */
    public long getStartupTime() {
        return mStartupTime;
    }

    public void putPasswordCache(String tag, String pw) {
        try {
            PWsdrCache pwc = new PWsdrCache();
            pwc.setEngineConfig(config);
            pwc.addEntry(tag, pw);
        } catch (EBaseException e) {
            // intercept this for now -- don't want to change the callers
            logger.warn(CMS.getLogMessage("CMSCORE_SDR_ADD_ERROR", e.toString()), e);
        }
    }

    public int getPID() {
        if (pid != 0) return pid;

        BufferedReader bf = null;
        try {
            // PID file is be created by wrapper script (e.g. /usr/sbin/tomcat6)
            // The default is for dogtag 9 systems which did not have this paramater
            String dir = mConfig.getString("pidDir", "/var/run");
            String name = dir+File.separator+instanceId+".pid";

            if (dir == null) return pid;
            File file = new File(name);
            if (!file.exists()) return pid;

            bf = new BufferedReader(new FileReader(file));
            String value = bf.readLine();
            pid = Integer.parseInt(value);

        } catch (Exception e) {
            logger.warn("Unable to get PID: " + e.getMessage(), e);

        } finally {
            try {
                if (bf != null) bf.close();
            } catch (Exception e) {
                logger.warn("Unable to close BufferedReader: " + e.getMessage(), e);
            }
        }

        return pid;
    }

    public VerifiedCerts mVCList = null;
    private int mVCListSize = 0;

    public void setListOfVerifiedCerts(int size, long interval, long unknownStateInterval) {
        if (size > 0 && mVCListSize == 0) {
            mVCListSize = size;
            mVCList = new VerifiedCerts(size, interval, unknownStateInterval);
        }
    }

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

        if (requestQueue != null) {
            Request checkRevReq = null;

            try {
                checkRevReq = requestRepository.createRequest(Request.GETREVOCATIONINFO_REQUEST);
                checkRevReq.setExtData(Request.REQ_TYPE, Request.GETREVOCATIONINFO_REQUEST);
                checkRevReq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_RA);

                X509CertImpl agentCerts[] = new X509CertImpl[certificates.length];
                for (int i = 0; i < certificates.length; i++) {
                    agentCerts[i] = (X509CertImpl) certificates[i];
                }

                checkRevReq.setExtData(Request.ISSUED_CERTS, agentCerts);

                requestQueue.processRequest(checkRevReq);

                RequestStatus status = checkRevReq.getRequestStatus();

                if (status == RequestStatus.COMPLETE) {
                    Enumeration<String> keys = checkRevReq.getExtDataKeys();
                    while (keys.hasMoreElements()) {
                        String name = keys.nextElement();

                        if (name.equals(Request.REVOKED_CERTS)) {
                            revoked = true;
                            if (mVCList != null) {
                                mVCList.update(cert, VerifiedCert.REVOKED);
                            }
                        }
                    }

                    if (revoked == false) {
                        if (mVCList != null) {
                            mVCList.update(cert, VerifiedCert.NOT_REVOKED);
                        }
                    }

                } else {
                    if (mVCList != null) {
                        mVCList.update(cert, VerifiedCert.CHECKED);
                    }
                }

            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_AUTH_AGENT_PROCESS_CHECKING"), e);
            }
        }

        return revoked;
    }

    public boolean isReady() {
        return ready;
    }

    // for debug only
    public void sleepOneMinute() {
        boolean debugSleep = false;
        try {
            debugSleep = mConfig.getBoolean("debug.sleepOneMinute", false);
        } catch (Exception e) {
        }

        /* debugSleep: sleep for one minute to check something, e.g. ldap*/
        if (debugSleep == true) {
            logger.debug("debugSleep: about to sleep for one minute; do check now: e.g. ldap, hsm, etc.");
            try {
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                logger.warn("debugSleep: sleep out:" + e.toString());
            }
        }
    }

    /**
     * Go through all system certs and check to see if they are good and audit the result.
     * Optionally only check certs validity.
     *
     * @throws Exception if something is wrong
     */
    public void verifySystemCerts(boolean checkValidityOnly) throws Exception {

        String auditMessage = null;

        try {
            String certlist = config.getString(id + ".cert.list", "");
            if (certlist.equals("")) {
                logger.error("CMSEngine: Missing " + id + ".cert.list in CS.cfg");
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CIMC_CERT_VERIFICATION,
                            ILogger.SYSTEM_UID,
                            ILogger.FAILURE,
                            "");

                auditor.log(auditMessage);
                throw new Exception("Missing " + id + ".cert.list in CS.cfg");
            }

            LoggerConfig loggerConfig = config.getLoggingConfig().getLoggersConfig().getLoggerConfig("SignedAudit");
            String auditSigningNickname = loggerConfig.getSignedAuditCertNickname();

            StringTokenizer tokenizer = new StringTokenizer(certlist, ",");
            while (tokenizer.hasMoreTokens()) {
                String tag = tokenizer.nextToken();
                tag = tag.trim();
                logger.debug("CMSEngine: verifySystemCerts() cert tag=" + tag);

                // if audit signing nickname not configured, skip
                if ("audit_signing".equals(tag) && StringUtils.isEmpty(auditSigningNickname)) {
                    continue;
                }

                if (!checkValidityOnly) {
                    verifySystemCertByTag(tag);
                } else {
                    verifySystemCertByTag(tag, true);
                }
            }

        } catch (Exception e) {
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CIMC_CERT_VERIFICATION,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE,
                        "");

            auditor.log(auditMessage);
            throw e;
        }
    }

    /**
     * Verify a certificate by its tag name, do a full verification.
     *
     * @throws Exception if something is wrong
     */
    public void verifySystemCertByTag(String tag) throws Exception {
        verifySystemCertByTag(tag,false);
    }

    /**
     * Verify a certificate by its tag name.
     * Perform optional validity check only.
     *
     * @throws Exception if something is wrong
     */
    public void verifySystemCertByTag(String tag, boolean checkValidityOnly) throws Exception {

        logger.debug("CMSEngine: verifySystemCertByTag(" + tag + ")");
        String auditMessage = null;

        try {
            String nickname = config.getString(id + ".cert." + tag + ".nickname", "");
            if (nickname.equals("")) {
                logger.info("CMSEngine: Skipping " + tag + " cert verification");
                return;
            }

            String certusage = config.getString(id + ".cert." + tag + ".certusage", "");
            if (certusage.equals("")) {
                logger.warn("CMSEngine: verifySystemCertByTag() certusage for cert tag "
                        + tag + " undefined in CS.cfg, getting current certificate usage");
                // throw new Exception("Missing certificate usage for " + tag + " certificate"); ?
            }

            if (!checkValidityOnly) {
                CertUtil.verifyCertificateUsage(nickname, certusage);
            } else {
                CertUtil.verifyCertValidity(nickname);
            }

            auditMessage = CMS.getLogMessage(
                    AuditEvent.CIMC_CERT_VERIFICATION,
                    ILogger.SYSTEM_UID,
                    ILogger.SUCCESS,
                        nickname);

            auditor.log(auditMessage);

        } catch (Exception e) {
            logger.error("CMSEngine: verifySystemCertsByTag() failed: " + e.getMessage(), e);
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CIMC_CERT_VERIFICATION,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE,
                        "");

            auditor.log(auditMessage);
            throw e;
        }
    }

    /**
     * Get signed audit groups
     *
     * This method is called to extract all groups associated
     * with the audit subject ID.
     *
     * @param subjectID audit subject ID
     * @return a comma-delimited string of groups associated
     *         with the audit subject ID
     */
    public String getAuditGroups(String subjectID) {

        if (subjectID == null || subjectID.equals(ILogger.UNIDENTIFIED)) {
            return null;
        }

        Enumeration<Group> groups;

        try {
            groups = ugSubsystem.findGroups("*");

        } catch (Exception e) {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        while (groups.hasMoreElements()) {
            Group group = groups.nextElement();

            if (group.isMember(subjectID) == true) {
                if (sb.length() != 0) sb.append(", ");
                sb.append(group.getGroupID());
            }
        }

        if (sb.length() == 0) {
            return null;
        }

        return sb.toString();
    }
}
