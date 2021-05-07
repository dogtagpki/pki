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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpServlet;

import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.server.PKIServerSocketListener;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIRealm;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cms.tomcat.ProxyRealm;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.VerifiedCert;
import com.netscape.cmscore.authentication.VerifiedCerts;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.cert.OidLoaderSubsystem;
import com.netscape.cmscore.cert.X500NameSubsystem;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.logging.LogSubsystem;
import com.netscape.cmscore.registry.PluginRegistry;
import com.netscape.cmscore.request.CertRequestConstants;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.security.JssSubsystemConfig;
import com.netscape.cmscore.security.PWsdrCache;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmscore.session.LDAPSecurityDomainSessionTable;
import com.netscape.cmscore.session.SecurityDomainSessionTable;
import com.netscape.cmscore.session.SessionTimer;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;
import com.netscape.cmsutil.util.NuxwdogUtil;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

public class CMSEngine implements ServletContextListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSEngine.class);

    private static final String SERVER_XML = "server.xml";

    // used for testing HSM issues
    public static final String PROP_SIGNED_AUDIT_CERT_NICKNAME =
                              "log.instance.SignedAudit.signedAuditCertNickname";

    public String id;
    public String name;

    public String instanceDir; /* path to instance <server-root>/cert-<instance-name> */
    private String instanceId;
    private int pid;

    protected EngineConfig config;
    protected EngineConfig mConfig;
    protected ServerXml serverXml;

    private boolean mExcludedLdapAttrsEnabled = false;
    // AutoSD : AutoShutdown
    private String mAutoSD_CrumbFile = null;
    private boolean mAutoSD_Restart = false;
    private int mAutoSD_RestartMax = 3;
    private int mAutoSD_RestartCount = 0;
    private PrivateKey mSigningKey = null;
    private byte[] mSigningData = null;
    private long mStartupTime = 0;
    private boolean isStarted = false;
    private IPasswordStore mPasswordStore = null;
    private ISecurityDomainSessionTable mSecurityDomainSessionTable = null;
    private Timer mSDTimer = null;
    private String mServerCertNickname = null;
    private boolean ready;

    private Debug debug = new Debug();
    private PluginRegistry pluginRegistry = new PluginRegistry();
    protected LogSubsystem logSubsystem = LogSubsystem.getInstance();
    protected JssSubsystem jssSubsystem = JssSubsystem.getInstance();
    protected DBSubsystem dbSubsystem = new DBSubsystem();

    protected RequestRepository requestRepository;
    protected RequestQueue requestQueue;

    protected UGSubsystem ugSubsystem = new UGSubsystem();
    protected OidLoaderSubsystem oidLoaderSubsystem = OidLoaderSubsystem.getInstance();
    protected X500NameSubsystem x500NameSubsystem = X500NameSubsystem.getInstance();
    protected RequestSubsystem requestSubsystem = new RequestSubsystem();
    protected AuthSubsystem authSubsystem;
    protected AuthzSubsystem authzSubsystem = AuthzSubsystem.getInstance();
    protected JobsScheduler jobsScheduler = JobsScheduler.getInstance();

    public final Map<String, SubsystemInfo> subsystemInfos = new LinkedHashMap<>();
    public final Map<String, ISubsystem> subsystems = new LinkedHashMap<>();

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


    public CMSEngine(String name) {
        this.id = name.toLowerCase();
        this.name = name;

        logger.info("Creating " + name + " engine");
    }

    public PluginRegistry getPluginRegistry() {
        return pluginRegistry;
    }

    public LogSubsystem getLogSubsystem() {
        return logSubsystem;
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

    public JobsScheduler getJobsScheduler() {
        return jobsScheduler;
    }

    public RequestNotifier getRequestNotifier() {
        return requestNotifier;
    }

    public void setRequestNotifier(RequestNotifier requestNotifier) {
        this.requestNotifier = requestNotifier;
    }

    public Enumeration<String> getRequestListenerNames() {
        return requestNotifier.getListenerNames();
    }

    public IRequestListener getRequestListener(String name) {
        return requestNotifier.getListener(name);
    }

    public void registerRequestListener(IRequestListener listener) {
        requestNotifier.registerListener(listener);
    }

    public void registerRequestListener(String name, IRequestListener listener) {
        requestNotifier.registerListener(name, listener);
    }

    public void removeRequestListener(IRequestListener listener) {
        requestNotifier.removeListener(listener);
    }

    public void removeRequestListener(String name) {
        requestNotifier.removeListener(name);
    }

    public RequestNotifier getPendingNotifier() {
        return pendingNotifier;
    }

    public void setPendingNotifier(RequestNotifier pendingNotifier) {
        this.pendingNotifier = pendingNotifier;
    }

    public IRequestListener getPendingListener(String name) {
        return pendingNotifier.getListener(name);
    }

    public void registerPendingListener(IRequestListener listener) {
        pendingNotifier.registerListener(listener);
    }

    public void registerPendingListener(String name, IRequestListener listener) {
        pendingNotifier.registerListener(name, listener);
    }

    public void loadConfig(String path) throws Exception {
        ConfigStorage storage = new FileConfigStore(path);
        config = createConfig(storage);
        config.load();

        instanceDir = config.getInstanceDir();
        instanceId = config.getInstanceID();

        mConfig = config;
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new EngineConfig(storage);
    }

    /**
     * Retrieves the instance root path of this server.
     */
    public String getInstanceDir() {
        return instanceDir;
    }

    public synchronized IPasswordStore getPasswordStore() throws EBaseException {
        if (mPasswordStore == null) {
            try {
                PasswordStoreConfig psc = mConfig.getPasswordStoreConfig();
                mPasswordStore = IPasswordStore.create(psc);
            } catch (Exception e) {
                throw new EBaseException(
                    "Failed to initialise password store: " + e.getMessage(), e);
            }
        }
        return mPasswordStore;
    }

    public void initDebug() throws Exception {
        IConfigStore debugConfig = config.getSubStore(Debug.ID);
        debug.init(debugConfig);
    }

    public void initSubsystemListeners() throws Exception {

        logger.info("CMSEngine: Initializing subsystem listeners");

        IConfigStore listenersConfig = config.getSubStore("listeners");

        if (listenersConfig.size() == 0) {
            listenersConfig = config.getSubStore("startupNotifiers");

            if (listenersConfig.size() > 0) {
                String subsystem = config.getType().toLowerCase();
                String configPath = instanceDir + "/conf/" + subsystem + "/CS.cfg";
                logger.warn("The 'startupNotifiers' property in " + configPath + " has been deprecated. Use 'listeners' instead.");
            }
        }

        String ids = listenersConfig.getString("list", null);
        if (ids == null) return;

        for (String id : ids.split(",")) {
            id = id.trim();
            if (id.isEmpty()) continue;

            IConfigStore instanceConfig = listenersConfig.getSubStore(id);
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

        boolean skipPublishingCheck = config.getBoolean("cms.password.ignore.publishing.failure", true);
        String pwList = config.getString("cms.passwordlist", "internaldb,replicationdb");
        String tags[] = StringUtils.split(pwList, ",");
        LDAPConfig ldapConfig = config.getInternalDBConfig();
        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        for (String tag : tags) {

            logger.info("CMSEngine: initializing password store for " + tag);

            String binddn;
            String authType;
            LdapConnInfo connInfo = null;

            if (tag.equals("internaldb")) {

                authType = authConfig.getString("authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        connConfig.getString("host"),
                        connConfig.getInteger("port"),
                        connConfig.getBoolean("secureConn"));

                binddn = authConfig.getString("bindDN");

            } else if (tag.equals("replicationdb")) {

                authType = authConfig.getString("authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        connConfig.getString("host"),
                        connConfig.getInteger("port"),
                        connConfig.getBoolean("secureConn"));

                binddn = "cn=Replication Manager masterAgreement1-" + config.getHostname() + "-" +
                        config.getInstanceID() + ",cn=config";

            } else if (tags.equals("CA LDAP Publishing")) {

                LDAPConfig publishConfig = config.getSubStore("ca.publish.ldappublish.ldap", LDAPConfig.class);
                LDAPAuthenticationConfig publishAuthConfig = publishConfig.getAuthenticationConfig();

                authType = publishAuthConfig.getString("authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                LDAPConnectionConfig publishConnConfig = publishConfig.getConnectionConfig();

                connInfo = new LdapConnInfo(
                        publishConnConfig.getString("host"),
                        publishConnConfig.getInteger("port"),
                        publishConnConfig.getBoolean("secureConn"));

                binddn = publishAuthConfig.getString("bindDN");

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
                if (authPrefix ==  null) {
                    logger.debug("CMSEngine.initializePasswordStore(): authPrefix not found...skipping");
                    continue;
                }
                logger.debug("CMSEngine.initializePasswordStore(): authPrefix=" + authPrefix);

                LDAPConfig prefixConfig = config.getSubStore(authPrefix + ".ldap", LDAPConfig.class);
                LDAPAuthenticationConfig prefixAuthConfig = prefixConfig.getAuthenticationConfig();

                authType = prefixAuthConfig.getString("authtype", "BasicAuth");
                logger.debug("CMSEngine.initializePasswordStore(): authType " + authType);
                if (!authType.equals("BasicAuth"))
                    continue;

                LDAPConnectionConfig prefixConnConfig = prefixConfig.getConnectionConfig();

                connInfo = new LdapConnInfo(
                        prefixConnConfig.getString("host"),
                        prefixConnConfig.getInteger("port"),
                        prefixConnConfig.getBoolean("secureConn"));

                binddn = prefixAuthConfig.getString("bindDN", null);
                if (binddn == null) {
                    logger.debug("CMSEngine.initializePasswordStore(): binddn not found...skipping");
                    continue;
                }
            }

            int iteration = 0;
            int result = PW_INVALID_CREDENTIALS;

            do {
                String passwd = mPasswordStore.getPassword(tag, iteration);
                result = testLDAPConnection(tag, connInfo, binddn, passwd);
                iteration++;
            } while ((result == PW_INVALID_CREDENTIALS) && (iteration < PW_MAX_ATTEMPTS));

            if (result != PW_OK) {
                if ((result == PW_INVALID_CREDENTIALS) && (tag.equals("replicationdb"))) {
                    logger.warn(
                        "CMSEngine: password test execution failed for replicationdb " +
                        "with NO_SUCH_USER. This may not be a latest instance. Ignoring ..");

                } else if (skipPublishingCheck && (result == PW_CANNOT_CONNECT) && (tag.equals("CA LDAP Publishing"))) {
                    logger.warn(
                        "CMSEngine: Unable to connect to the publishing database to check password, " +
                        "but continuing to start up. Please check if publishing is operational.");
                } else {
                    // password test failed
                    logger.error("CMSEngine: password test execution failed: " + result);
                    throw new EBaseException("Password test execution failed. Is the database up?");
                }
            }
        }
    }

    public int testLDAPConnection(String name, LdapConnInfo info, String binddn, String pwd) {

        int ret = PW_OK;

        if (StringUtils.isEmpty(pwd)) {
            return PW_INVALID_CREDENTIALS;
        }

        String host = info.getHost();
        int port = info.getPort();

        PKISocketConfig socketConfig = mConfig.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory(info.getSecure());
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

        logger.info("CMSEngine: Java version: " + System.getProperty("java.version"));

        Security.addProvider(new org.mozilla.jss.netscape.security.provider.CMS());

        logger.info("CMSEngine: security providers:");
        for (Provider provider : Security.getProviders()) {
            logger.debug("CMSEngine: - " + provider);
        }
    }

    public void initDatabase() throws Exception {
    }

    public void initPluginRegistry() throws Exception {
        IConfigStore pluginRegistryConfig = config.getSubStore(PluginRegistry.ID);
        String subsystem = config.getType().toLowerCase();
        String defaultRegistryFile = instanceDir + "/conf/" + subsystem + "/registry.cfg";
        pluginRegistry.init(pluginRegistryConfig, defaultRegistryFile);
        pluginRegistry.startup();
    }

    public void initLogSubsystem() throws Exception {
        IConfigStore logConfig = config.getSubStore(LogSubsystem.ID);
        logSubsystem.init(logConfig);
        logSubsystem.startup();
    }

    public void initJssSubsystem() throws Exception {
        JssSubsystemConfig jssConfig = config.getJssSubsystemConfig();
        jssSubsystem.init(jssConfig);
        jssSubsystem.startup();
    }

    public void initDBSubsystem() throws Exception {

        DatabaseConfig dbConfig = config.getDatabaseConfig();
        PKISocketConfig socketConfig = config.getSocketConfig();
        IPasswordStore passwordStore = getPasswordStore();

        dbSubsystem.init(dbConfig, socketConfig, passwordStore);
    }

    public void initUGSubsystem() throws Exception {

        PKISocketConfig socketConfig = config.getSocketConfig();
        UGSubsystemConfig ugConfig = config.getUGSubsystemConfig();
        IPasswordStore passwordStore = getPasswordStore();

        ugSubsystem.init(socketConfig, ugConfig, passwordStore);
    }

    public void initOIDLoaderSubsystem() throws Exception {
        IConfigStore oidLoaderConfig = config.getSubStore(OidLoaderSubsystem.ID);
        oidLoaderSubsystem.init(oidLoaderConfig);
        oidLoaderSubsystem.startup();
    }

    public void initX500NameSubsystem() throws Exception {
        IConfigStore x500NameConfig = config.getSubStore(X500NameSubsystem.ID);
        x500NameSubsystem.init(x500NameConfig);
        x500NameSubsystem.startup();
    }

    public void initRequestSubsystem() throws Exception {
        IConfigStore requestConfig = config.getSubStore(RequestSubsystem.ID);
        requestSubsystem.init(requestConfig, dbSubsystem);
        requestSubsystem.startup();
    }

    public void initAuthSubsystem() throws Exception {
        AuthenticationConfig authConfig = config.getAuthenticationConfig();
        authSubsystem = new AuthSubsystem();
        authSubsystem.init(authConfig);
        authSubsystem.startup();
    }

    public void initAuthzSubsystem() throws Exception {
        IConfigStore authzConfig = config.getSubStore(AuthzSubsystem.ID);
        authzSubsystem.init(authzConfig);
        authzSubsystem.startup();
    }

    public void initJobsScheduler() throws Exception {
        IConfigStore jobsSchedulerConfig = config.getSubStore(JobsScheduler.ID);
        jobsScheduler.init(jobsSchedulerConfig);
        jobsScheduler.startup();
    }

    public void configurePorts() throws Exception {

        String instanceRoot = config.getInstanceDir();
        String path = instanceRoot + File.separator + "conf" + File.separator + SERVER_XML;

        serverXml = ServerXml.load(path);
        unsecurePort = serverXml.getUnsecurePort();
        securePort = serverXml.getSecurePort();

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
        if (sd.equals("existing")) {
            return;
        }

        // monitor security domain sessions

        // my default is 1 day
        String source = config.getString("securitydomain.source", "memory");
        String flushInterval = config.getString("securitydomain.flushinterval", "86400000");
        String checkInterval = config.getString("securitydomain.checkinterval", "5000");

        if (source.equals("ldap")) {
            mSecurityDomainSessionTable = new LDAPSecurityDomainSessionTable(Long.parseLong(flushInterval));
        } else {
            mSecurityDomainSessionTable = new SecurityDomainSessionTable(Long.parseLong(flushInterval));
        }

        SessionTimer task = new SessionTimer(mSecurityDomainSessionTable);

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

    public Configurator createConfigurator() throws Exception {
        return new Configurator(this);
    }

    public IConfigStore createFileConfigStore(String path) throws EBaseException {
        try {
            /* if the file is not there, create one */
            File f = new File(path);
            f.createNewFile();

            ConfigStorage storage = new FileConfigStore(path);
            IConfigStore cs = new PropConfigStore(storage);
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

    public ISecurityDomainSessionTable getSecurityDomainSessionTable() {
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

    public Collection<ISubsystem> getSubsystems() {
        return subsystems.values();
    }

    public ISubsystem getSubsystem(String name) {
        return subsystems.get(name);
    }

    public void setSubsystemEnabled(String id, boolean enabled) {
        SubsystemInfo si = subsystemInfos.get(id);
        si.enabled = enabled;
    }

    /**
     * load subsystems
     */
    protected void loadSubsystems() throws Exception {

        subsystemInfos.clear();
        subsystems.clear();

        SubsystemsConfig subsystemsConfig = mConfig.getSubsystemsConfig();

        for (String subsystemNumber : subsystemsConfig.getSubsystemNames()) {
            SubsystemConfig subsystemConfig = subsystemsConfig.getSubsystemConfig(subsystemNumber);
            String id = subsystemConfig.getID();
            logger.info("CMSEngine: Loading " + id + " subsystem");

            String className = subsystemConfig.getClassName();
            boolean enabled = subsystemConfig.isEnabled();

            ISubsystem subsystem = (ISubsystem) Class.forName(className).getDeclaredConstructor().newInstance();

            SubsystemInfo subsystemInfo = new SubsystemInfo(id);
            subsystemInfo.setEnabled(enabled);
            subsystemInfo.setUpdateIdOnInit(true);

            subsystems.put(id, subsystem);
            subsystemInfos.put(id, subsystemInfo);
        }
    }

    public void initSubsystem(ISubsystem subsystem, IConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof SelfTestSubsystem) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        subsystem.init(subsystemConfig);
    }

    public void initSubsystems() throws Exception {

        for (String id : subsystems.keySet()) {
            logger.info("CMSEngine: Initializing " + id + " subsystem");

            ISubsystem subsystem = subsystems.get(id);
            SubsystemInfo subsystemInfo = subsystemInfos.get(id);

            if (subsystemInfo.updateIdOnInit) {
                subsystem.setId(id);
            }

            if (!subsystemInfo.enabled) {
                logger.info("CMSEngine: " + id + " subsystem is disabled");
                continue;
            }

            IConfigStore subsystemConfig = mConfig.getSubStore(id);
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
         * autoShutdown.crumbFile=[PKI_INSTANCE_PATH]/logs/autoShutdown.crumb
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
        String mSAuditCertNickName = config.getString(PROP_SIGNED_AUDIT_CERT_NICKNAME);
        logger.debug("CMSEngine: audit signing cert: " + mSAuditCertNickName);

        CryptoManager mManager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate cert = mManager.findCertByNickname(mSAuditCertNickName);

        mSigningKey = mManager.findPrivKeyByCert(cert);
        mSigningData = cert.getPublicKey().getEncoded();
    }

    public void configureServerCertNickname() throws EBaseException {

        String id = mConfig.getType().toLowerCase();

        if (id.equals("ca") || id.equals("ocsp") ||
                id.equals("kra") || id.equals("tks")) {

            logger.info("CMSEngine: Configuring servlet certificate nickname");
            IConfigStore serverCertStore = mConfig.getSubStore(id + "." + "sslserver");

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

    public void configureExcludedLdapAttrs() throws EBaseException {

        String id = mConfig.getType().toLowerCase();

        if (id.equals("ca") || id.equals("kra")) {

            logger.info("CMSEngine: Configuring excluded LDAP attributes");
            /*
              figure out if any ldap attributes need exclusion in enrollment records
              Default config:
                excludedLdapAttrs.enabled=false;
                (excludedLdapAttrs.attrs unspecified to take default)
             */
            mExcludedLdapAttrsEnabled = mConfig.getBoolean("excludedLdapAttrs.enabled", false);
            logger.debug("CMSEngine: excludedLdapAttrs.enabled: " + mExcludedLdapAttrsEnabled);

            if (mExcludedLdapAttrsEnabled) {

                excludedLdapAttrsList = Arrays.asList(excludedLdapAttrs);
                String unparsedExcludedLdapAttrs = "";

                try {
                    unparsedExcludedLdapAttrs = mConfig.getString("excludedLdapAttrs.attrs");
                    logger.debug("CMSEngine: excludedLdapAttrs.attrs: " + unparsedExcludedLdapAttrs);
                } catch (EPropertyNotFound e) {
                    logger.debug("CMSEngine: excludedLdapAttrs.attrs unspecified, using the default: " + unparsedExcludedLdapAttrs);
                }

                if (!unparsedExcludedLdapAttrs.equals("")) {
                    excludedLdapAttrsList = Arrays.asList(unparsedExcludedLdapAttrs.split(","));
                    // overwrites the default
                    //excludedLdapAttrSet = new HashSet(excludedLdapAttrsList);
                }
            }
        }
    }

    public boolean isExcludedLdapAttrsEnabled() {
        return mExcludedLdapAttrsEnabled;
    }

    public boolean isExcludedLdapAttr(String key) {
        if (isExcludedLdapAttrsEnabled()) {
            return excludedLdapAttrsList.contains(key);
        } else {
            return false;
        }
    }

    // default for excludedLdapAttrs.enabled == false
    // can be overwritten with excludedLdapAttrs.attrs
    public List<String> excludedLdapAttrsList = new ArrayList<String>();

    public static String excludedLdapAttrs[] = {
            "req_x509info",
            "publickey",
            "req_extensions",
            "cert_request",
            "req_archive_options",
            "req_key"
    };

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

    protected void startupSubsystems() throws Exception {

        for (ISubsystem subsystem : subsystems.values()) {
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

        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String subsystemConfDir = serverConfDir + File.separator + id;

        String path = subsystemConfDir + File.separator + "CS.cfg";
        loadConfig(path);

        CMS.setCMSEngine(this);

        initDebug();
        initPasswordStore();
        initSubsystemListeners();
        initSecurityProvider();
        initPluginRegistry();
        initDatabase();
        initLogSubsystem();
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
        initJobsScheduler();

        configureAutoShutdown();
        configureServerCertNickname();
        configureExcludedLdapAttrs();

        initSecurityDomain();

        // Register realm for this subsystem
        ProxyRealm.registerRealm(id, new PKIRealm());

        // Register TomcatJSS socket listener
        TomcatJSS tomcatJss = TomcatJSS.getInstance();
        tomcatJss.addSocketListener(new PKIServerSocketListener());

        ready = true;
        isStarted = true;

        mStartupTime = System.currentTimeMillis();

        logger.info(name + " engine started");
        notifySubsystemStarted();
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
            if (tokenName.equals("") && nickName.equals(""))
                return; // not sure the logic
            else
                newName = tokenName + ":" + nickName;
        }
        setServerCertNickname(newName);
    }

    public void setServerCertNickname(String newName) {
        mServerCertNickname = newName;
    }

    public IMailNotification getMailNotification() {
        try {
            String className = mConfig.getString("notificationClassName",
                    "com.netscape.cms.notification.MailNotification");
            IMailNotification notification = (IMailNotification) Class.forName(className).getDeclaredConstructor().newInstance();

            return notification;
        } catch (Exception e) {
            return null;
        }
    }

    public IPasswordCheck getPasswordChecker() {
        try {
            String className = mConfig.getString("passwordCheckerClass",
                    "com.netscape.cms.password.PasswordChecker");
            IPasswordCheck check = (IPasswordCheck) Class.forName(className).getDeclaredConstructor().newInstance();

            return check;
        } catch (Exception e) {
            return null;
        }
    }

    public ISharedToken getSharedTokenClass(String configName) {
        String method = "CMSEngine: getSharedTokenClass: ";
        ISharedToken tokenClass = null;

        String name = null;
        try {
            logger.debug(method + "getting :" + configName);
            name = mConfig.getString(configName);
            logger.debug(method + "Shared Secret plugin class name retrieved:" +
                    name);
        } catch (Exception e) {
            logger.warn(method + " Failed to retrieve shared secret plugin class name");
            return null;
        }

        try {
            tokenClass = (ISharedToken) Class.forName(name).getDeclaredConstructor().newInstance();
            logger.debug(method + "Shared Secret plugin class retrieved");
        } catch (Exception e) {
            logger.warn("CMSEngine: " + e.getMessage(), e);
            return null;
        }

        return tokenClass;
    }

    public void disableRequests() {
        CommandQueue.mShuttingDown = true;
    }

    public boolean areRequestsDisabled() {
        return CommandQueue.mShuttingDown;
    }

    public void terminateRequests() {
        Enumeration<ICMSRequest> e = CommandQueue.mCommandQueue.keys();

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
        jobsScheduler.shutdown();
    }

    public void shutdownAuthzSubsystem() {
        authzSubsystem.shutdown();
    }

    public void shutdownAuthSubsystem() {
        authSubsystem.shutdown();
    }

    public void shutdownRequestSubsystem() {
        requestSubsystem.shutdown();
    }

    public void shutdownX500NameSubsystem() {
        x500NameSubsystem.shutdown();
    }

    public void shutdownOIDLoaderSubsystem() {
        oidLoaderSubsystem.shutdown();
    }

    public void shutdownUGSubsystem() {
        ugSubsystem.shutdown();
    }

    public void shutdownDBSubsystem() {
        dbSubsystem.shutdown();
    }

    public void shutdownJSSSubsystem() {
        jssSubsystem.shutdown();
    }

    public void shutdownLogSubsystem() {
        logSubsystem.shutdown();
    }

    public void shutdownDatabase() {
    }

    public void shutdownPluginRegistry() {
        pluginRegistry.shutdown();
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     */
    public void shutdown() {

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
        List<ISubsystem> list = new ArrayList<>();
        list.addAll(subsystems.values());
        Collections.reverse(list);

        for (ISubsystem subsystem : list) {
            logger.debug("CMSEngine: Stopping " + subsystem.getId() + " subsystem");
            subsystem.shutdown();
        }
    }

    /**
     * returns the main config store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public EngineConfig getConfig() {
        return mConfig;
    }

    public ServerXml getServerXml() {
        return serverXml;
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
            IRequest checkRevReq = null;

            try {
                checkRevReq = requestRepository.createRequest(CertRequestConstants.GETREVOCATIONINFO_REQUEST);
                checkRevReq.setExtData(IRequest.REQ_TYPE, CertRequestConstants.GETREVOCATIONINFO_REQUEST);
                checkRevReq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_RA);

                X509CertImpl agentCerts[] = new X509CertImpl[certificates.length];
                for (int i = 0; i < certificates.length; i++) {
                    agentCerts[i] = (X509CertImpl) certificates[i];
                }

                checkRevReq.setExtData(IRequest.ISSUED_CERTS, agentCerts);

                requestQueue.processRequest(checkRevReq);

                RequestStatus status = checkRevReq.getRequestStatus();

                if (status == RequestStatus.COMPLETE) {
                    Enumeration<String> keys = checkRevReq.getExtDataKeys();
                    while (keys.hasMoreElements()) {
                        String name = keys.nextElement();

                        if (name.equals(IRequest.REVOKED_CERTS)) {
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

    public void contextInitialized(ServletContextEvent event) {

        String path = event.getServletContext().getContextPath();
        if ("".equals(path)) {
            id = "ROOT";
        } else {
            id = path.substring(1);
        }

        try {
            start();

        } catch (Exception e) {
            logger.error("Unable to start " + name + " engine: " + e.getMessage(), e);
            shutdown();
            throw new RuntimeException("Unable to start " + name + " engine: " + e.getMessage(), e);
        }
    }

    public void contextDestroyed(ServletContextEvent event) {
        shutdown();
    }
}
