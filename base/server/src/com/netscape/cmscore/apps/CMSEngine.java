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
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpServlet;

import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.server.PKIServerSocketListener;
import org.dogtagpki.server.ca.ICertificateAuthority;
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
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ConsoleError;
import com.netscape.certsrv.logging.SystemEvent;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
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
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.logging.LogSubsystem;
import com.netscape.cmscore.registry.PluginRegistry;
import com.netscape.cmscore.request.CertRequestConstants;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.security.PWsdrCache;
import com.netscape.cmscore.session.LDAPSecurityDomainSessionTable;
import com.netscape.cmscore.session.SecurityDomainSessionTable;
import com.netscape.cmscore.session.SessionTimer;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;
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
    protected DBSubsystem dbSubsystem = DBSubsystem.getInstance();
    protected UGSubsystem ugSubsystem = new UGSubsystem();
    private RequestSubsystem requestSubsystem = new RequestSubsystem();

    public Collection<String> staticSubsystems = new LinkedHashSet<>();
    public Collection<String> dynSubsystems = new LinkedHashSet<>();
    public Collection<String> finalSubsystems = new LinkedHashSet<>();

    public final Map<String, SubsystemInfo> subsystemInfos = new HashMap<>();
    public final Map<String, ISubsystem> subsystems = new HashMap<>();

    public String hostname;
    public String unsecurePort;
    public String securePort;

    private static final int PW_OK =0;
    //private static final int PW_BAD_SETUP = 1;
    private static final int PW_INVALID_PASSWORD = 2;
    private static final int PW_CANNOT_CONNECT = 3;
    private static final int PW_NO_USER = 4;
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

    public UGSubsystem getUGSubsystem() {
        return ugSubsystem;
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
                /* mConfig.getProperties() is O(n), but we cache the returned
                 * password store so this is fine */
                mPasswordStore =
                    IPasswordStore.getPasswordStore(instanceId, mConfig.getProperties());
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
            int result = PW_INVALID_PASSWORD;

            do {
                String passwd = mPasswordStore.getPassword(tag, iteration);
                result = testLDAPConnection(tag, connInfo, binddn, passwd);
                iteration++;
            } while ((result == PW_INVALID_PASSWORD) && (iteration < PW_MAX_ATTEMPTS));

            if (result != PW_OK) {
                if ((result == PW_NO_USER) && (tag.equals("replicationdb"))) {
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
            return PW_INVALID_PASSWORD;
        }

        String host = info.getHost();
        int port = info.getPort();

        PKISocketFactory socketFactory = new PKISocketFactory(info.getSecure());
        socketFactory.init(mConfig);

        LDAPConnection conn = new LDAPConnection(socketFactory);

        try {
            logger.info("CMSEngine: verifying connection to " + host + ":" + port + " as " + binddn);
            conn.connect(host, port, binddn, pwd);

        } catch (LDAPException e) {

            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                logger.debug("CMSEngine: user does not exist: " + binddn);
                ret = PW_NO_USER;
                break;
            case LDAPException.INVALID_CREDENTIALS:
                logger.debug("CMSEngine: invalid password");
                ret = PW_INVALID_PASSWORD;
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
        IConfigStore jssConfig = config.getSubStore(JssSubsystem.ID);
        jssSubsystem.init(jssConfig);
        jssSubsystem.startup();
    }

    public void initDBSubsystem() throws Exception {
        IConfigStore dbConfig = config.getSubStore(DBSubsystem.ID);
        dbSubsystem.init(dbConfig);
        dbSubsystem.startup();
    }

    public void initUGSubsystem() throws Exception {
        IConfigStore ugConfig = config.getSubStore(UGSubsystem.ID);
        ugSubsystem.init(ugConfig);
        ugSubsystem.startup();
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

        configureAutoShutdown();
        configureServerCertNickname();
        configureExcludedLdapAttrs();
        configurePorts();

        initSecurityDomain();
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

    public String getEEHost() {
        String host = "";
        try {
            host = mConfig.getHostname();
        } catch (Exception e) {
        }
        return host;
    }

    public String getEENonSSLHost() {
        String host = "";
        try {
            host = mConfig.getHostname();
        } catch (Exception e) {
        }
        return host;
    }

    public String getEENonSSLIP() {
        return hostname;
    }

    public String getEENonSSLPort() {
        return unsecurePort;
    }

    public String getEESSLHost() {
        String host = "";
        try {
            host = mConfig.getHostname();
        } catch (Exception e) {
        }
        return host;
    }

    public String getEESSLIP() {
        return hostname;
    }

    public String getEESSLPort() {
        return securePort;
    }

    public String getEEClientAuthSSLPort() {
        return securePort;
    }

    public String getAgentHost() {
        String host = "";
        try {
            host = mConfig.getHostname();
        } catch (Exception e) {
        }
        return host;
    }

    public String getAgentIP() {
        return hostname;
    }

    public String getAgentPort() {
        return securePort;
    }

    public String getAdminHost() {
        String host = "";
        try {
            host = mConfig.getHostname();
        } catch (Exception e) {
        }
        return host;
    }

    public String getAdminIP() {
        return hostname;
    }

    public String getAdminPort() {
        return securePort;
    }

    public SubsystemInfo addSubsystem(String id, ISubsystem instance) {

        logger.info("CMSEngine: adding " + id + " subsystem");

        SubsystemInfo si = new SubsystemInfo(id);
        subsystems.put(id, instance);
        subsystemInfos.put(id, si);
        return si;
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
    protected void loadSubsystems() throws EBaseException {

        logger.info("CMSEngine: loading static subsystems");

        staticSubsystems.clear();
        dynSubsystems.clear();
        finalSubsystems.clear();

        subsystemInfos.clear();
        subsystems.clear();

        staticSubsystems.add(OidLoaderSubsystem.ID);
        addSubsystem(OidLoaderSubsystem.ID, OidLoaderSubsystem.getInstance());

        staticSubsystems.add(X500NameSubsystem.ID);
        addSubsystem(X500NameSubsystem.ID, X500NameSubsystem.getInstance());

        // skip TP subsystem;
        // problem in needing dbsubsystem in constructor. and it's not used.

        staticSubsystems.add(RequestSubsystem.ID);
        addSubsystem(RequestSubsystem.ID, requestSubsystem);

        logger.info("CMSEngine: loading dynamic subsystems");

        SubsystemsConfig ssconfig = mConfig.getSubsystemsConfig();

        for (String ssName : ssconfig.getSubsystemNames()) {
            SubsystemConfig subsystemConfig = ssconfig.getSubsystemConfig(ssName);

            String id = subsystemConfig.getID();
            String classname = subsystemConfig.getClassName();
            boolean enabled = subsystemConfig.isEnabled();

            ISubsystem ss = null;
            try {
                ss = (ISubsystem) Class.forName(classname).newInstance();
            } catch (InstantiationException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()), e);
            } catch (IllegalAccessException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()), e);
            } catch (ClassNotFoundException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()), e);
            }

            dynSubsystems.add(id);

            SubsystemInfo si = addSubsystem(id, ss);
            si.setEnabled(enabled);
            si.setUpdateIdOnInit(true);
        }

        logger.info("CMSEngine: loading final subsystems");

        finalSubsystems.add(AuthSubsystem.ID);
        addSubsystem(AuthSubsystem.ID, AuthSubsystem.getInstance());

        finalSubsystems.add(AuthzSubsystem.ID);
        addSubsystem(AuthzSubsystem.ID, AuthzSubsystem.getInstance());

        finalSubsystems.add(JobsScheduler.ID);
        addSubsystem(JobsScheduler.ID, JobsScheduler.getInstance());
    }

    protected void initSubsystems() throws Exception {

        logger.info("CMSEngine: Initializing subsystems");

        initSubsystems(staticSubsystems);
        initSubsystems(dynSubsystems);
        initSubsystems(finalSubsystems);
    }

    private void initSubsystems(Collection<String> ids)
            throws EBaseException {
        for (String id : ids) {
            SubsystemInfo si = subsystemInfos.get(id);
            initSubsystem(si);
        }
    }

    /**
     * initialize a subsystem
     */
    private void initSubsystem(SubsystemInfo ssinfo)
            throws EBaseException {

        String id = ssinfo.id;
        logger.info("CMSEngine: Initializing " + id + " subsystem");

        ISubsystem ss = subsystems.get(id);

        if (ssinfo.updateIdOnInit) {
            ss.setId(id);
        }

        if (!ssinfo.enabled) {
            logger.info("CMSEngine: " + id + " subsystem is disabled");
            return;
        }

        IConfigStore ssConfig = mConfig.getSubStore(id);
        ss.init(ssConfig);
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
            ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString())));

            logger.warn(method + "autoShutdown for " + e.getMessage(), e);

            autoShutdown();
        } catch (Exception e) {
            logger.warn(method + "continue for " + e.getMessage(), e);
        }
        logger.debug(method + "passed; continue");
    }

    public void reinit(String id) throws EBaseException {

        logger.info("CMSEngine: reinitializing " + id + " subsystem");

        ISubsystem system = getSubsystem(id);
        IConfigStore cs = mConfig.getSubStore(id);
        system.init(cs);
    }

    public void startupSubsystems() throws EBaseException {
        startupSubsystems(staticSubsystems);
        startupSubsystems(dynSubsystems);
        startupSubsystems(finalSubsystems);

        // global admin servlet. (anywhere else more fit for this ?)
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
        initSecurityProvider();
        initPluginRegistry();
        initDatabase();
        initLogSubsystem();
        initJssSubsystem();
        initDBSubsystem();
        initUGSubsystem();

        init();

        startupSubsystems();

        // Register realm for this subsystem
        ProxyRealm.registerRealm(id, new PKIRealm());

        // Register TomcatJSS socket listener
        TomcatJSS tomcatJss = TomcatJSS.getInstance();
        tomcatJss.addSocketListener(new PKIServerSocketListener());

        ready = true;
        isStarted = true;

        mStartupTime = System.currentTimeMillis();

        logger.info(name + " engine started");
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
            IMailNotification notification = (IMailNotification)
                    Class.forName(className).newInstance();

            return notification;
        } catch (Exception e) {
            return null;
        }
    }

    public IPasswordCheck getPasswordChecker() {
        try {
            String className = mConfig.getString("passwordCheckerClass",
                    "com.netscape.cms.password.PasswordChecker");
            IPasswordCheck check = (IPasswordCheck)
                    Class.forName(className).newInstance();

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
            tokenClass = (ISharedToken) Class.forName(name).newInstance();
            logger.debug(method + "Shared Secret plugin class retrieved");
        } catch (ClassNotFoundException e) {
            logger.warn(method + " Failed to find class name: " + name);
            return null;
        } catch (InstantiationException e) {
            logger.warn("EnrollProfile: Failed to instantiate class: " + name);
            return null;
        } catch (IllegalAccessException e) {
            logger.warn(method + " Illegal access: " + name);
            return null;
        }

        return tokenClass;
    }

    private void startupSubsystems(Collection<String> ids)
            throws EBaseException {

        for (String id : ids) {
            ISubsystem subsystem = subsystems.get(id);

            logger.info("CMSEngine: starting subsystem " + id);
            subsystem.startup();
        }
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

        shutdownSubsystems(finalSubsystems);
        shutdownSubsystems(dynSubsystems);
        shutdownSubsystems(staticSubsystems);

        if (mSDTimer != null) {
            mSDTimer.cancel();
        }

        if (mSecurityDomainSessionTable != null) {
            mSecurityDomainSessionTable.shutdown();
        }

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

    private void shutdownSubsystems(Collection<String> ids) {
        // reverse list of subsystems
        List<String> list = new ArrayList<>();
        list.addAll(ids);
        Collections.reverse(list);

        for (String id : list) {
            ISubsystem subsystem = subsystems.get(id);

            logger.debug("CMSEngine: stopping " + id);
            subsystem.shutdown();
            logger.debug("CMSEngine: " + id + " stopped");
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

    public static void upgradeConfig(IConfigStore c)
            throws EBaseException {
        String version = c.getString("cms.version", "pre4.2");

        if (version.equals("4.22")) {
            Upgrade.perform422to45(c);
        } else if (version.equals("4.2")) {
            // SUPPORT UPGRADE FROM 4.2 to 4.2 (SP2)
            Upgrade.perform42to422(c);
            Upgrade.perform422to45(c);
        } else {
            // ONLY SUPPORT UPGRADE FROM 4.2 to 4.2 (SP2)
            /**
             * if (!version.equals("pre4.2"))
             * return;
             *
             * Upgrade.perform(c);
             **/
        }
    }

    private ICertificateRepository getCertDB() {
        ICertificateRepository certDB = null;

        try {
            ICertificateAuthority ca = (ICertificateAuthority) subsystems.get("ca");

            if (ca != null) {
                certDB = ca.getCertificateRepository();
            }
        } catch (Exception e) {
            logger.warn("CMSEngine: " + CMS.getLogMessage("CMSCORE_AUTH_AGENT_CERT_REPO"));
        }

        return certDB;
    }

    private IRequestQueue getReqQueue() {
        IRequestQueue queue = null;

        try {
            IRegistrationAuthority ra = (IRegistrationAuthority) subsystems.get("ra");

            if (ra != null) {
                queue = ra.getRequestQueue();
            }

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CMSCORE_AUTH_AGENT_REQUEST_QUEUE"), e);
        }

        return queue;
    }

    private VerifiedCerts mVCList = null;
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

        CertificateRepository certDB = (CertificateRepository) getCertDB();

        if (certDB != null) {
            try {
                if (certDB.isCertificateRevoked(cert) != null) {
                    revoked = true;
                    if (mVCList != null)
                        mVCList.update(cert, VerifiedCert.REVOKED);
                } else {
                    if (mVCList != null)
                        mVCList.update(cert, VerifiedCert.NOT_REVOKED);
                }
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_AUTH_AGENT_REVO_STATUS"), e);
            }
        } else {
            IRequestQueue queue = getReqQueue();

            if (queue != null) {
                IRequest checkRevReq = null;

                try {
                    checkRevReq = queue.newRequest(CertRequestConstants.GETREVOCATIONINFO_REQUEST);
                    checkRevReq.setExtData(IRequest.REQ_TYPE,
                            CertRequestConstants.GETREVOCATIONINFO_REQUEST);
                    checkRevReq.setExtData(IRequest.REQUESTOR_TYPE,
                            IRequest.REQUESTOR_RA);

                    X509CertImpl agentCerts[] = new X509CertImpl[certificates.length];

                    for (int i = 0; i < certificates.length; i++) {
                        agentCerts[i] = (X509CertImpl) certificates[i];
                    }
                    checkRevReq.setExtData(IRequest.ISSUED_CERTS, agentCerts);

                    queue.processRequest(checkRevReq);

                    RequestStatus status = checkRevReq.getRequestStatus();

                    if (status == RequestStatus.COMPLETE) {
                        Enumeration<String> enum1 = checkRevReq.getExtDataKeys();

                        while (enum1.hasMoreElements()) {
                            String name = enum1.nextElement();

                            if (name.equals(IRequest.REVOKED_CERTS)) {
                                revoked = true;
                                if (mVCList != null)
                                    mVCList.update(cert, VerifiedCert.REVOKED);
                            }
                        }
                        if (revoked == false) {
                            if (mVCList != null)
                                mVCList.update(cert, VerifiedCert.NOT_REVOKED);
                        }

                    } else {
                        if (mVCList != null)
                            mVCList.update(cert, VerifiedCert.CHECKED);
                    }
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CMSCORE_AUTH_AGENT_PROCESS_CHECKING"), e);
                }
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
