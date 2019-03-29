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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Timer;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.commons.lang.StringUtils;
import org.apache.xerces.parsers.DOMParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.ITimeSource;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ConsoleError;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SystemEvent;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.VerifiedCert;
import com.netscape.cmscore.authentication.VerifiedCerts;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.cmscore.cert.OidLoaderSubsystem;
import com.netscape.cmscore.cert.X500NameSubsystem;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.jobs.JobsScheduler;
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
import com.netscape.cmscore.time.SimpleTimeSource;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.NuxwdogPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

public class CMSEngine implements ISubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSEngine.class);

    private static final String ID = "MAIN";

    private static final String PROP_SUBSYSTEM = "subsystem";
    private static final String PROP_ID = "id";
    private static final String PROP_CLASS = "class";
    private static final String PROP_ENABLED = "enabled";
    private static final String SERVER_XML = "server.xml";

    // used for testing HSM issues
    public static final String PROP_SIGNED_AUDIT_CERT_NICKNAME =
                              "log.instance.SignedAudit.signedAuditCertNickname";

    public static final SubsystemRegistry mSSReg = SubsystemRegistry.getInstance();

    public String name;
    public String instanceDir; /* path to instance <server-root>/cert-<instance-name> */
    private String instanceId;
    private int pid;

    private CryptoManager mManager = null;

    private IConfigStore mConfig = null;
    private boolean mExcludedLdapAttrsEnabled = false;
    // AutoSD : AutoShutdown
    private String mAutoSD_CrumbFile = null;
    private boolean mAutoSD_Restart = false;
    private int mAutoSD_RestartMax = 3;
    private int mAutoSD_RestartCount = 0;
    private String mSAuditCertNickName = null;
    private PrivateKey mSigningKey = null;
    private byte[] mSigningData = null;
    @SuppressWarnings("unused")
    private ISubsystem mOwner;
    private long mStartupTime = 0;
    private boolean isStarted = false;
    private StringBuffer mWarning = new StringBuffer();
    private ITimeSource mTimeSource = null;
    private IPasswordStore mPasswordStore = null;
    private WarningListener mWarningListener = null;
    private ILogQueue mQueue = null;
    private ISecurityDomainSessionTable mSecurityDomainSessionTable = null;
    private String mConfigSDSessionId = null;
    private Timer mSDTimer = null;
    private String mServerCertNickname = null;
    private String serverStatus = null;

    // static subsystems - must be singletons
    public Map<String, SubsystemInfo> staticSubsystems = new LinkedHashMap<>();

    // dynamic subsystems are loaded at init time, not necessarily singletons.
    public Map<String, SubsystemInfo> dynSubsystems = new LinkedHashMap<>();

    // final static subsystems - must be singletons.
    public Map<String, SubsystemInfo> finalSubsystems = new LinkedHashMap<>();

    private static final int IP = 0;
    private static final int PORT = 1;
    @SuppressWarnings("unused")
    private static final int HOST = 2;
    private static final int AGENT = 0;
    private static final int ADMIN = 1;
    private static final int EE_SSL = 2;
    private static final int EE_NON_SSL = 3;
    private static final int EE_CLIENT_AUTH_SSL = 4;
    private static String info[][] = { { null, null, null },//agent
            { null, null, null },//admin
            { null, null, null },//sslEE
            { null, null, null },//non_sslEE
            { null, null, null } //ssl_clientauth_EE
    };

    private static final int PW_OK =0;
    //private static final int PW_BAD_SETUP = 1;
    private static final int PW_INVALID_PASSWORD = 2;
    private static final int PW_CANNOT_CONNECT = 3;
    private static final int PW_NO_USER = 4;
    private static final int PW_MAX_ATTEMPTS = 3;


    public CMSEngine(String name) {
        this.name = name;
    }

    /**
     * gets this ID
     */
    public String getId() {
        return ID;
    }

    /**
     * should never be called. returns error.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Retrieves the instance root path of this server.
     */
    public String getInstanceDir() {
        return instanceDir;
    }

    public boolean startedByNuxwdog() {
        String wdPipeName = System.getenv("WD_PIPE_NAME");
        if (StringUtils.isNotEmpty(wdPipeName)) {
            return true;
        }
        return false;
    }

    public synchronized IPasswordStore getPasswordStore() throws EBaseException {
        if (mPasswordStore == null) {
            String pwdClass = null;
            String pwdPath = null;

            if (startedByNuxwdog()) {
                pwdClass = NuxwdogPasswordStore.class.getName();
                // note: pwdPath is expected to be null in this case
            } else {
                pwdClass = mConfig.getString("passwordClass");
                pwdPath = mConfig.getString("passwordFile", null);
            }

            try {
                mPasswordStore = (IPasswordStore) Class.forName(pwdClass).newInstance();
                mPasswordStore.init(pwdPath);
                mPasswordStore.setId(instanceId);
            } catch (Exception e) {
                logger.error("Cannot get password store: " + e);
                throw new EBaseException(e);
            }
        }
        return mPasswordStore;
    }

    public void initializePasswordStore(IConfigStore config) throws EBaseException, IOException {
        logger.debug("CMSEngine.initializePasswordStore() begins");
        // create and initialize mPasswordStore
        getPasswordStore();

        boolean skipPublishingCheck = config.getBoolean(
                "cms.password.ignore.publishing.failure", true);
        String pwList = config.getString("cms.passwordlist", "internaldb,replicationdb");
        String tags[] = StringUtils.split(pwList, ",");

        for (String tag : tags) {
            int iteration = 0;
            int result = PW_INVALID_PASSWORD;
            String binddn;
            String authType;
            LdapConnInfo connInfo = null;
            logger.debug("CMSEngine.initializePasswordStore(): tag=" + tag);

            if (tag.equals("internaldb")) {
                authType = config.getString("internaldb.ldapauth.authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        config.getString("internaldb.ldapconn.host"),
                        config.getInteger("internaldb.ldapconn.port"),
                        config.getBoolean("internaldb.ldapconn.secureConn"));

                binddn = config.getString("internaldb.ldapauth.bindDN");
            } else if (tag.equals("replicationdb")) {
                authType = config.getString("internaldb.ldapauth.authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        config.getString("internaldb.ldapconn.host"),
                        config.getInteger("internaldb.ldapconn.port"),
                        config.getBoolean("internaldb.ldapconn.secureConn"));

                binddn = "cn=Replication Manager masterAgreement1-" + config.getString("machineName", "") + "-" +
                        config.getString("instanceId", "") + ",cn=config";
            } else if (tags.equals("CA LDAP Publishing")) {
                authType = config.getString("ca.publish.ldappublish.ldap.ldapauth.authtype", "BasicAuth");
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        config.getString("ca.publish.ldappublish.ldap.ldapconn.host"),
                        config.getInteger("ca.publish.ldappublish.ldap.ldapconn.port"),
                        config.getBoolean("ca.publish.ldappublish.ldap.ldapconn.secureConn"));

                binddn = config.getString("ca.publish.ldappublish.ldap.ldapauth.bindDN");

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
                authType = config.getString(authPrefix +".ldap.ldapauth.authtype", "BasicAuth");
                logger.debug("CMSEngine.initializePasswordStore(): authType " + authType);
                if (!authType.equals("BasicAuth"))
                    continue;

                connInfo = new LdapConnInfo(
                        config.getString(authPrefix + ".ldap.ldapconn.host"),
                        config.getInteger(authPrefix + ".ldap.ldapconn.port"),
                        config.getBoolean(authPrefix + ".ldap.ldapconn.secureConn"));

                binddn = config.getString(authPrefix + ".ldap.ldapauth.bindDN", null);
                if (binddn == null) {
                    logger.debug("CMSEngine.initializePasswordStore(): binddn not found...skipping");
                    continue;
                }
            }

            do {
                String passwd = mPasswordStore.getPassword(tag, iteration);
                result = testLDAPConnection(tag, connInfo, binddn, passwd);
                iteration++;
            } while ((result == PW_INVALID_PASSWORD) && (iteration < PW_MAX_ATTEMPTS));

            if (result != PW_OK) {
                if ((result == PW_NO_USER) && (tag.equals("replicationdb"))) {
                    logger.warn(
                        "CMSEngine: init(): password test execution failed for replicationdb" +
                        "with NO_SUCH_USER.  This may not be a latest instance.  Ignoring ..");
                } else if (skipPublishingCheck && (result == PW_CANNOT_CONNECT) && (tag.equals("CA LDAP Publishing"))) {
                    logger.warn(
                        "Unable to connect to the publishing database to check password, " +
                        "but continuing to start up.  Please check if publishing is operational.");
                } else {
                    // password test failed
                    logger.error("CMSEngine: init(): password test execution failed: " + result);
                    throw new EBaseException("Password test execution failed. Is the database up?");
                }
            }
        }
    }

    public int testLDAPConnection(String name, LdapConnInfo info, String binddn, String pwd) {
        int ret = PW_OK;

        if (StringUtils.isEmpty(pwd))
            return PW_INVALID_PASSWORD;

        String host = info.getHost();
        int port = info.getPort();

        LDAPConnection conn = new LDAPConnection(new PKISocketFactory(info.getSecure()));

        logger.debug("testLDAPConnection connecting to " + host + ":" + port);

        try {
            conn.connect(host, port, binddn, pwd);
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                logger.error("testLDAPConnection: The specified user " + binddn + " does not exist");
                ret = PW_NO_USER;
                break;
            case LDAPException.INVALID_CREDENTIALS:
                logger.error("testLDAPConnection: Invalid Password");
                ret = PW_INVALID_PASSWORD;
                break;
            default:
                logger.error("testLDAPConnection: Unable to connect to " + name + ": " + e);
                ret = PW_CANNOT_CONNECT;
                break;
            }
        } finally {
            try {
                if (conn != null)
                    conn.disconnect();
            } catch (Exception e) {
            }
        }
        return ret;
    }

    /**
     * initialize all static, dynamic and final static subsystems.
     *
     * @param owner null
     * @param config main config store.
     * @exception EBaseException if any error occur in subsystems during
     *                initialization.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        logger.info("Initializing " + name + " subsystem");

        mOwner = owner;
        mConfig = config;
        int state = mConfig.getInteger("cs.state");

        serverStatus = "starting";

        instanceDir = config.getString("instanceRoot");
        instanceId = config.getString("instanceId");

        if (state == 1) {
            // configuration is complete, initialize password store
            try {
                initializePasswordStore(config);
            } catch (IOException e) {
                logger.error("Unable to initialize password store: " + e.getMessage(), e);
                throw new EBaseException("Exception while initializing password store: " + e);
            }
        }

        // my default is 1 day
        String flush_timeout = config.getString("securitydomain.flushinterval", "86400000");
        String secdomain_source = config.getString("securitydomain.source", "memory");
        String secdomain_check_interval = config.getString("securitydomain.checkinterval", "5000");

        String tsClass = config.getString("timeSourceClass", null);

        if (tsClass != null) {
            try {
                mTimeSource = (ITimeSource)
                        Class.forName(tsClass).newInstance();
            } catch (Exception e) {
                // nothing to do
            }
        }
        if (mTimeSource == null) {
            // if time source is not set, set it to simple time source
            mTimeSource = new SimpleTimeSource();
        }

        Security.addProvider(new org.mozilla.jss.netscape.security.provider.CMS());

        loadSubsystems();
        initSubsystems();

        logger.debug("Java version: " + System.getProperty("java.version"));
        java.security.Provider ps[] = java.security.Security.getProviders();

        if (ps == null || ps.length <= 0) {
            logger.debug("CMSEngine: Java Security Provider NONE");
        } else {
            for (int x = 0; x < ps.length; x++) {
                logger.debug("CMSEngine: Java Security Provider " + x + " class=" + ps[x]);
            }
        }
        parseServerXML();
        fixProxyPorts();

        String sd = mConfig.getString("securitydomain.select", "");

        if ((state == 1) && (!sd.equals("existing"))) {
            // check session domain table only if this is a
            // configured security domain host

            if (secdomain_source.equals("ldap")) {
                mSecurityDomainSessionTable = new LDAPSecurityDomainSessionTable((new Long(flush_timeout)).longValue());
            } else {
                mSecurityDomainSessionTable = new SecurityDomainSessionTable((new Long(flush_timeout)).longValue());
            }

            mSDTimer = new Timer();
            SessionTimer timertask = new SessionTimer(mSecurityDomainSessionTable);

            mSDTimer.schedule(timertask, 5, (new Long(secdomain_check_interval)).longValue());
        }

        serverStatus = "running";
    }

    /**
     * Parse server.xml to get the ports and IPs
     * @throws EBaseException
     */
    private void parseServerXML() throws EBaseException {
        try {
            String instanceRoot = mConfig.getString("instanceRoot");
            String path = instanceRoot + File.separator + "conf" + File.separator + SERVER_XML;
            DOMParser parser = new DOMParser();
            parser.parse(path);
            NodeList nodes = parser.getDocument().getElementsByTagName("Connector");
            String parentName = "";
            String name = "";
            String port = "";
            for (int i = 0; i < nodes.getLength(); i++) {
                Element n = (Element) nodes.item(i);

                parentName = "";
                Element p = (Element) n.getParentNode();
                if (p != null) {
                    parentName = p.getAttribute("name");
                }
                name = n.getAttribute("name");
                port = n.getAttribute("port");

                // The "server.xml" file is parsed from top-to-bottom, and
                // supports BOTH "Port Separation" (the new default method)
                // as well as "Shared Ports" (the old legacy method).  Since
                // both methods must be supported, the file structure MUST
                // conform to ONE AND ONLY ONE of the following formats:
                //
                // Port Separation:
                //
                //  <Catalina>
                //     ...
                //     <!-- Port Separation:  Unsecure Port -->
                //     <Connector name="Unsecure" . . .
                //     ...
                //     <!-- Port Separation:  Agent Secure Port -->
                //     <Connector name="Agent" . . .
                //     ...
                //     <!-- Port Separation:  Admin Secure Port -->
                //     <Connector name="Admin" . . .
                //     ...
                //     <!-- Port Separation:  EE Secure Port -->
                //     <Connector name="EE" . . .
                //     ...
                //  </Catalina>
                //
                //
                // Shared Ports:
                //
                //  <Catalina>
                //     ...
                //     <!-- Shared Ports:  Unsecure Port -->
                //     <Connector name="Unsecure" . . .
                //     ...
                //     <!-- Shared Ports:  Agent, EE, and Admin Secure Port -->
                //     <Connector name="Secure" . . .
                //     ...
                //     <!--
                //     <Connector name="Unused" . . .
                //     -->
                //     ...
                //     <!--
                //     <Connector name="Unused" . . .
                //     -->
                //     ...
                //  </Catalina>
                //
                if (parentName.equals("Catalina")) {
                    if (name.equals("Unsecure")) {
                        // Port Separation:  Unsecure Port
                        //                   OR
                        // Shared Ports:     Unsecure Port
                        info[EE_NON_SSL][PORT] = port;
                    } else if (name.equals("Agent")) {
                        // Port Separation:  Agent Secure Port
                        info[AGENT][PORT] = port;
                    } else if (name.equals("Admin")) {
                        // Port Separation:  Admin Secure Port
                        info[ADMIN][PORT] = port;
                    } else if (name.equals("EE")) {
                        // Port Separation:  EE Secure Port
                        info[EE_SSL][PORT] = port;
                    } else if (name.equals("EEClientAuth")) {
                        // Port Separation: EE Client Auth Secure Port
                        info[EE_CLIENT_AUTH_SSL][PORT] = port;
                    } else if (name.equals("Secure")) {
                        // Shared Ports:  Agent, EE, and Admin Secure Port
                        info[AGENT][PORT] = port;
                        info[ADMIN][PORT] = port;
                        info[EE_SSL][PORT] = port;
                        info[EE_CLIENT_AUTH_SSL][PORT] = port;
                    }
                }
            }

        } catch (Exception e) {
            logger.error("CMSEngine: parseServerXML exception: " + e.getMessage(), e);
            throw new EBaseException("CMSEngine: Cannot parse the configuration file. " + e.getMessage(), e);
        }
    }

    private void fixProxyPorts() throws EBaseException {
        try {
            String port = mConfig.getString("proxy.securePort", "");
            if (!port.equals("")) {
                info[EE_SSL][PORT] = port;
                info[ADMIN][PORT] = port;
                info[AGENT][PORT] = port;
                info[EE_CLIENT_AUTH_SSL][PORT] = port;
            }

            port = mConfig.getString("proxy.unsecurePort", "");
            if (!port.equals("")) {
                info[EE_NON_SSL][PORT] = port;
            }
        } catch (EBaseException e) {
            logger.error("CMSEngine: fixProxyPorts exception: " + e.getMessage(), e);
            throw e;
        }
    }

    public IConfigStore createFileConfigStore(String path) throws EBaseException {
        try {
            /* if the file is not there, create one */
            File f = new File(path);
            f.createNewFile();
        } catch (IOException e) {
            logger.error("Cannot create file: " + path + ": " + e.getMessage(), e);
            throw new EBaseException("Cannot create file: " + path + ": " + e.getMessage(), e);
        }
        return new FileConfigStore(path);
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
        mConfig.putInteger("cs.state", mode);
    }

    public int getCSState() {
        int mode = 0;
        try {
            mode = mConfig.getInteger("cs.state");
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
            host = mConfig.getString("machineName");
        } catch (Exception e) {
        }
        return host;
    }

    public String getEENonSSLHost() {
        String host = "";
        try {
            host = mConfig.getString("machineName");
        } catch (Exception e) {
        }
        return host;
    }

    public String getEENonSSLIP() {
        return info[EE_NON_SSL][IP];
    }

    public String getEENonSSLPort() {
        return info[EE_NON_SSL][PORT];
    }

    public String getEESSLHost() {
        String host = "";
        try {
            host = mConfig.getString("machineName");
        } catch (Exception e) {
        }
        return host;
    }

    public String getEESSLIP() {
        return info[EE_SSL][IP];
    }

    public String getEESSLPort() {
        return info[EE_SSL][PORT];
    }

    public String getEEClientAuthSSLPort() {
        return info[EE_CLIENT_AUTH_SSL][PORT];
    }

    public String getAgentHost() {
        String host = "";
        try {
            host = mConfig.getString("machineName");
        } catch (Exception e) {
        }
        return host;
    }

    public String getAgentIP() {
        return info[AGENT][IP];
    }

    public String getAgentPort() {
        return info[AGENT][PORT];
    }

    public String getAdminHost() {
        String host = "";
        try {
            host = mConfig.getString("machineName");
        } catch (Exception e) {
        }
        return host;
    }

    public String getAdminIP() {
        return info[ADMIN][IP];
    }

    public String getAdminPort() {
        return info[ADMIN][PORT];
    }

    public Enumeration<String> getSubsystemNames() {
        return mSSReg.keys();
    }

    public Enumeration<ISubsystem> getSubsystems() {
        return mSSReg.elements();
    }

    public ISubsystem getSubsystem(String name) {
        return mSSReg.get(name);
    }

    protected void initSubsystems() throws EBaseException {

        mSSReg.put(ID, this);

        initSubsystems(staticSubsystems);

        // Once the log subsystem is initialized, we
        // want to register a listener to catch
        // all the warning message so that we can
        // display them in the console.
        mQueue = Logger.getLogger().getLogQueue();
        mWarningListener = new WarningListener(mWarning);
        mQueue.addLogEventListener(mWarningListener);

        initSubsystems(dynSubsystems);
        initSubsystems(finalSubsystems);
    }

    private void initSubsystems(Map<String, SubsystemInfo> subsystems)
            throws EBaseException {
        for (SubsystemInfo si : subsystems.values()) {
            initSubsystem(si);
        }
    }

    private ArrayList<String> getDynSubsystemNames() throws EBaseException {
        IConfigStore ssconfig = mConfig.getSubStore(PROP_SUBSYSTEM);
        Enumeration<String> ssNames = ssconfig.getSubStoreNames();
        ArrayList<String> ssNamesList = new ArrayList<String>();
        while (ssNames.hasMoreElements())
            ssNamesList.add(ssNames.nextElement());
        return ssNamesList;
    }

    /**
     * load subsystems
     */
    protected void loadSubsystems() throws EBaseException {

        logger.debug("CMSEngine: loading static subsystems");

        staticSubsystems.clear();

        staticSubsystems.put(Debug.ID,
                new SubsystemInfo(Debug.ID, Debug.getInstance()));
        staticSubsystems.put(LogSubsystem.ID,
                new SubsystemInfo(LogSubsystem.ID, LogSubsystem.getInstance()));
        staticSubsystems.put(JssSubsystem.ID,
                new SubsystemInfo(JssSubsystem.ID, JssSubsystem.getInstance()));
        staticSubsystems.put(DBSubsystem.ID,
                new SubsystemInfo(DBSubsystem.ID, DBSubsystem.getInstance()));
        staticSubsystems.put(UGSubsystem.ID,
                new SubsystemInfo(UGSubsystem.ID, UGSubsystem.getInstance()));
        staticSubsystems.put(PluginRegistry.ID,
                new SubsystemInfo(PluginRegistry.ID, new PluginRegistry()));
        staticSubsystems.put(OidLoaderSubsystem.ID,
                new SubsystemInfo(OidLoaderSubsystem.ID, OidLoaderSubsystem.getInstance()));
        staticSubsystems.put(X500NameSubsystem.ID,
                new SubsystemInfo(X500NameSubsystem.ID, X500NameSubsystem.getInstance()));
        // skip TP subsystem;
        // problem in needing dbsubsystem in constructor. and it's not used.
        staticSubsystems.put(RequestSubsystem.ID,
                new SubsystemInfo(RequestSubsystem.ID, RequestSubsystem.getInstance()));

        logger.debug("CMSEngine: loading dyn subsystems");

        dynSubsystems.clear();

        ArrayList<String> ssNames = getDynSubsystemNames();
        IConfigStore ssconfig = mConfig.getSubStore(PROP_SUBSYSTEM);

        for (String ssName : ssNames) {
            IConfigStore config = ssconfig.getSubStore(ssName);

            String id = config.getString(PROP_ID);
            String classname = config.getString(PROP_CLASS);
            boolean enabled = config.getBoolean(PROP_ENABLED, true);

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

            dynSubsystems.put(id, new SubsystemInfo(id, ss, enabled, true));
            logger.debug("CMSEngine: loaded dyn subsystem " + id);
        }

        logger.debug("CMSEngine: loading final subsystems");

        finalSubsystems.clear();

        finalSubsystems.put(AuthSubsystem.ID,
                new SubsystemInfo(AuthSubsystem.ID, AuthSubsystem.getInstance()));
        finalSubsystems.put(AuthzSubsystem.ID,
                new SubsystemInfo(AuthzSubsystem.ID, AuthzSubsystem.getInstance()));
        finalSubsystems.put(JobsScheduler.ID,
                new SubsystemInfo(JobsScheduler.ID, JobsScheduler.getInstance()));

        if (isPreOpMode()) {
            // Disable some subsystems before database initialization
            // in pre-op mode to prevent errors.
            SubsystemInfo si = staticSubsystems.get(UGSubsystem.ID);
            si.enabled = false;
        }
    }

    /**
     * Set whether the given subsystem is enabled.
     *
     * @param id The subsystem ID.
     * @param enabled Whether the subsystem is enabled
     */
    public void setSubsystemEnabled(String id, boolean enabled)
            throws EBaseException {
        IConfigStore ssconfig = mConfig.getSubStore(PROP_SUBSYSTEM);
        for (String ssName : getDynSubsystemNames()) {
            IConfigStore config = ssconfig.getSubStore(ssName);
            if (id.equalsIgnoreCase(config.getString(PROP_ID))) {
                config.putBoolean(PROP_ENABLED, enabled);
                break;
            }
        }
    }

    /**
     * initialize a subsystem
     */
    private void initSubsystem(SubsystemInfo ssinfo)
            throws EBaseException {

        String id = ssinfo.id;
        ISubsystem ss = ssinfo.instance;

        logger.debug("CMSEngine: initSubsystem(" + id + ")");
        mSSReg.put(id, ss);

        if (ssinfo.updateIdOnInit) {
            ss.setId(id);
        }

        IConfigStore ssConfig = mConfig.getSubStore(id);
        if (!ssinfo.enabled) {
            logger.debug("CMSEngine: " + id + " disabled");
            return;
        }

        logger.debug("CMSEngine: initializing " + id);
        ss.init(this, ssConfig);

        try {
            /*
             * autoShutdown.allowed=false
             * autoShutdown.crumbFile=[PKI_INSTANCE_PATH]/logs/autoShutdown.crumb
             * autoShutdown.restart.enable=false
             * autoShutdown.restart.max=3
             * autoShutdown.restart.count=0
             */

            mAutoSD_Restart = mConfig.getBoolean("autoShutdown.restart.enable", false);
            logger.debug("CMSEngine: restart at autoShutdown: " + mAutoSD_Restart);

            if (mAutoSD_Restart) {
                mAutoSD_RestartMax = mConfig.getInteger("autoShutdown.restart.max", 3);
                logger.debug("CMSEngine: restart max: " + mAutoSD_RestartMax);

                mAutoSD_RestartCount = mConfig.getInteger("autoShutdown.restart.count", 0);
                logger.debug("CMSEngine: current restart count: " + mAutoSD_RestartCount);

            } else { //!mAutoSD_Restart
                mAutoSD_CrumbFile = mConfig.getString("autoShutdown.crumbFile",
                    instanceDir + "/logs/autoShutdown.crumb");
                logger.debug("CMSEngine: autoShutdown crumb file path: " + mAutoSD_CrumbFile);

                File crumb = new File(mAutoSD_CrumbFile);
                try {
                    if (crumb.exists()) {
                        logger.debug("CMSEngine: delete autoShutdown crumb file");
                        crumb.delete();
                    }
                } catch (Exception e) {
                    logger.warn("Delete autoShutdown crumb file failed: " + e.getMessage(), e);
                    logger.warn("Continue with initialization");
                }
            }

            /*
             * establish signing key reference using audit signing cert
             * for HSM failover detection
             */
            mSAuditCertNickName = mConfig.getString(PROP_SIGNED_AUDIT_CERT_NICKNAME);
            mManager = CryptoManager.getInstance();

            logger.debug("CMSEngine: about to look for cert for auto-shutdown support:" + mSAuditCertNickName);

            org.mozilla.jss.crypto.X509Certificate cert = null;
            try {
                cert = mManager.findCertByNickname(mSAuditCertNickName);
            } catch (ObjectNotFoundException as) {
                logger.warn("CMSEngine: Unable to support auto-shutdown: " + as.getMessage());
            }

            if (cert != null) {
                logger.debug("CMSEngine: found cert:" + mSAuditCertNickName);
                mSigningKey = mManager.findPrivKeyByCert(cert);
                mSigningData = cert.getPublicKey().getEncoded();
            }

        } catch (Exception e) {
            logger.warn("CMSEngine: Unable to configure auto-shutdown: " + e.getMessage(), e);
        }

        // add to id - subsystem hash table.
        logger.debug("CMSEngine: done init id=" + id);
        logger.debug("CMSEngine: initialized " + id);

        if (id.equals("ca") || id.equals("ocsp") ||
                id.equals("kra") || id.equals("tks")) {

            logger.debug("CMSEngine: get SSL server nickname");
            IConfigStore serverCertStore = mConfig.getSubStore(id + "." + "sslserver");

            if (serverCertStore != null && serverCertStore.size() > 0) {
                String nickName = serverCertStore.getString("nickname");
                String tokenName = serverCertStore.getString("tokenname");

                if (tokenName != null && tokenName.length() > 0 &&
                        nickName != null && nickName.length() > 0) {
                    setServerCertNickname(tokenName, nickName);
                    logger.debug("Subsystem " + id + " init sslserver:  tokenName:" + tokenName + "  nickName:" + nickName);

                } else if (nickName != null && nickName.length() > 0) {
                    setServerCertNickname(nickName);
                    logger.debug("Subsystem " + id + " init sslserver:  nickName:" + nickName);

                } else {
                    logger.warn("Subsystem " + id + " init error: SSL server certificate nickname is not available.");
                }
            }
        }

        if (id.equals("ca") || id.equals("kra")) {

            /*
              figure out if any ldap attributes need exclusion in enrollment records
              Default config:
                excludedLdapAttrs.enabled=false;
                (excludedLdapAttrs.attrs unspecified to take default)
             */
            mExcludedLdapAttrsEnabled = mConfig.getBoolean("excludedLdapAttrs.enabled", false);
            if (mExcludedLdapAttrsEnabled == true) {
                logger.debug("CMSEngine: initSubsystem: excludedLdapAttrs.enabled: true");
                excludedLdapAttrsList = Arrays.asList(excludedLdapAttrs);
                String unparsedExcludedLdapAttrs = "";
                try {
                    unparsedExcludedLdapAttrs = mConfig.getString("excludedLdapAttrs.attrs");
                    logger.debug("CMSEngine: initSubsystem: excludedLdapAttrs.attrs =" + unparsedExcludedLdapAttrs);
                } catch (Exception e) {
                    logger.debug("CMSEngine: initSubsystem: excludedLdapAttrs.attrs unspecified, taking default");
                }
                if (!unparsedExcludedLdapAttrs.equals("")) {
                    excludedLdapAttrsList = Arrays.asList(unparsedExcludedLdapAttrs.split(","));
                    // overwrites the default
                    //excludedLdapAttrSet = new HashSet(excludedLdapAttrsList);
                }
            } else {
                logger.debug("CMSEngine: initSubsystem: excludedLdapAttrs.enabled: false");
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
        ISubsystem system = getSubsystem(id);
        IConfigStore cs = mConfig.getSubStore(id);
        system.init(this, cs);
    }

    /**
     * Starts up all subsystems. subsystems must be initialized.
     *
     * @exception EBaseException if any subsystem fails to startup.
     */
    public void startup() throws EBaseException {
        startupSubsystems(staticSubsystems);
        startupSubsystems(dynSubsystems);
        startupSubsystems(finalSubsystems);

        // global admin servlet. (anywhere else more fit for this ?)

        mStartupTime = System.currentTimeMillis();

        mQueue.removeLogEventListener(mWarningListener);
        if (!mWarning.toString().equals("")) {
            logger.warn(Constants.SERVER_STARTUP_WARNING_MESSAGE + mWarning);
        }

        // check serial number ranges if a CA/KRA
        ICertificateAuthority ca = (ICertificateAuthority) getSubsystem("ca");
        if ((ca != null) && !isPreOpMode()) {
            logger.debug("CMSEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CMSEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }

        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) getSubsystem("kra");
        if ((kra != null) && !isPreOpMode()) {
            logger.debug("CMSEngine: checking request serial number ranges for the KRA");
            kra.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CMSEngine: checking key serial number ranges");
            kra.getKeyRepository().checkRanges();
        }

        /*LogDoc
         *
         * @phase server startup
         * @reason all subsystems are initialized and started.
         */
        logger.info(CMS.getLogMessage("SERVER_STARTUP"));

        String type = mConfig.get("cs.type");
        logger.info(type + " is started.");

        isStarted = true;
    }

    public boolean isInRunningState() {
        return isStarted;
    }

    public byte[] getPKCS7(Locale locale, IRequest req) {
        try {
            X509CertImpl cert = req.getExtDataInCert(
                    IEnrollProfile.REQUEST_ISSUED_CERT);
            if (cert == null)
                return null;

            ICertificateAuthority ca = (ICertificateAuthority)
                    getSubsystem("ca");
            CertificateChain cachain = ca.getCACertChain();
            X509Certificate[] cacerts = cachain.getChain();

            X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
            int m = 1, n = 0;

            for (; n < cacerts.length; m++, n++) {
                userChain[m] = (X509CertImpl) cacerts[n];
            }

            userChain[0] = cert;
            PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                    new ContentInfo(new byte[0]),
                    userChain,
                    new SignerInfo[0]);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            p7.encodeSignedData(bos);
            return bos.toByteArray();
        } catch (Exception e) {
            return null;
        }
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

    public void debug(String msg) {
        if (!Debug.on()) {
            // this helps to not saving stuff to file when debug
            // is disable
            return;
        }
        Debug.trace(msg);
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
            name = getConfigStore().getString(configName);
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

    private void startupSubsystems(Map<String, SubsystemInfo> subsystems)
            throws EBaseException {

        for (SubsystemInfo si : subsystems.values()) {
            logger.debug("CMSEngine: starting " + si.id);
            si.instance.startup();
            logger.debug("CMSEngine: " + si.id + " started");
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
            if (startedByNuxwdog()) {
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
        shutdownSubsystems(finalSubsystems);
        shutdownSubsystems(dynSubsystems);
        shutdownSubsystems(staticSubsystems);

        shutdownHttpServer(restart);

    }

    public void disableSubsystem() {

        logger.info("CMSEngine: Disabling " + name + " subsystem");

        try {
            String subsystemID = name.toLowerCase();
            ProcessBuilder pb = new ProcessBuilder("pki-server", "subsystem-disable", "-i", instanceId, subsystemID);
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

    private void shutdownSubsystems(Map<String, SubsystemInfo> subsystems) {
        // reverse list of subsystems
        List<SubsystemInfo> list = new ArrayList<>(subsystems.values());
        Collections.reverse(list);

        for (SubsystemInfo si : list) {
            logger.debug("CMSEngine: stopping " + si.id);
            si.instance.shutdown();
            logger.debug("CMSEngine: " + si.id + " stopped");
        }
    }

    /**
     * returns the main config store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
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

    public void setConfigSDSessionId(String val) {
        mConfigSDSessionId = val;
    }

    public String getConfigSDSessionId() {
        return mConfigSDSessionId;
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
            ICertificateAuthority ca = (ICertificateAuthority)
                    SubsystemRegistry.getInstance().get("ca");

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
            IRegistrationAuthority ra = (IRegistrationAuthority)
                    SubsystemRegistry.getInstance().get("ra");

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
        boolean revoked = false;

        if (certificates != null) {
            X509CertImpl cert = (X509CertImpl) certificates[0];

            int result = VerifiedCert.UNKNOWN;

            if (mVCList != null) {
                result = mVCList.check(cert);
            }
            if (result != VerifiedCert.REVOKED &&
                    result != VerifiedCert.NOT_REVOKED &&
                    result != VerifiedCert.CHECKED) {

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
            } else if (result == VerifiedCert.REVOKED) {
                revoked = true;
            }
        }

        return revoked;
    }

    public String getServerStatus() {
        return serverStatus;
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
}

class WarningListener implements ILogEventListener {
    private StringBuffer mSB = null;

    public WarningListener(StringBuffer sb) {
        mSB = sb;
    }

    public void log(ILogEvent event) throws ELogException {
        String str = event.toString();

        // start.cc and restart.cc does not like carriage
        // return. They are the programs that pass the
        // log messages to the console
        str = str.replace('\n', ' ');
        if (event.getLevel() == ILogger.LL_FAILURE) {
            mSB.append("FAILURE: " + str + "|");
        }
        if (event.getLevel() == ILogger.LL_WARN) {
            mSB.append("WARNING: " + str + "|");
        }
    }

    public void flush() {
    }

    public void shutdown() {
    }

    public IConfigStore getConfigStore() {
        return null;
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
    }

    public void startup() {
    }

    /**
     * Retrieve last "maxLine" number of system log with log lever >"level"
     * and from source "source". If the parameter is omitted. All entries
     * are sent back.
     */
    public synchronized NameValuePairs retrieveLogContent(Hashtable<String, String> req) throws ServletException,
            IOException, EBaseException {
        return null;
    }

    /**
     * Retrieve log file list.
     */
    public synchronized NameValuePairs retrieveLogList(Hashtable<String, String> req) throws ServletException,
            IOException, EBaseException {
        return null;
    }

    public String getImplName() {
        return "ConsoleLog";
    }

    public String getDescription() {
        return "ConsoleLog";
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        return v;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        return v;
    }
}
