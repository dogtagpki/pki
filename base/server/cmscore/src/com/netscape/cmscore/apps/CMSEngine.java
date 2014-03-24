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
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;
import netscape.security.extensions.CertInfo;
import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import org.apache.xerces.parsers.DOMParser;
import org.mozilla.jss.CryptoManager.CertificateUsage;
import org.mozilla.jss.util.PasswordCallback;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.acls.ACL;
import com.netscape.certsrv.acls.ACLEntry;
import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.apps.CMS;
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
import com.netscape.certsrv.base.ITimeSource;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogQueue;
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
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.VerifiedCert;
import com.netscape.cmscore.authentication.VerifiedCerts;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.cert.CrlCachePrettyPrint;
import com.netscape.cmscore.cert.CrlPrettyPrint;
import com.netscape.cmscore.cert.ExtPrettyPrint;
import com.netscape.cmscore.cert.OidLoaderSubsystem;
import com.netscape.cmscore.cert.X500NameSubsystem;
import com.netscape.cmscore.connector.HttpConnection;
import com.netscape.cmscore.connector.HttpPKIMessage;
import com.netscape.cmscore.connector.HttpRequestEncoder;
import com.netscape.cmscore.connector.Resender;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.RepositoryRecord;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.ldapconn.LdapAnonConnFactory;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.LdapJssSSLSocketFactory;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.logging.LogSubsystem;
import com.netscape.cmscore.logging.Logger;
import com.netscape.cmscore.logging.SignedAuditLogger;
import com.netscape.cmscore.notification.EmailFormProcessor;
import com.netscape.cmscore.notification.EmailResolverKeys;
import com.netscape.cmscore.notification.EmailTemplate;
import com.netscape.cmscore.notification.ReqCertSANameEmailResolver;
import com.netscape.cmscore.policy.GeneralNameUtil;
import com.netscape.cmscore.registry.PluginRegistry;
import com.netscape.cmscore.request.CertRequestConstants;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.security.PWCBsdr;
import com.netscape.cmscore.security.PWsdrCache;
import com.netscape.cmscore.session.LDAPSecurityDomainSessionTable;
import com.netscape.cmscore.session.SecurityDomainSessionTable;
import com.netscape.cmscore.session.SessionTimer;
import com.netscape.cmscore.time.SimpleTimeSource;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.net.ISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.util.Utils;

public class CMSEngine implements ICMSEngine {
    private static final String ID = "MAIN";

    private static final String PROP_SUBSYSTEM = "subsystem";
    private static final String PROP_ID = "id";
    private static final String PROP_CLASS = "class";
    private static final String SERVER_XML = "server.xml";

    public static final SubsystemRegistry mSSReg = SubsystemRegistry.getInstance();

    public String instanceDir; /* path to instance <server-root>/cert-<instance-name> */
    private String instanceId;
    private int pid;

    private IConfigStore mConfig = null;
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
    private static SubsystemInfo[] mStaticSubsystems = {
            new SubsystemInfo(
                    Debug.ID, Debug.getInstance()),
            new SubsystemInfo(LogSubsystem.ID,
                    LogSubsystem.getInstance()),
            new SubsystemInfo(
                    JssSubsystem.ID, JssSubsystem.getInstance()),
            new SubsystemInfo(
                    DBSubsystem.ID, DBSubsystem.getInstance()),
            new SubsystemInfo(
                    UGSubsystem.ID, UGSubsystem.getInstance()),
            new SubsystemInfo(
                    PluginRegistry.ID, new PluginRegistry()),
            new SubsystemInfo(
                    OidLoaderSubsystem.ID, OidLoaderSubsystem.getInstance()),
            new SubsystemInfo(
                    X500NameSubsystem.ID, X500NameSubsystem.getInstance()),
            // skip TP subsystem;
            // problem in needing dbsubsystem in constructor. and it's not used.
            new SubsystemInfo(
                    RequestSubsystem.ID, RequestSubsystem.getInstance()),
        };

    // dynamic subsystems are loaded at init time, not neccessarily singletons.
    private static SubsystemInfo[] mDynSubsystems = null;

    // final static subsystems - must be singletons.
    private static SubsystemInfo[] mFinalSubsystems = {
            new SubsystemInfo(
                    AuthSubsystem.ID, AuthSubsystem.getInstance()),
            new SubsystemInfo(
                    AuthzSubsystem.ID, AuthzSubsystem.getInstance()),
            new SubsystemInfo(
                    JobsScheduler.ID, JobsScheduler.getInstance()),
        };

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

    /**
     * private constructor.
     */
    public CMSEngine() {
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
     * Retrieves the instance roort path of this server.
     */
    public String getInstanceDir() {
        return instanceDir;
    }

    public synchronized IPasswordStore getPasswordStore() {
        // initialize the PasswordReader and PasswordWriter
        try {
            String pwdPath = mConfig.getString("passwordFile");
            if (mPasswordStore == null) {
                CMS.debug("CMSEngine: getPasswordStore(): password store not initialized before.");
                String pwdClass = mConfig.getString("passwordClass");

                try {
                    mPasswordStore = (IPasswordStore) Class.forName(pwdClass).newInstance();
                } catch (Exception e) {
                    CMS.debug("CMSEngine: getPasswordStore(): password store initialization failure:"
                            + e.toString());
                    throw e;
                }
            } else {
                CMS.debug("CMSEngine: getPasswordStore(): password store initialized before.");
            }

            // have to initialize it because other places don't always
            mPasswordStore.init(pwdPath);
            CMS.debug("CMSEngine: getPasswordStore(): password store initialized.");
        } catch (Exception e) {
            CMS.debug("CMSEngine: getPasswordStore(): failure:" + e.toString());
        }

        return mPasswordStore;
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
        mOwner = owner;
        mConfig = config;
        int state = mConfig.getInteger("cs.state");

        serverStatus = "starting";

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

        instanceDir = config.getString("instanceRoot");
        instanceId = config.getString("instanceId");

        loadDynSubsystems();

        java.security.Security.addProvider(
                new netscape.security.provider.CMS());

        mSSReg.put(ID, this);
        initSubsystems(mStaticSubsystems, false);

        // Once the log subsystem is initialized, we
        // want to register a listener to catch
        // all the warning message so that we can
        // display them in the console.
        mQueue = Logger.getLogger().getLogQueue();
        mWarningListener = new WarningListener(mWarning);
        mQueue.addLogEventListener(mWarningListener);

        initSubsystems(mDynSubsystems, true);
        initSubsystems(mFinalSubsystems, false);

        CMS.debug("Java version=" + System.getProperty("java.version"));
        java.security.Provider ps[] = java.security.Security.getProviders();

        if (ps == null || ps.length <= 0) {
            CMS.debug("CMSEngine: Java Security Provider NONE");
        } else {
            for (int x = 0; x < ps.length; x++) {
                CMS.debug("CMSEngine: Java Security Provider " + x + " class=" + ps[x]);
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
     * Parse ACL resource attributes
     *
     * @param resACLs same format as the resourceACLs attribute:
     *
     *            <PRE>
     *     <resource name>:<permission1,permission2,...permissionn>:
     *     <allow|deny> (<subset of the permission set>) <evaluator expression>
     * </PRE>
     * @exception EACLsException ACL related parsing errors for resACLs
     * @return an ACL instance built from the parsed resACLs
     */
    public IACL parseACL(String resACLs) throws EACLsException {
        if (resACLs == null) {
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_NULL_VALUE", "resACLs"));
        }

        ACL acl = null;
        Vector<String> rights = null;
        int idx1 = resACLs.indexOf(":");

        if (idx1 <= 0) {
            acl = new ACL(resACLs, rights, resACLs);
        } else {
            // getting resource id
            String resource = resACLs.substring(0, idx1);

            if (resource == null) {
                String infoMsg = "resource not specified in resourceACLS attribute:" +
                        resACLs;

                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }

            // getting list of applicable rights
            String st = resACLs.substring(idx1 + 1);
            int idx2 = st.indexOf(":");
            String rightsString = null;

            if (idx2 != -1)
                rightsString = st.substring(0, idx2);
            else {
                String infoMsg =
                        "rights not specified in resourceACLS attribute:" + resACLs;
                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }

            if (rightsString != null) {
                rights = new Vector<String>();
                StringTokenizer rtok = new StringTokenizer(rightsString, ",");

                while (rtok.hasMoreTokens()) {
                    rights.addElement(rtok.nextToken());
                }
            }

            acl = new ACL(resource, rights, resACLs);

            String stx = st.substring(idx2 + 1);
            int idx3 = stx.indexOf(":");
            String aclStr = stx.substring(0, idx3);

            // getting list of acl entries
            if (aclStr != null) {
                StringTokenizer atok = new StringTokenizer(aclStr, ";");

                while (atok.hasMoreTokens()) {
                    String acs = atok.nextToken();

                    // construct ACL entry
                    ACLEntry entry = ACLEntry.parseACLEntry(acl, acs);

                    if (entry == null) {
                        String infoMsg = "parseACLEntry() call failed";
                        String[] params = new String[2];

                        params[0] = "ACLEntry = " + acs;
                        params[1] = infoMsg;
                        throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
                    }

                    entry.setACLEntryString(acs);
                    acl.addEntry(entry);
                }
            } else {
                // fine
                String infoMsg = "acls not specified in resourceACLS attribute:" +

                resACLs;

                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }

            // getting description
            String desc = stx.substring(idx3 + 1);

            acl.setDescription(desc);
        }

        return (acl);
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
            CMS.debug("CMSEngine: parseServerXML exception: " + e.toString());
            throw new EBaseException("CMSEngine: Cannot parse the configuration file. " + e.toString());
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
            CMS.debug("CMSEngine: fixProxyPorts exception: " + e.toString());
            throw e;
        }
    }

    public IConfigStore createFileConfigStore(String path) throws EBaseException {
        try {
            /* if the file is not there, create one */
            File f = new File(path);
            f.createNewFile();
        } catch (IOException e) {
            CMS.debug("Cannot create file: " + path + " ." + e.toString());
            throw new EBaseException("Cannot create file: " + path + " ." + e.toString());
        }
        return new FileConfigStore(path);
    }

    public IArgBlock createArgBlock() {
        return new ArgBlock();
    }

    public IArgBlock createArgBlock(Hashtable<String, String> httpReq) {
        return new ArgBlock(httpReq);
    }

    public IArgBlock createArgBlock(String realm, Hashtable<String, String> httpReq) {
        return new ArgBlock(realm, httpReq);
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

    public IRepositoryRecord createRepositoryRecord() {
        return new RepositoryRecord();
    }

    public ICRLIssuingPointRecord createCRLIssuingPointRecord(String
            id, BigInteger crlNumber, Long crlSize, Date thisUpdate, Date nextUpdate) {
        return new CRLIssuingPointRecord(id, crlNumber, crlSize, thisUpdate, nextUpdate);
    }

    public ISecurityDomainSessionTable getSecurityDomainSessionTable() {
        return mSecurityDomainSessionTable;
    }

    public String getCRLIssuingPointRecordName() {
        return CRLIssuingPointRecord.class.getName();
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

    public IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory) {
        return new HttpConnection(authority, factory);
    }

    public IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory, int timeout) {
        return new HttpConnection(authority, factory, timeout);
    }

    public IResender getResender(IAuthority authority, String nickname,
            IRemoteAuthority remote, int interval) {
        return new Resender(authority, nickname, remote, interval);
    }

    public IPKIMessage getHttpPKIMessage() {
        return new HttpPKIMessage();
    }

    public ILdapConnInfo getLdapConnInfo(IConfigStore config)
            throws EBaseException, ELdapException {
        return new LdapConnInfo(config);
    }

    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory(
            String certNickname) {
        return new LdapJssSSLSocketFactory(certNickname);
    }

    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory() {
        return new LdapJssSSLSocketFactory();
    }

    public ILdapAuthInfo getLdapAuthInfo() {
        return new LdapAuthInfo();
    }

    public ILdapConnFactory getLdapBoundConnFactory()
            throws ELdapException {
        return new LdapBoundConnFactory();
    }

    public ILdapConnFactory getLdapAnonConnFactory()
            throws ELdapException {
        return new LdapAnonConnFactory();
    }

    public IRequestEncoder getHttpRequestEncoder() {
        return new HttpRequestEncoder();
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

    /**
     * initialize an array of subsystem info.
     */
    private void initSubsystems(SubsystemInfo[] sslist, boolean doSetId)
            throws EBaseException {
        if (sslist == null)
            return;
        for (int i = 0; i < sslist.length; i++) {
            initSubsystem(sslist[i], doSetId);
        }
    }

    /**
     * load dynamic subsystems
     */
    private void loadDynSubsystems()
            throws EBaseException {
        IConfigStore ssconfig = mConfig.getSubStore(PROP_SUBSYSTEM);

        // count number of dyn loaded subsystems.
        Enumeration<String> ssnames = ssconfig.getSubStoreNames();
        int nsubsystems = 0;

        for (nsubsystems = 0; ssnames.hasMoreElements(); nsubsystems++)
            ssnames.nextElement();
        if (Debug.ON) {
            Debug.trace(nsubsystems + " dyn subsystems loading..");
        }
        if (nsubsystems == 0)
            return;

        // load dyn subsystems.
        mDynSubsystems = new SubsystemInfo[nsubsystems];
        for (int i = 0; i < mDynSubsystems.length; i++) {
            IConfigStore config =
                    ssconfig.getSubStore(String.valueOf(i));
            String id = config.getString(PROP_ID);
            String classname = config.getString(PROP_CLASS);
            ISubsystem ss = null;

            try {
                ss = (ISubsystem) Class.forName(classname).newInstance();
            } catch (InstantiationException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()));
            } catch (IllegalAccessException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()));
            } catch (ClassNotFoundException e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_FAILED_1", id, e.toString()));
            }
            mDynSubsystems[i] = new SubsystemInfo(id, ss);
            Debug.trace("loaded dyn subsystem " + id);
        }
    }

    public LDAPConnection getBoundConnection(String host, int port,
               int version, LDAPSSLSocketFactoryExt fac, String bindDN,
               String bindPW) throws LDAPException {
        return new LdapBoundConnection(host, port, version, fac,
                bindDN, bindPW);
    }

    /**
     * initialize a subsystem
     */
    private void initSubsystem(SubsystemInfo ssinfo, boolean doSetId)
            throws EBaseException {
        String id = ssinfo.mId;
        ISubsystem ss = ssinfo.mInstance;
        IConfigStore ssConfig = mConfig.getSubStore(id);

        CMS.debug("CMSEngine: initSubsystem id=" + id);
        if (doSetId)
            ss.setId(id);
        CMS.debug("CMSEngine: ready to init id=" + id);
        ss.init(this, ssConfig);
        // add to id - subsystem hash table.
        CMS.debug("CMSEngine: done init id=" + id);
        mSSReg.put(id, ss);
        CMS.debug("CMSEngine: initialized " + id);

        if (id.equals("ca") || id.equals("ocsp") ||
                id.equals("kra") || id.equals("tks")) {
            CMS.debug("CMSEngine::initSubsystem " + id + " Java subsytem about to calculate serverCertNickname. ");
            // get SSL server nickname
            IConfigStore serverCertStore = mConfig.getSubStore(id + "." + "sslserver");
            if (serverCertStore != null && serverCertStore.size() > 0) {
                String nickName = serverCertStore.getString("nickname");
                String tokenName = serverCertStore.getString("tokenname");
                if (tokenName != null && tokenName.length() > 0 &&
                        nickName != null && nickName.length() > 0) {
                    CMS.setServerCertNickname(tokenName, nickName);
                    CMS.debug("Subsystem " + id + " init sslserver:  tokenName:" + tokenName + "  nickName:" + nickName);
                } else if (nickName != null && nickName.length() > 0) {
                    CMS.setServerCertNickname(nickName);
                    CMS.debug("Subsystem " + id + " init sslserver:  nickName:" + nickName);
                } else {
                    CMS.debug("Subsystem " + id + " init error: SSL server certificate nickname is not available.");
                }
            }
        }
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
        startupSubsystems(mStaticSubsystems);
        if (mDynSubsystems != null)
            startupSubsystems(mDynSubsystems);
        startupSubsystems(mFinalSubsystems);

        // global admin servlet. (anywhere else more fit for this ?)

        mStartupTime = System.currentTimeMillis();

        mQueue.removeLogEventListener(mWarningListener);
        if (!mWarning.toString().equals("")) {
            System.out.println(Constants.SERVER_STARTUP_WARNING_MESSAGE + mWarning);
        }

        // check serial number ranges if a CA/KRA
        ICertificateAuthority ca = (ICertificateAuthority) getSubsystem("ca");
        if ((ca != null) && !isPreOpMode()) {
            CMS.debug("CMSEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            CMS.debug("CMSEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }

        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) getSubsystem("kra");
        if ((kra != null) && !isPreOpMode()) {
            CMS.debug("CMSEngine: checking request serial number ranges for the KRA");
            kra.getRequestQueue().getRequestRepository().checkRanges();

            CMS.debug("CMSEngine: checking key serial number ranges");
            kra.getKeyRepository().checkRanges();
        }

        /*LogDoc
         *
         * @phase server startup
         * @reason all subsystems are initialized and started.
         */
        Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_ADMIN,
                ILogger.LL_INFO, CMS.getLogMessage("SERVER_STARTUP"));
        System.out.println(Constants.SERVER_STARTUP_MESSAGE);
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
                    CMS.getSubsystem("ca");
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

        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME) ||
                tokenName.equalsIgnoreCase("Internal Key Storage Token"))
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
        // modify server.xml
        /*
                String filePrefix = instanceDir + File.separator +
                    "config" + File.separator;
                String orig = filePrefix + "server.xml";
                String dest = filePrefix + "server.xml.bak";
                String newF = filePrefix + "server.xml.new";

                // save the old copy
                Utils.copy(orig, dest);

                BufferedReader in1 = null;
                PrintWriter out1 = null;

                try {
                    in1 = new BufferedReader(new FileReader(dest));
                    out1 = new PrintWriter(
                                new BufferedWriter(new FileWriter(newF)));
                    String line = "";

                    while (in1.ready()) {
                        line = in1.readLine();
                        if (line != null)
                            out1.println(lineParsing(line, newName));
                    }

                    out1.close();
                    in1.close();
                } catch (Exception eee) {
                    Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_ADMIN,
                        ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", eee.toString()));
                }

                File file = new File(newF);
                File nfile = new File(orig);

                try {
                    boolean success = file.renameTo(nfile);

                    if (!success) {
                        if (Utils.isNT()) {
                            // NT is very picky on the path
                            Utils.exec("copy " +
                                file.getAbsolutePath().replace('/', '\\') + " " +
                                nfile.getAbsolutePath().replace('/', '\\'));
                        } else {
                            Utils.exec("cp " + file.getAbsolutePath() + " " +
                                nfile.getAbsolutePath());
                        }
                    }
                } catch (Exception exx) {
                    Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_ADMIN,
                        ILogger.LL_FAILURE, "CMSEngine: Error " + exx.toString());
                }
                // update "cache" for CMS.getServerCertNickname()
        */
        mServerCertNickname = newName;
    }

    public String getFingerPrint(Certificate cert)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        return CertUtils.getFingerPrint(cert);
    }

    public String getFingerPrints(Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        return CertUtils.getFingerPrints(cert);
    }

    public String getFingerPrints(byte[] certDer)
            throws NoSuchAlgorithmException {
        return CertUtils.getFingerPrints(certDer);
    }

    public String getUserMessage(Locale locale, String msgID, String params[]) {
        // if locale is null, try to get it out from session context
        if (locale == null) {
            SessionContext sc = SessionContext.getExistingContext();

            if (sc != null)
                locale = (Locale) sc.get(SessionContext.LOCALE);
        }
        ResourceBundle rb = null;

        if (locale == null) {
            rb = ResourceBundle.getBundle(
                        "UserMessages", Locale.ENGLISH);
        } else {
            rb = ResourceBundle.getBundle(
                        "UserMessages", locale);
        }
        String msg = rb.getString(msgID);

        if (params == null)
            return msg;
        MessageFormat mf = new MessageFormat(msg);

        return mf.format(params);
    }

    public String getUserMessage(Locale locale, String msgID) {
        return getUserMessage(locale, msgID, (String[]) null);
    }

    public String getUserMessage(Locale locale, String msgID, String p1) {
        String params[] = { p1 };

        return getUserMessage(locale, msgID, params);
    }

    public String getUserMessage(Locale locale, String msgID, String p1, String p2) {
        String params[] = { p1, p2 };

        return getUserMessage(locale, msgID, params);
    }

    public String getUserMessage(Locale locale, String msgID,
            String p1, String p2, String p3) {
        String params[] = { p1, p2, p3 };

        return getUserMessage(locale, msgID, params);
    }

    public String getLogMessage(String msgID, String params[]) {
        ResourceBundle rb = ResourceBundle.getBundle(
                "LogMessages");
        String msg = rb.getString(msgID);

        if (params == null)
            return msg;
        MessageFormat mf = new MessageFormat(msg);

        return mf.format(params);
    }

    public void debug(byte data[]) {
        if (!debugOn()) {
            // this helps to not saving stuff to file when debug
            // is disable
            return;
        }
        Debug.print(data);
    }

    public void debug(int level, String msg) {
        if (!debugOn()) {
            // this helps to not saving stuff to file when debug
            // is disable
            return;
        }
        Debug.trace(level, msg);
    }

    public void debug(String msg) {
        if (!debugOn()) {
            // this helps to not saving stuff to file when debug
            // is disable
            return;
        }
        Debug.trace(msg);
    }

    public void debug(Throwable e) {
        if (!debugOn()) {
            // this helps to not saving stuff to file when debug
            // is disable
            return;
        }
        Debug.printStackTrace(e);
    }

    public boolean debugOn() {
        return Debug.on();
    }

    public void debugStackTrace() {
        Debug.printStackTrace();
    }

    public void traceHashKey(String type, String key) {
        Debug.traceHashKey(type, key);
    }

    public void traceHashKey(String type, String key, String val) {
        Debug.traceHashKey(type, key, val);
    }

    public void traceHashKey(String type, String key, String val, String def) {
        Debug.traceHashKey(type, key, val, def);
    }

    public String getLogMessage(String msgID) {
        return getLogMessage(msgID, (String[]) null);
    }

    public String getLogMessage(String msgID, String p1) {
        String params[] = { p1 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2) {
        String params[] = { p1, p2 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3) {
        String params[] = { p1, p2, p3 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4) {
        String params[] = { p1, p2, p3, p4 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5) {
        String params[] = { p1, p2, p3, p4, p5 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6) {
        String params[] = { p1, p2, p3, p4, p5, p6 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7) {
        String params[] = { p1, p2, p3, p4, p5, p6, p7 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8) {
        String params[] = { p1, p2, p3, p4, p5, p6, p7, p8 };

        return getLogMessage(msgID, params);
    }

    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8, String p9) {
        String params[] = { p1, p2, p3, p4, p5, p6, p7, p8, p9 };

        return getLogMessage(msgID, params);
    }

    public void getSubjAltNameConfigDefaultParams(String name,
            Vector<String> params) {
        GeneralNameUtil.SubjAltNameGN.getDefaultParams(name, params);
    }

    public void getSubjAltNameConfigExtendedPluginInfo(String name,
            Vector<String> params) {
        GeneralNameUtil.SubjAltNameGN.getExtendedPluginInfo(name, params);
    }

    public ISubjAltNameConfig createSubjAltNameConfig(String name, IConfigStore config, boolean isValueConfigured)
            throws EBaseException {
        return new GeneralNameUtil.SubjAltNameGN(name, config, isValueConfigured);
    }

    public GeneralName form_GeneralNameAsConstraints(String generalNameChoice, String value) throws EBaseException {
        return GeneralNameUtil.form_GeneralNameAsConstraints(generalNameChoice, value);
    }

    public GeneralName form_GeneralName(String generalNameChoice,
            String value) throws EBaseException {
        return GeneralNameUtil.form_GeneralName(generalNameChoice, value);
    }

    public void getGeneralNameConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
        GeneralNameUtil.GeneralNameConfig.getDefaultParams(name, isValueConfigured, params);
    }

    public void getGeneralNamesConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
        GeneralNameUtil.GeneralNamesConfig.getDefaultParams(name, isValueConfigured, params);
    }

    public void getGeneralNameConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
        GeneralNameUtil.GeneralNameConfig.getExtendedPluginInfo(name, isValueConfigured, info);
    }

    public void getGeneralNamesConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
        GeneralNameUtil.GeneralNamesConfig.getExtendedPluginInfo(name, isValueConfigured, info);
    }

    public IGeneralNamesConfig createGeneralNamesConfig(String name,
            IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return new GeneralNameUtil.GeneralNamesConfig(name, config, isValueConfigured, isPolicyEnabled);
    }

    public IGeneralNameAsConstraintsConfig createGeneralNameAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return new GeneralNameUtil.GeneralNameAsConstraintsConfig(name, config, isValueConfigured, isPolicyEnabled);
    }

    public IGeneralNamesAsConstraintsConfig createGeneralNamesAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return new GeneralNameUtil.GeneralNamesAsConstraintsConfig(name, config, isValueConfigured, isPolicyEnabled);
    }

    public ObjectIdentifier checkOID(String attrName, String value)
            throws EBaseException {
        return CertUtils.checkOID(attrName, value);
    }

    public String BtoA(byte data[]) {
        return Utils.base64encode(data);
    }

    public byte[] AtoB(String data) {
        return Utils.base64decode(data);
    }

    public String getEncodedCert(X509Certificate cert) {
        try {
            return "-----BEGIN CERTIFICATE-----\n" +
                    CMS.BtoA(cert.getEncoded()) +
                    "-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            return null;
        }
    }

    public boolean verifySystemCerts() {
        return CertUtils.verifySystemCerts();
    }

    public boolean verifySystemCertByTag(String tag) {
        return CertUtils.verifySystemCertByTag(tag);
    }

    public boolean verifySystemCertByNickname(String nickname, String certificateUsage) {
        return CertUtils.verifySystemCertByNickname(nickname, certificateUsage);
    }

    public CertificateUsage getCertificateUsage(String certusage) {
        return CertUtils.getCertificateUsage(certusage);
    }

    public boolean isSigningCert(X509Certificate cert) {
        return CertUtils.isSigningCert((X509CertImpl) cert);
    }

    public boolean isEncryptionCert(X509Certificate cert) {
        return CertUtils.isEncryptionCert((X509CertImpl) cert);
    }

    public X509CertInfo getDefaultX509CertInfo() {
        return new CertInfo();
    }

    public IEmailResolverKeys getEmailResolverKeys() {
        return new EmailResolverKeys();
    }

    public IEmailResolver getReqCertSANameEmailResolver() {
        return new ReqCertSANameEmailResolver();
    }

    public IEmailFormProcessor getEmailFormProcessor() {
        return new EmailFormProcessor();
    }

    public IEmailTemplate getEmailTemplate(String path) {
        return new EmailTemplate(path);
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

    public IPrettyPrintFormat getPrettyPrintFormat(String delimiter) {
        return new com.netscape.cmscore.cert.PrettyPrintFormat(delimiter);
    }

    public IExtPrettyPrint getExtPrettyPrint(Extension e, int indent) {
        return new ExtPrettyPrint(e, indent);
    }

    public ICertPrettyPrint getCertPrettyPrint(X509Certificate cert) {
        return new CertPrettyPrint(cert);
    }

    public ICRLPrettyPrint getCRLPrettyPrint(X509CRL crl) {
        return new CrlPrettyPrint((X509CRLImpl) crl);
    }

    public ICRLPrettyPrint getCRLCachePrettyPrint(ICRLIssuingPoint ip) {
        return new CrlCachePrettyPrint(ip);
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

    public ILogger getLogger() {
        return Logger.getLogger();
    }

    public IAuditor getAuditor() {
        return Auditor.getAuditor();
    }

    public ILogger getSignedAuditLogger() {
        return SignedAuditLogger.getLogger();
    }

    /**
     * starts up subsystems in a subsystem list..
     */
    private void startupSubsystems(SubsystemInfo[] sslist)
            throws EBaseException {
        ISubsystem ss = null;

        for (int i = 0; i < sslist.length; i++) {
            CMS.debug("CMSEngine: " + sslist[i].mId + " startup start");
            ss = sslist[i].mInstance;
            ss.startup();
            CMS.debug("CMSEngine: " + sslist[i].mId + " startup done");
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

    private void shutdownHttpServer() {

        try {
            String cmds[] = null;
            String cmd = "stop-cert";
            if (isNT()) {
                // NT
                cmds = new String[3];
                cmds[0] = "cmd";
                cmds[1] = "/c";
                cmds[2] = instanceDir + "\\" + cmd;
            } else {
                // UNIX
                cmds = new String[3];
                cmds[0] = "/bin/sh";
                cmds[1] = "-c";
                cmds[2] = instanceDir + "/" + cmd;
            }

            Process process = Runtime.getRuntime().exec(cmds);

            process.waitFor();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    } // end shutdownHttpServer

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     */
    public void shutdown() {
        Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_ADMIN,
                ILogger.LL_INFO, Constants.SERVER_SHUTDOWN_MESSAGE);

        CMS.debug("CMSEngine.shutdown()");

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

        shutdownSubsystems(mFinalSubsystems);
        shutdownSubsystems(mDynSubsystems);
        shutdownSubsystems(mStaticSubsystems);
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     * Added extra call to shutdown the web server.
     */

    public void forceShutdown() {

        Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_ADMIN,
                ILogger.LL_INFO, Constants.SERVER_SHUTDOWN_MESSAGE);

        CMS.debug("CMSEngine.forceShutdown()");

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
        terminateRequests();

        shutdownSubsystems(mFinalSubsystems);
        shutdownSubsystems(mDynSubsystems);
        shutdownSubsystems(mStaticSubsystems);
        shutdownHttpServer();

    }

    /**
     * shuts down a subsystem list in reverse order.
     */
    private void shutdownSubsystems(SubsystemInfo[] sslist) {
        if (sslist == null)
            return;

        for (int i = sslist.length - 1; i >= 0; i--) {
            if (sslist[i] != null && sslist[i].mInstance != null) {
                sslist[i].mInstance.shutdown();
            }
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
            Logger.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SDR_ADD_ERROR", e.toString()));
        }
    }

    public PasswordCallback getPasswordCallback() {
        return new PWCBsdr();
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
            e.printStackTrace();

        } finally {
            if (bf != null) try { bf.close(); } catch (Exception e) { e.printStackTrace(); }
        }

        return pid;
    }

    public Date getCurrentDate() {
        if (mTimeSource == null) {
            return new Date();
        }
        return mTimeSource.getCurrentDate();
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

    public ICommandQueue getCommandQueue() {
        return new CommandQueue();
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
            CMS.debug("CMSEngine: " + CMS.getLogMessage("CMSCORE_AUTH_AGENT_CERT_REPO"));
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AGENT_REQUEST_QUEUE"));
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
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AGENT_REVO_STATUS"));
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
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_AGENT_PROCESS_CHECKING"));
                        }
                    }
                }
            } else if (result == VerifiedCert.REVOKED) {
                revoked = true;
            }
        }

        return revoked;
    }

    private void log(int level, String msg) {
        Logger.getLogger().log(ILogger.EV_SYSTEM, null,
                ILogger.S_AUTHENTICATION, level, msg);
    }

    @Override
    public String getServerStatus() {
        return serverStatus;
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

class SubsystemInfo {
    public final String mId;
    public final ISubsystem mInstance;

    public SubsystemInfo(String id, ISubsystem ssInstance) {
        mId = id;
        mInstance = ssInstance;
    }

}
