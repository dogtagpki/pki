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
package com.netscape.cms.servlet.admin;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cmsutil.util.Utils;

/**
 * A class represents an administration servlet that
 * is responsible to serve administrative
 * operation such as configuration parameter updates.
 *
 * Since each administration servlet needs to perform
 * authentication information parsing and response
 * formulation, it makes sense to encapsulate the
 * commonalities into this class.
 *
 * By extending this serlvet, the subclass does not
 * need to re-implement the request parsing code
 * (i.e. authentication information parsing).
 *
 * If a subsystem needs to expose configuration
 * parameters management, it should create an
 * administration servlet (i.e. CAAdminServlet)
 * and register it to RemoteAdmin subsystem.
 *
 * <code>
 * public class CAAdminServlet extends AdminServlet {
 *   ...
 * }
 * </code>
 *
 * @version $Revision$, $Date$
 */
public class AdminServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 7740464244137421542L;
    private final static String HDR_AUTHORIZATION = "Authorization";
    private final static String HDR_LANG = "accept-language";

    protected ILogger mLogger = CMS.getLogger();
    protected IAuditor auditor = CMS.getAuditor();
    private IUGSubsystem mUG = null;
    protected IConfigStore mConfig = null;
    protected IAuthzSubsystem mAuthz = null;

    // we don't allow to switch authz db mid-way, for now
    protected String mAclMethod = null;
    protected String mOp = "";
    protected static String AUTHZ_RES_NAME = "certServer";
    protected AuthzToken mToken;

    private String mServletID = null;
    public final static String PROP_AUTHZ_MGR = "AuthzMgr";
    public final static String PROP_ACL = "ACLinfo";

    public final static String AUTHZ_MGR_BASIC = "BasicAclAuthz";
    public final static String AUTHZ_MGR_LDAP = "DirAclAuthz";
    public final static String PROP_ID = "ID";
    public final static String AUTHZ_CONFIG_STORE = "authz";
    public final static String AUTHZ_SRC_TYPE = "sourceType";
    public final static String AUTHZ_SRC_LDAP = "ldap";
    public final static String AUTHZ_SRC_XML = "web.xml";
    public static final String CERT_ATTR =
            "javax.servlet.request.X509Certificate";

    private final static String LOGGING_SIGNED_AUDIT_AUTH_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTH_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTH_SUCCESS_3";
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS_4";
    private final static String LOGGING_SIGNED_AUDIT_ROLE_ASSUME =
            "LOGGING_SIGNED_AUDIT_ROLE_ASSUME_3";
    private final static String CERTUSERDB =
            IAuthSubsystem.CERTUSERDB_AUTHMGR_ID;
    private final static String PASSWDUSERDB =
            IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID;

    /**
     * Constructs generic administration servlet.
     */
    public AdminServlet() {
    }

    /**
     * Initializes the servlet.
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mUG = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        mConfig = CMS.getConfigStore();

        String srcType = AUTHZ_SRC_LDAP;

        try {
            IConfigStore authzConfig = mConfig.getSubStore(AUTHZ_CONFIG_STORE);

            srcType = authzConfig.getString(AUTHZ_SRC_TYPE, AUTHZ_SRC_LDAP);
        } catch (EBaseException e) {
            CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_FAIL_SRC_TYPE"));
        }
        mAuthz =
                (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);

        mServletID = getSCparam(sc, PROP_ID, "servlet id unknown");
        CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_INITED", mServletID));

        if (srcType.equalsIgnoreCase(AUTHZ_SRC_XML)) {
            CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_INITED", ""));
            // get authz mgr from xml file;  if not specified, use
            //			ldap by default
            mAclMethod = getSCparam(sc, PROP_AUTHZ_MGR, AUTHZ_MGR_LDAP);

            if (mAclMethod.equalsIgnoreCase(AUTHZ_MGR_BASIC)) {
                String aclInfo = sc.getInitParameter(PROP_ACL);

                if (aclInfo != null) {
                    try {
                        addACLInfo(aclInfo);
                        //mAuthz.authzMgrAccessInit(mAclMethod, aclInfo);
                    } catch (EBaseException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_MGR_INIT_FAIL"));
                        throw new ServletException("failed to init authz info from xml config file");
                    }
                    CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_MGR_INIT_DONE", mServletID));
                } else { // PROP_AUTHZ_MGR not specified, use default authzmgr
                    CMS.debug("AdminServlet: "
                            + CMS.getLogMessage("ADMIN_SRVLT_PROP_ACL_NOT_SPEC", PROP_ACL, mServletID, AUTHZ_MGR_LDAP));
                }
            } else { // PROP_AUTHZ_MGR not specified, use default authzmgr
                CMS.debug("AdminServlet: "
                        + CMS.getLogMessage("ADMIN_SRVLT_PROP_ACL_NOT_SPEC", PROP_AUTHZ_MGR, mServletID, AUTHZ_MGR_LDAP));
            }

        } else {
            mAclMethod = AUTHZ_MGR_LDAP;
            CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_AUTH_LDAP_NOT_XML", mServletID));
        }
    }

    public void outputHttpParameters(HttpServletRequest httpReq) {
        CMS.debug("AdminServlet:service() uri = " + httpReq.getRequestURI());
        Enumeration<String> paramNames = httpReq.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String pn = paramNames.nextElement();
            // added this facility so that password can be hidden,
            // all sensitive parameters should be prefixed with
            // __ (double underscores); however, in the event that
            // a security parameter slips through, we perform multiple
            // additional checks to insure that it is NOT displayed
            if (pn.startsWith("__") ||
                    pn.endsWith("password") ||
                    pn.endsWith("passwd") ||
                    pn.endsWith("pwd") ||
                    pn.equalsIgnoreCase("admin_password_again") ||
                    pn.equalsIgnoreCase("directoryManagerPwd") ||
                    pn.equalsIgnoreCase("bindpassword") ||
                    pn.equalsIgnoreCase("bindpwd") ||
                    pn.equalsIgnoreCase("passwd") ||
                    pn.equalsIgnoreCase("password") ||
                    pn.equalsIgnoreCase("pin") ||
                    pn.equalsIgnoreCase("pwd") ||
                    pn.equalsIgnoreCase("pwdagain") ||
                    pn.equalsIgnoreCase("uPasswd")) {
                CMS.debug("AdminServlet::service() param name='" + pn +
                         "' value='(sensitive)'");
            } else {
                CMS.debug("AdminServlet::service() param name='" + pn +
                         "' value='" + httpReq.getParameter(pn) + "'");
            }
        }
    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        boolean running_state = CMS.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CMS server is not ready to serve.");

        if (CMS.debugOn()) {
            outputHttpParameters(req);
        }
    }

    private void addACLInfo(String info) throws EBaseException {
        StringTokenizer tokenizer = new StringTokenizer(info, "#");

        while (tokenizer.hasMoreTokens()) {
            String acl = tokenizer.nextToken();

            mAuthz.authzMgrAccessInit(mAclMethod, acl);
        }
    }

    private String getSCparam(ServletConfig sc, String param, String defVal) {
        String val = sc.getInitParameter(param);

        if (val == null)
            return defVal;
        else
            return val;
    }

    /**
     * Authenticates to the identity scope with the given
     * userid and password via identity manager.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTH_FAIL used when authentication fails (in case of SSL-client auth, only
     * webserver env can pick up the SSL violation; CMS authMgr can pick up cert mis-match, so this event is used)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTH_SUCCESS used when authentication succeeded
     * </ul>
     *
     * @exception IOException an input/output error has occurred
     */
    protected void authenticate(HttpServletRequest req) throws
            IOException {

        String auditMessage = null;
        String auditUID = ILogger.UNIDENTIFIED;
        String authType = "";

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            try {
                IConfigStore configStore = CMS.getConfigStore();

                authType = configStore.getString("authType");
            } catch (EBaseException e) {
                // do nothing for now.
            }
            IAuthSubsystem auth = (IAuthSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            X509Certificate cert = null;

            if (authType.equals("sslclientauth")) {
                X509Certificate[] allCerts =
                        (X509Certificate[]) req.getAttribute(CERT_ATTR);

                if (allCerts == null || allCerts.length == 0) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                ILogger.UNIDENTIFIED,
                                ILogger.FAILURE,
                                CERTUSERDB,
                                auditUID);

                    audit(auditMessage);

                    throw new IOException("No certificate");
                }

                cert = allCerts[0];
                try {
                    byte[] certEncoded = cert.getEncoded();

                    cert = new X509CertImpl(certEncoded);

                    // save the "Subject DN" of this certificate in case it
                    // must be audited as an authentication failure
                    String certUID = cert.getSubjectDN().getName();

                    if (certUID != null) {
                        certUID = certUID.trim();

                        if (!(certUID.equals(""))) {
                            auditUID = certUID;
                        }
                    }
                } catch (Exception e) {
                }
            }

            // create session (if we don't, identity will reject
            // the authentication).
            SessionContext sc = SessionContext.getContext();
            IAuthToken token = null;

            log(ILogger.LL_DEBUG, CMS.getLogMessage("ADMIN_SRVLT_ABOUT_AUTH",
                    mServletID));
            try {
                if (authType.equals("sslclientauth")) {
                    IAuthManager authMgr = auth.get(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);
                    IAuthCredentials authCreds =
                            getAuthCreds(authMgr, cert);

                    token = authMgr.authenticate(authCreds);
                } else {
                    String authToken = req.getHeader(HDR_AUTHORIZATION);
                    String b64s = authToken.substring(
                            authToken.lastIndexOf(' ') + 1);
                    String authCode = new String(Utils.base64decode(b64s));
                    String userid = authCode.substring(0,
                            authCode.indexOf(':'));
                    String password = authCode.substring(
                            authCode.indexOf(':') + 1);
                    AuthCredentials cred = new AuthCredentials();

                    // save the "userid" of this certificate in case it
                    // must be audited as an authentication failure
                    String pwdUID = userid;

                    if (pwdUID != null) {
                        pwdUID = pwdUID.trim();

                        if (!(pwdUID.equals(""))) {
                            auditUID = pwdUID;
                        }
                    }

                    cred.set("uid", userid);
                    cred.set("pwd", password);

                    token = auth.authenticate(cred,
                                IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
                    CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_AUTH_FOR_SRVLT",
                            mServletID));
                }
            } catch (EBaseException e) {
                //will fix it later for authorization
                /*
                 String errMsg = "authenticate(): " +
                 AdminResources.SRVLT_FAIL_AUTHS +": "+userid +":"+
                 e.getMessage();
                 log(ILogger.LL_FAILURE,
                 CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAIL",
                 CMS.getLogMessage("ADMIN_SRVLT_FAIL_AUTHS"),
                 userid,e.getMessage()));
                 */

                if (authType.equals("sslclientauth")) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                ILogger.UNIDENTIFIED,
                                ILogger.FAILURE,
                                CERTUSERDB,
                                auditUID);

                    audit(auditMessage);
                } else {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                ILogger.UNIDENTIFIED,
                                ILogger.FAILURE,
                                PASSWDUSERDB,
                                auditUID);

                    audit(auditMessage);
                }

                throw new IOException("authentication failed");
            }

            try {
                String tuserid = token.getInString("userid");

                if (tuserid == null) {
                    mLogger.log(
                            ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_NO_AUTH_TOKEN",
                                    tuserid));

                    if (authType.equals("sslclientauth")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                    ILogger.UNIDENTIFIED,
                                    ILogger.FAILURE,
                                    CERTUSERDB,
                                    auditUID);

                        audit(auditMessage);
                    } else {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                    ILogger.UNIDENTIFIED,
                                    ILogger.FAILURE,
                                    PASSWDUSERDB,
                                    auditUID);

                        audit(auditMessage);
                    }

                    throw new IOException("authentication failed");
                }

                // get user.
                // this either returns null or
                // throws exception when user not found
                IUser user = mUG.getUser(tuserid);

                if (user == null) {
                    mLogger.log(
                            ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_USER_NOT_FOUND",
                                    tuserid));

                    if (authType.equals("sslclientauth")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                    ILogger.UNIDENTIFIED,
                                    ILogger.FAILURE,
                                    CERTUSERDB,
                                    auditUID);

                        audit(auditMessage);
                    } else {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                    ILogger.UNIDENTIFIED,
                                    ILogger.FAILURE,
                                    PASSWDUSERDB,
                                    auditUID);

                        audit(auditMessage);
                    }

                    throw new IOException("authentication failed");
                }

                // set session context to work with some agent servlets.
                // XXX should see if this can be used for more things.
                SessionContext sessionContext = SessionContext.getContext();

                sessionContext.put(SessionContext.AUTH_TOKEN, token);
                sessionContext.put(SessionContext.USER_ID, tuserid);
                sessionContext.put(SessionContext.USER, user);
            } catch (EUsrGrpException e) {
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_USR_GRP_ERR", e.toString()));

                if (authType.equals("sslclientauth")) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                ILogger.UNIDENTIFIED,
                                ILogger.FAILURE,
                                CERTUSERDB,
                                auditUID);

                    audit(auditMessage);
                } else {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                                ILogger.UNIDENTIFIED,
                                ILogger.FAILURE,
                                PASSWDUSERDB,
                                auditUID);

                    audit(auditMessage);
                }

                throw new IOException("authentication failed");
            }

            // build locale based on the client language
            Locale locale = getLocale(req);

            sc.put(SessionContext.LOCALE, locale);

            if (authType.equals("sslclientauth")) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                            auditSubjectID(),
                            ILogger.SUCCESS,
                            CERTUSERDB);

                audit(auditMessage);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                            auditSubjectID(),
                            ILogger.SUCCESS,
                            PASSWDUSERDB);

                audit(auditMessage);
            }
        } catch (IOException eAudit1) {
            if (authType.equals("sslclientauth")) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                            ILogger.UNIDENTIFIED,
                            ILogger.FAILURE,
                            CERTUSERDB,
                            auditUID);

                audit(auditMessage);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                            ILogger.UNIDENTIFIED,
                            ILogger.FAILURE,
                            PASSWDUSERDB,
                            auditUID);

                audit(auditMessage);
            }

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    public static AuthCredentials getAuthCreds(
            IAuthManager authMgr, X509Certificate clientCert)
            throws EBaseException {
        // get credentials from http parameters.
        String[] reqCreds = authMgr.getRequiredCreds();
        AuthCredentials creds = new AuthCredentials();

        for (int i = 0; i < reqCreds.length; i++) {
            String reqCred = reqCreds[i];

            if (reqCred.equals(IAuthManager.CRED_SSL_CLIENT_CERT)) {
                // cert could be null;
                creds.set(reqCred, new X509Certificate[] { clientCert }
                        );
            }
        }
        return creds;
    }

    /**
     * Authorize must occur after Authenticate
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_FAIL used when authorization has failed
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS used when authorization is successful
     * <li>signed.audit LOGGING_SIGNED_AUDIT_ROLE_ASSUME used when user assumes a role (in current CMS that's when one
     * accesses a role port)
     * </ul>
     *
     * @param req HTTP servlet request
     * @return the authorization token
     */
    protected AuthzToken authorize(HttpServletRequest req) {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditACLResource = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String auditOperation = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String resource = null;
        String operation = null;

        // use session context to get auth token for now
        SessionContext sc = SessionContext.getContext();
        IAuthToken authToken = (IAuthToken) sc.get(SessionContext.AUTH_TOKEN);

        AuthzToken authzTok = null;

        CMS.debug("AdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CHECK_AUTHZ_AUTH", mServletID));
        // hardcoded for now .. just testing
        try {
            // we check both "read" and "write" for now. later within
            //			each servlet, they can break it down
            authzTok = mAuthz.authorize(mAclMethod, authToken, AUTHZ_RES_NAME, mOp);
            // initialize the ACL resource, overwriting "auditACLResource"
            // if it is not null
            resource = (String)
                    authzTok.get(AuthzToken.TOKEN_AUTHZ_RESOURCE);
            if (resource != null) {
                auditACLResource = resource.trim();
            }

            // initialize the operation, overwriting "auditOperation"
            // if it is not null
            operation = (String)
                    authzTok.get(AuthzToken.TOKEN_AUTHZ_OPERATION);
            if (operation != null) {
                auditOperation = operation.trim();
            }

            CMS.debug(CMS.getLogMessage("ADMIN_SRVLT_AUTH_SUCCEED", mServletID));
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditGroups(auditSubjectID));

            audit(auditMessage);

            return null;
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditGroups(auditSubjectID));

            audit(auditMessage);

            return null;
        } catch (Exception e) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditACLResource,
                        auditOperation);

            audit(auditMessage);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditGroups(auditSubjectID));

            audit(auditMessage);

            return null;
        }

        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditACLResource,
                    auditOperation);

        audit(auditMessage);

        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditGroups(auditSubjectID));

        audit(auditMessage);

        return authzTok;
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader(HDR_LANG);

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                        UserInfo.getUserCountry(lang));
        }
        return locale;
    }

    public static int SUCCESS = 0;
    public static int ERROR = 1;
    public static int RESTART = -1;

    /**
     * Sends response.
     *
     * @param returnCode return code
     * @param errorMsg localized error message
     * @param params result parameters
     * @param resp HTTP servlet response
     */
    protected void sendResponse(int returnCode, String errorMsg,
            NameValuePairs params, HttpServletResponse resp)
            throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        dos.writeInt(returnCode);
        if (errorMsg != null) {
            dos.writeUTF(errorMsg);
        }
        StringBuffer buf = new StringBuffer();

        if (params != null) {
            Collection<String> names = params.keySet();

            if (!names.isEmpty()) {
                for (Iterator<String> i = names.iterator(); i.hasNext(); ) {
                    String name = i.next();
                    String value = java.net.URLEncoder.encode(
                            params.get(name), "UTF-8");

                    buf.append(java.net.URLEncoder.encode(name, "UTF-8") +
                            "=" + value);
                    if (i.hasNext())
                        buf.append("&");
                }
                byte content[] = buf.toString().getBytes();

                dos.write(content, 0, content.length);
            }
        }
        byte msg[] = bos.toByteArray();

        resp.setContentLength(msg.length);
        resp.getOutputStream().write(msg);
        resp.getOutputStream().flush();
    }

    /**
     * URL decodes the given string.
     */
    protected String URLdecode(String s) {
        if (s == null)
            return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);

            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);

                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        } // end for
        return out.toString();
    }

    protected String getParameter(HttpServletRequest req, String name) {
        // Servlet framework already apply URLdecode
        //   return URLdecode(req.getParameter(name));
        return req.getParameter(name);
    }

    /**
     * Generic configuration store get operation.
     */
    protected synchronized void getConfig(
            IConfigStore config, HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            //if (name.equals(Constants.PT_OP))
            //	continue;
            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;

            //System.out.println(name);
            //System.out.println(name+","+config.getString(name));
            params.put(name, config.getString(name));
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Generic configuration store set operation.
     * The caller is responsible to do validiation before
     * calling this, and commit changes after this call.
     */
    protected synchronized void setConfig(
            IConfigStore config, HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            //if (name.equals(Constants.PT_OP))
            //	continue;
            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            // XXX Need validation...
            // XXX what if update failed
            config.putString(name, req.getParameter(name));
        }
        commit(true);
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Lists configuration store.
     */
    protected synchronized void listConfig(
            IConfigStore config, HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> e = config.getPropertyNames();
        NameValuePairs params = new NameValuePairs();

        while (e.hasMoreElements()) {
            String s = e.nextElement();

            params.put(s, config.getString(s));
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * authorize a user based on its authentication credentials.
     */
    public boolean authorize(IAuthToken token) throws EBaseException {
        String mGroupNames[] = { "Administrators" };
        boolean mAnd = true;

        try {
            String userid = token.getInString("userid");

            if (userid == null) {
                mLogger.log(
                        ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_GRP_AUTHZ_FAIL", userid));
                return false;
            }

            // get user.
            // this either returns null or throws exception when user not found
            IUser user = mUG.getUser(userid);

            if (user == null) {
                mLogger.log(
                        ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_USER_NOT_IN_DB", userid));
                return false;
            }

            // set session context to work with some agent servlets.
            // XXX should see if this can be used for more things.
            SessionContext sessionContext = SessionContext.getContext();

            sessionContext.put(SessionContext.AUTH_TOKEN, token);
            sessionContext.put(SessionContext.USER_ID, userid);
            sessionContext.put(SessionContext.USER, user);

            // check group membership of user.
            if (mAnd) {
                for (int i = 0; i < mGroupNames.length; i++) {
                    if (!mUG.isMemberOf(user, mGroupNames[i])) {
                        mLogger.log(
                                ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                                CMS.getLogMessage("ADMIN_SRVLT_USER_NOT_IN_GRP", userid,
                                        mGroupNames[i]));
                        return false;
                    }
                }
                return true;
            } else {
                for (int i = 0; i < mGroupNames.length; i++) {
                    if (mUG.isMemberOf(user, mGroupNames[i])) {
                        mLogger.log(ILogger.EV_SYSTEM,
                                ILogger.S_OTHER, ILogger.LL_INFO,
                                CMS.getLogMessage("ADMIN_SRVLT_GRP_AUTH_SUCC_USER", userid,
                                        mGroupNames[i]));
                        return true;
                    }
                }
                StringBuffer groups = new StringBuffer();
                groups.append(mGroupNames[0]);

                for (int j = 1; j < mGroupNames.length; j++) {
                    groups.append(",");
                    groups.append(mGroupNames[j]);
                }
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                        ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_USER_NOT_ANY_GRP", userid, groups.toString()));
                return false;
            }
        } catch (EUsrGrpException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_USR_GRP_ERR", e.toString()));
            return false;
        }
    }

    /**
     * FileConfigStore functionality
     *
     * The original config file is moved to <filename>.<date>.
     * Commits the current properties to the configuration file.
     * <P>
     *
     * @param createBackup true if a backup file should be created
     */
    protected void commit(boolean createBackup) throws EBaseException {
        mConfig.commit(createBackup);
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_ADMIN,
                level, "AdminServlet: " + msg);
    }

    /**
     * Signed Audit Log
     *
     * This method is inherited by all extended admin servlets
     * and is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (auditor == null) {
            return;
        }

        auditor.log(msg);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {
        if (auditor == null) return null;
        return auditor.getSubjectID();
    }

    /**
     * Signed Audit Parameters
     *
     * This method is inherited by all extended admin servlets and
     * is called to extract parameters from the HttpServletRequest
     * and return a string of name;;value pairs separated by a '+'
     * if more than one name;;value pair exists.
     * <P>
     *
     * @param req HTTP servlet request
     * @return a delimited string of one or more delimited name/value pairs
     */
    protected String auditParams(HttpServletRequest req) {
        if (auditor == null) return null;

        // always identify the scope of the request
        String scope = req.getParameter(Constants.OP_SCOPE);

        // identify the operation type of the request
        String type = req.getParameter(Constants.OP_TYPE);

        // identify the resource type of the request
        String id = req.getParameter(Constants.RS_ID);

        // identify any remaining request parameters
        Map<String, String> params = new LinkedHashMap<String, String>();

        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            // skip previously extracted parameters
            if (name.equals(Constants.OP_SCOPE)) continue;
            if (name.equals(Constants.OP_TYPE)) continue;
            if (name.equals(Constants.RS_ID)) continue;

            String value = req.getParameter(name);
            params.put(name, value);
        }

        return auditor.getParamString(scope, type, id, params);
    }

    /**
     * Signed Audit Groups
     *
     * This method is called to extract all "groups" associated
     * with the "auditSubjectID()".
     * <P>
     *
     * @param subjectID string containing the signed audit log message SubjectID
     * @return a delimited string of groups associated
     *         with the "auditSubjectID()"
     */
    private String auditGroups(String subjectID) {
        if (auditor == null) return null;
        return auditor.getGroups(subjectID);
    }

    protected NameValuePairs convertStringArrayToNVPairs(String[] s) {
        if (s == null)
            return null;
        NameValuePairs nvps = new NameValuePairs();
        int i;

        for (i = 0; i < s.length; i++) {
            int j = s[i].indexOf(";");
            String paramName = s[i].substring(0, j);
            String args = s[i].substring(j + 1);

            nvps.put(paramName, args);
        }
        return nvps;

    }

    protected static IExtendedPluginInfo getClassByNameAsExtendedPluginInfo(String className) {

        IExtendedPluginInfo epi = null;

        try {
            // here is the new dummy obj created
            Object o = Class.forName(className).newInstance();

            epi = (IExtendedPluginInfo) o;
        } catch (Exception e) {
        }

        return epi;
    }
}
