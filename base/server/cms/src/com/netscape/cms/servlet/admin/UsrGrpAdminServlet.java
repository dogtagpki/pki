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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.pkcs.PKCS7;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

/**
 * A class representing an administration servlet for
 * User/Group Manager. It communicates with client
 * SDK to allow remote administration of User/Group
 * manager.
 *
 * This servlet will be registered to remote
 * administration subsystem by usrgrp manager.
 *
 * @version $Revision$, $Date$
 */
public class UsrGrpAdminServlet extends AdminServlet {

    /**
     *
     */
    private static final long serialVersionUID = -4341817607402387714L;
    private final static String INFO = "UsrGrpAdminServlet";
    private final static String RES_CA_GROUP = "certServer.ca.group";
    private final static String RES_RA_GROUP = "certServer.ra.group";
    private final static String RES_KRA_GROUP = "certServer.kra.group";
    private final static String RES_OCSP_GROUP = "certServer.ocsp.group";
    private final static String RES_TKS_GROUP = "certServer.tks.group";
    private final static String SYSTEM_USER = "$System$";
    //	private final static String RES_GROUP = "root.common.goldfish";

    private final static String BACK_SLASH = "\\";

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_ROLE =
            "LOGGING_SIGNED_AUDIT_CONFIG_ROLE_3";

    private IUGSubsystem mMgr = null;

    private static String[] mMultiRoleGroupEnforceList = null;
    private final static String MULTI_ROLE_ENABLE = "multiroles.enable";
    private final static String MULTI_ROLE_ENFORCE_GROUP_LIST = "multiroles.false.groupEnforceList";

    /**
     * Constructs User/Group manager servlet.
     */
    public UsrGrpAdminServlet() {
        super();
        mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mMgr = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves incoming User/Group management request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        String scope = super.getParameter(req, Constants.OP_SCOPE);
        String op = super.getParameter(req, Constants.OP_TYPE);

        if (op == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_INVALID_PROTOCOL"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        Locale clientLocale = super.getLocale(req);

        try {
            super.authenticate(req);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_FAIL_AUTHS"));

            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        // authorization
        // temporary test before servlets are exposed with authtoken
        /*
         SessionContext sc = SessionContext.getContext();
         AuthToken authToken = (AuthToken) sc.get(SessionContext.AUTH_TOKEN);

         AuthzToken authzTok = null;
         CMS.debug("UserGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CHECK_AUTHZ_SUB"));
         // hardcoded for now .. just testing
         try {
         authzTok = mAuthz.authorize("DirAclAuthz", authToken, RES_GROUP, "read");
         } catch (EBaseException e) {
         log(ILogger.LL_FAILURE,  CMS.getLogMessage("ADMIN_SRVLT_AUTH_CALL_FAIL",e.toString()));
         }
         if (AuthzToken.AUTHZ_STATUS_FAIL.equals(authzTok.get(AuthzToken.TOKEN_AUTHZ_STATUS))) {
         // audit would have been needed here if this weren't just a test...

         log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_FAIL_AUTHS"));

         sendResponse(ERROR,
         MessageFormatter.getLocalizedString(
         getLocale(req),
         AdminResources.class.getName(),
         AdminResources.SRVLT_FAIL_AUTHS),
         null, resp);
         return;
         }
         */

        try {
            ISubsystem subsystem = CMS.getSubsystem("ca");
            if (subsystem != null)
                AUTHZ_RES_NAME = RES_CA_GROUP;
            subsystem = CMS.getSubsystem("ra");
            if (subsystem != null)
                AUTHZ_RES_NAME = RES_RA_GROUP;
            subsystem = CMS.getSubsystem("kra");
            if (subsystem != null)
                AUTHZ_RES_NAME = RES_KRA_GROUP;
            subsystem = CMS.getSubsystem("ocsp");
            if (subsystem != null)
                AUTHZ_RES_NAME = RES_OCSP_GROUP;
            subsystem = CMS.getSubsystem("tks");
            if (subsystem != null)
                AUTHZ_RES_NAME = RES_TKS_GROUP;
            if (scope != null) {
                if (scope.equals(ScopeDef.SC_USER_TYPE)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }

                    getUserType(req, resp);
                    return;
                }

                if (op.equals(OpDef.OP_READ)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_GROUPS)) {
                        findGroup(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USERS)) {
                        findUser(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                        findUserCerts(req, resp, clientLocale);
                        return;
                    }
                } else if (op.equals(OpDef.OP_MODIFY)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_GROUPS)) {
                        modifyGroup(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USERS)) {
                        modifyUser(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                        modifyUserCert(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_ADD)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_GROUPS)) {
                        addGroup(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USERS)) {
                        addUser(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                        addUserCert(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_DELETE)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_GROUPS)) {
                        removeGroup(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USERS)) {
                        removeUser(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_SEARCH)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_GROUPS)) {
                        findGroups(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_USERS)) {
                        findUsers(req, resp);
                        return;
                    } else {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("ADMIN_SRVLT_INVALID_OP_SCOPE"));
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                                null, resp);
                        return;
                    }
                }
            } // if
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, e.toString());
            sendResponse(ERROR, e.toString(getLocale(req)),
                    null, resp);
            return;
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            log(ILogger.LL_FAILURE, CMS.getLogMessage(" ADMIN_SRVLT_FAIL_PERFORM"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                    null, resp);
            return;
        }
    }

    private void getUserType(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = super.getParameter(req, Constants.RS_ID);
        IUser user = mMgr.getUser(id);
        String val = user.getUserType();

        if (val == null || val.equals(""))
            val = "noType";
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_USER_TYPE, val);
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Searches for users in LDAP directory. List uids only
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    private synchronized void findUsers(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        Enumeration<IUser> e = null;

        try {
            e = mMgr.listUsers("*");
        } catch (Exception ex) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        StringBuffer sb = new StringBuffer();
        int i = 0;

        while (e.hasMoreElements()) {
            IUser user = e.nextElement();

            if (i > 0) {
                sb.append(";");
                sb.append(user.getUserID());
                sb.append(":");
                sb.append(user.getFullName());
            } else {
                sb.append(user.getUserID());
                sb.append(":");
                sb.append(user.getFullName());
            }
            i++;
        }
        params.put("userInfo", sb.toString());

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * List user information. Certificates covered in a separate
     * protocol for findUserCerts(). List of group memberships are
     * also provided.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    private synchronized void findUser(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        NameValuePairs params = new NameValuePairs();

        IUser user = null;

        try {
            user = mMgr.getUser(id);
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        if (user != null) {
            params.put(Constants.PR_USER_FULLNAME, user.getFullName());
            params.put(Constants.PR_USER_EMAIL, user.getEmail());
            params.put(Constants.PR_USER_PHONE, user.getPhone());
            params.put(Constants.PR_USER_STATE, user.getState());

            // get list of groups, and get a list of those that this
            //			uid belongs to
            Enumeration<IGroup> e = null;

            try {
                e = mMgr.findGroups("*");
            } catch (Exception ex) {
                ex.printStackTrace();
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
                return;
            }

            StringBuffer grpString = new StringBuffer();

            while (e.hasMoreElements()) {
                IGroup group = e.nextElement();

                if (group.isMember(id) == true) {
                    if (grpString.length() != 0) {
                        grpString.append(",");
                    }
                    grpString.append(group.getGroupID());
                }
            }

            params.put(Constants.PR_USER_GROUP, grpString.toString());

            sendResponse(SUCCESS, null, params, resp);
            return;
        }

        log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
        return;
    }

    /**
     * List user certificate(s)
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    private synchronized void findUserCerts(HttpServletRequest req,
            HttpServletResponse resp, Locale clientLocale)
            throws ServletException,
            IOException, EBaseException {

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        NameValuePairs params = new NameValuePairs();

        IUser user = null;

        try {
            user = mMgr.getUser(id);
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
            return;
        }

        if (user == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
            return;
        }

        X509Certificate[] certs =
                user.getX509Certificates();

        if (certs != null) {
            for (int i = 0; i < certs.length; i++) {
                ICertPrettyPrint print = CMS.getCertPrettyPrint(certs[i]);

                // add base64 encoding
                String base64 = CMS.getEncodedCert(certs[i]);

                // pretty print certs
                params.put(getCertificateString(certs[i]),
                        print.toString(clientLocale) + "\n" + base64);
            }
            sendResponse(SUCCESS, null, params, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * Converts certificate into string format.
     */
    protected String getCertificateString(X509Certificate cert) {
        if (cert == null) {
            return null;
        }

        // note that it did not represent a certificate fully
        return cert.getVersion() + ";" + cert.getSerialNumber().toString() +
                ";" + cert.getIssuerDN() + ";" + cert.getSubjectDN();
    }

    /**
     * Searchess for groups in LDAP server
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#group
     */
    private synchronized void findGroups(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        Enumeration<IGroup> e = null;

        try {
            e = mMgr.listGroups("*");
        } catch (Exception ex) {
            ex.printStackTrace();
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        while (e.hasMoreElements()) {
            IGroup group = e.nextElement();
            String desc = group.getDescription();

            if (desc != null) {
                params.put(group.getGroupID(), desc);
            } else {
                params.put(group.getGroupID(), "");
            }
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * finds a group
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    private synchronized void findGroup(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        Enumeration<IGroup> e = null;

        try {
            e = mMgr.findGroups(id);
        } catch (Exception ex) {
            ex.printStackTrace();
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        if (e.hasMoreElements()) {
            IGroup group = e.nextElement();

            params.put(Constants.PR_GROUP_GROUP, group.getGroupID());
            params.put(Constants.PR_GROUP_DESC,
                    group.getDescription());

            Enumeration<String> members = group.getMemberNames();
            StringBuffer membersString = new StringBuffer();

            if (members != null) {
                while (members.hasMoreElements()) {
                    if (membersString.length() != 0) {
                        membersString.append(", ");
                    }

                    String mn = members.nextElement();

                    membersString.append(mn);
                }
            }

            params.put(Constants.PR_GROUP_USER, membersString.toString());

            sendResponse(SUCCESS, null, params, resp);
            return;
        } else {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"), null, resp);
            return;

        }
    }

    /**
     * Adds a new user to LDAP server
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void addUser(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            if (id.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_RS_ID_BS"),
                        null, resp);
                return;
            }

            if (id.equals(SYSTEM_USER)) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", id));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_SPECIAL_ID", id),
                        null, resp);
                return;
            }

            IUser user = mMgr.createUser(id);
            String fname = super.getParameter(req, Constants.PR_USER_FULLNAME);

            if ((fname == null) || (fname.length() == 0)) {
                String msg = CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED_1", "full name");

                log(ILogger.LL_FAILURE, msg);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, msg, null, resp);
                return;
            } else
                user.setFullName(fname);

            String email = super.getParameter(req, Constants.PR_USER_EMAIL);

            if (email != null) {
                user.setEmail(email);
            } else {
                user.setEmail("");
            }
            String pword = super.getParameter(req, Constants.PR_USER_PASSWORD);

            if (pword != null && !pword.equals("")) {
                IPasswordCheck passwdCheck = CMS.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    throw new EUsrGrpException(passwdCheck.getReason(pword));

                    //UsrGrpResources.BAD_PASSWD);
                }

                user.setPassword(pword);
            } else {
                user.setPassword("");
            }
            String phone = super.getParameter(req, Constants.PR_USER_PHONE);

            if (phone != null) {
                user.setPhone(phone);
            } else {
                user.setPhone("");
            }
            String userType = super.getParameter(req, Constants.PR_USER_TYPE);

            if (userType != null) {
                user.setUserType(userType);
            } else {
                user.setUserType("");
            }
            String userState = super.getParameter(req, Constants.PR_USER_STATE);

            if (userState != null) {
                user.setState(userState);
            }

            try {
                mMgr.addUser(user);

                // if group is specified, add user to group
                String groupName = super.getParameter(req,
                        Constants.PR_USER_GROUP);

                if (groupName != null) {
                    Enumeration<IGroup> e = null;

                    try {
                        e = mMgr.findGroups(groupName);
                    } catch (Exception ex) {
                        ex.printStackTrace();

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                        return;
                    }

                    if (e.hasMoreElements()) {
                        IGroup group = e.nextElement();

                        group.addMemberName(id);
                        try {
                            mMgr.modifyGroup(group);
                        } catch (Exception ex) {
                            log(ILogger.LL_FAILURE, ex.toString());

                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditParams(req));

                            audit(auditMessage);

                            sendResponse(ERROR,
                                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                            return;
                        }
                    }
                    // for audit log
                    SessionContext sContext = SessionContext.getContext();
                    String adminId = (String) sContext.get(SessionContext.USER_ID);

                    mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                            AuditFormat.LEVEL, AuditFormat.ADDUSERGROUPFORMAT,
                            new Object[] { adminId, id, groupName }
                            );
                }

                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (EUsrGrpException e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                if (user.getUserID() == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED_1", "uid"), null, resp);
                } else {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                }
                return;

            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * Adds a certificate to a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void addUserCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            IUser user = mMgr.createUser(id);
            String certS = super.getParameter(req, Constants.PR_USER_CERT);
            String certsString = Cert.stripBrackets(certS);

            // no cert is a success
            if (certsString == null) {
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            }

            // only one cert added per operation
            X509Certificate certs[] = null;

            // Base64 decode cert

            try {
                byte bCert[] = Utils.base64decode(certsString);
                X509Certificate cert = new X509CertImpl(bCert);

                certs = new X509Certificate[1];
                certs[0] = cert;
            } catch (CertificateException e) {
                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));
                byte p7Cert[] = Utils.base64decode(certsString);

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(p7Cert);

                    X509Certificate p7certs[] = pkcs7.getCertificates();

                    if (p7certs.length == 0) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_ERROR"), null, resp);
                        return;
                    }
                    // fix for 370099 - cert ordering can not be assumed
                    // find out the ordering ...
                    certs = new X509Certificate[p7Cert.length];

                    // self-signed and alone? take it. otherwise test
                    // the ordering
                    if (p7certs[0].getSubjectDN().toString().equals(
                            p7certs[0].getIssuerDN().toString()) &&
                            (p7certs.length == 1)) {
                        certs[0] = p7certs[0];
                        CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));
                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        certs[0] = p7certs[0];
                        CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));
                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        certs[0] = p7certs[p7certs.length - 1];
                    } else {
                        // not a chain, or in random order
                        CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_ERROR"), null, resp);
                        return;
                    }

                    CMS.debug("UsrGrpAdminServlet: "
                            + CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending == true) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }
                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        CMS.debug("UsrGrpAdminServlet: "
                                + CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                null;

                        leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof InternalCertificate) {
                            ((InternalCertificate) leafCert).setSSLTrust(
                                    InternalCertificate.VALID_CA |
                                            InternalCertificate.TRUSTED_CA |
                                            InternalCertificate.TRUSTED_CLIENT_CA);
                        } else {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }

                    /*
                     } catch (CryptoManager.UserCertConflictException ex) {
                     // got a "user cert" in the chain, most likely the CA
                    // cert of this instance, which has a private key.  Ignore
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_PKS7_IGNORED", ex.toString()));
                    */
                } catch (Exception ex) {
                    //-----
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", ex.toString()));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_ERROR"), null, resp);
                    return;
                }
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_O_ERROR", e.toString()));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_O_ERROR"), null, resp);
                return;
            }

            try {
                CMS.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                certs[0].checkValidity(); // throw exception if fails

                user.setX509Certificates(certs);
                mMgr.addUserCert(user);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;

            } catch (CertificateExpiredException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(certs[0].getSubjectDN())));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_EXPIRED"), null, resp);
                return;
            } catch (CertificateNotYetValidException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(certs[0].getSubjectDN())));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_NOT_YET_VALID"), null, resp);
                return;

            } catch (ConflictingOperationException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_CERT_EXISTS"), null, resp);
                return;

            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
                return;
            }
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * Removes a certificate for a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * In this method, "certDN" is actually a combination of version, serialNumber, issuerDN, and SubjectDN.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void modifyUserCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            IUser user = mMgr.createUser(id);
            String certDN = super.getParameter(req, Constants.PR_USER_CERT);

            // no certDN is a success
            if (certDN == null) {
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            }

            user.setCertDN(certDN);
            try {
                mMgr.removeUserCert(user);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
                return;
            }
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * removes a user. user not removed if belongs to any group
     * (Administrators should remove the user from "uniquemember" of
     * any group he/she belongs to before trying to remove the user
     * itself.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void removeUser(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);
            boolean mustDelete = false;
            int index = 0;

            if ((index = id.lastIndexOf(":true")) != -1) {
                id = id.substring(0, index);
                mustDelete = true;
            }

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }
            // get list of groups, and see if uid belongs to any
            Enumeration<IGroup> e = null;

            try {
                e = mMgr.findGroups("*");
            } catch (Exception ex) {
                ex.printStackTrace();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
                return;
            }

            while (e.hasMoreElements()) {
                IGroup group = e.nextElement();

                if (group.isMember(id) == true) {
                    if (mustDelete) {
                        mMgr.removeUserFromGroup(group, id);
                    } else {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req));

                        audit(auditMessage);

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_FAIL_USER_RMV_G"),
                                null, resp);
                        return;
                    }
                }
            }

            // comes out clean of group membership...now remove user
            try {
                mMgr.removeUser(id);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (Exception ex) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_FAIL_USER_RMV"), null, resp);
                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * Adds a new group in local scope.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void addGroup(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            IGroup group = mMgr.createGroup(id);
            String members = super.getParameter(req,
                    Constants.PR_GROUP_USER);
            String desc = super.getParameter(req,
                    Constants.PR_GROUP_DESC);

            if (desc != null) {
                group.set("description", desc);
            } else {
                group.set("description", "");
            }

            if (members != null) {
                StringTokenizer st = new StringTokenizer(members, ",");

                while (st.hasMoreTokens()) {
                    group.addMemberName(st.nextToken());
                }
            }

            // allow adding a group with no members
            try {
                mMgr.addGroup(group);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_GROUP_ADD_FAILED"),
                        null, resp);
                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * removes a group
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void removeGroup(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // if fails, let the exception fall through
            mMgr.removeGroup(id);
            NameValuePairs params = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * modifies a group
     * <P>
     *
     * last person of the super power group "Certificate Server Administrators" can never be removed.
     * <P>
     *
     * http://warp.mcom.com/server/certificate/columbo/design/ ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void modifyGroup(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            IGroup group = mMgr.createGroup(id);

            String desc = super.getParameter(req,
                    Constants.PR_GROUP_DESC);

            if (desc != null) {
                group.set("description", desc);
            }

            String members = super.getParameter(req, Constants.PR_GROUP_USER);

            if (members != null) {
                StringTokenizer st = new StringTokenizer(members, ",");

                String groupName = group.getName();
                boolean multiRole = true;

                try {
                    multiRole = mConfig.getBoolean(MULTI_ROLE_ENABLE);
                } catch (Exception eee) {
                }
                while (st.hasMoreTokens()) {
                    String memberName = st.nextToken();
                    if (multiRole) {
                        group.addMemberName(memberName);
                    } else {
                        if (isGroupInMultiRoleEnforceList(groupName)) {
                            if (!isDuplicate(groupName, memberName)) {
                                group.addMemberName(memberName);
                            } else {
                                // store a message in the signed audit log file
                                auditMessage = CMS.getLogMessage(
                                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                            auditSubjectID,
                                            ILogger.FAILURE,
                                            auditParams(req));

                                audit(auditMessage);

                                throw new EBaseException(CMS.getUserMessage("CMS_BASE_DUPLICATE_ROLES", memberName));
                            }
                        } else {
                            group.addMemberName(memberName);
                        }
                    }
                }
            }

            // allow adding a group with no members, except "Certificate
            // Server Administrators"
            try {
                mMgr.modifyGroup(group);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_GROUP_MODIFY_FAILED"),
                        null, resp);
                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private boolean isGroupInMultiRoleEnforceList(String groupName) {
        String groupList = null;

        if (groupName == null || groupName.equals("")) {
            return true;
        }
        if (mMultiRoleGroupEnforceList == null) {
            try {
                groupList = mConfig.getString(MULTI_ROLE_ENFORCE_GROUP_LIST);
            } catch (Exception e) {
            }

            if (groupList != null && !groupList.equals("")) {
                mMultiRoleGroupEnforceList = groupList.split(",");
                for (int j = 0; j < mMultiRoleGroupEnforceList.length; j++) {
                    mMultiRoleGroupEnforceList[j] = mMultiRoleGroupEnforceList[j].trim();
                }
            }
        }

        if (mMultiRoleGroupEnforceList == null)
            return true;

        for (int i = 0; i < mMultiRoleGroupEnforceList.length; i++) {
            if (groupName.equals(mMultiRoleGroupEnforceList[i])) {
                return true;
            }
        }
        return false;
    }

    private boolean isDuplicate(String groupName, String memberName) {
        Enumeration<IGroup> groups = null;

        // Let's not mess with users that are already a member of this group
        boolean isMember = false;
        try {
            isMember = mMgr.isMemberOf(memberName, groupName);
        } catch (Exception e) {
        }

        if (isMember == true) {
            return false;
        }
        try {
            groups = mMgr.listGroups("*");
            while (groups.hasMoreElements()) {
                IGroup group = groups.nextElement();
                String name = group.getName();
                Enumeration<IGroup> g = mMgr.findGroups(name);
                IGroup g1 = g.nextElement();
                if (!name.equals(groupName)) {
                    if (isGroupInMultiRoleEnforceList(name)) {
                        Enumeration<String> members = g1.getMemberNames();
                        while (members.hasMoreElements()) {
                            String m1 = members.nextElement();
                            if (m1.equals(memberName))
                                return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
        }

        return false;
    }

    /**
     * Modifies an existing user in local scope.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void modifyUser(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            IUser user = mMgr.createUser(id);
            String fname = super.getParameter(req, Constants.PR_USER_FULLNAME);

            if ((fname == null) || (fname.length() == 0)) {
                String msg =
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED", "full name");

                log(ILogger.LL_FAILURE, msg);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, msg, null, resp);
                return;
            } else
                user.setFullName(fname);

            String email = super.getParameter(req, Constants.PR_USER_EMAIL);

            if (email != null) {
                user.setEmail(email);
            }
            String pword = super.getParameter(req, Constants.PR_USER_PASSWORD);

            if ((pword != null) && (!pword.equals(""))) {
                IPasswordCheck passwdCheck = CMS.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    throw new EUsrGrpException(passwdCheck.getReason(pword));

                    //UsrGrpResources.BAD_PASSWD);
                }

                user.setPassword(pword);
            }
            String phone = super.getParameter(req, Constants.PR_USER_PHONE);

            if (phone != null) {
                user.setPhone(phone);
            }

            String userState = super.getParameter(req, Constants.PR_USER_STATE);
            if (userState != null) {
                user.setState(userState);
            }

            try {
                mMgr.modifyUser(user);
                NameValuePairs params = new NameValuePairs();

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(SUCCESS, null, params, resp);
                return;
            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_USRGRP,
                level, "UsrGrpAdminServlet: " + msg);
    }
}
