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

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.password.PasswordChecker;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

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

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UsrGrpAdminServlet.class);

    private static final long serialVersionUID = -4341817607402387714L;
    private static final String INFO = "UsrGrpAdminServlet";
    private static final String SYSTEM_USER = "$System$";

    private static final String BACK_SLASH = "\\";

    private UGSubsystem mMgr = null;

    private static String[] mMultiRoleGroupEnforceList = null;
    private static final String MULTI_ROLE_ENABLE = "multiroles.enable";
    private static final String MULTI_ROLE_ENFORCE_GROUP_LIST = "multiroles.false.groupEnforceList";

    /**
     * Initializes this servlet.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        CMSEngine engine = getCMSEngine();
        mAuthz = engine.getAuthzSubsystem();
        mMgr = engine.getUGSubsystem();
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves incoming User/Group management request.
     */
    @Override
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        String scope = super.getParameter(req, Constants.OP_SCOPE);
        String op = super.getParameter(req, Constants.OP_TYPE);

        if (op == null) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_INVALID_PROTOCOL"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        Locale clientLocale = super.getLocale(req);

        try {
            super.authenticate(req);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_FAIL_AUTHS"));

            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        String subsystemPath = getServletContext().getContextPath();
        String subsystemID = subsystemPath.substring(1);
        AUTHZ_RES_NAME = "certServer." + subsystemID + ".group";

        try {
            if (scope == null)
                return;
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
                } else if (scope.equals(ScopeDef.SC_USERS)) {
                    findUser(req, resp);
                } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                    findUserCerts(req, resp, clientLocale);
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
                } else if (scope.equals(ScopeDef.SC_USERS)) {
                    modifyUser(req, resp);
                } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                    modifyUserCert(req, resp);
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
                } else if (scope.equals(ScopeDef.SC_USERS)) {
                    addUser(req, resp);
                } else if (scope.equals(ScopeDef.SC_USER_CERTS)) {
                    addUserCert(req, resp);
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
                } else if (scope.equals(ScopeDef.SC_USERS)) {
                    removeUser(req, resp);
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
                } else if (scope.equals(ScopeDef.SC_USERS)) {
                    findUsers(req, resp);
                } else {
                    logger.error(CMS.getLogMessage("ADMIN_SRVLT_INVALID_OP_SCOPE"));
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                }
            }
        } catch (EBaseException e) {
            logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);
            sendResponse(ERROR, e.toString(getLocale(req)),
                    null, resp);
        } catch (Exception e) {
            logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);
            logger.error(CMS.getLogMessage(" ADMIN_SRVLT_FAIL_PERFORM"));
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                    null, resp);
        }
    }

    private void getUserType(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        String id = super.getParameter(req, Constants.RS_ID);
        User user = mMgr.getUser(id);
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
    private synchronized void findUsers(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        NameValuePairs params = new NameValuePairs();

        Enumeration<User> e = null;

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
            User user = e.nextElement();

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
    private synchronized void findUser(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        NameValuePairs params = new NameValuePairs();

        User user = null;

        try {
            user = mMgr.getUser(id);
        } catch (Exception e) {
            logger.error(e.getMessage());
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
            Enumeration<Group> e = null;

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
                Group group = e.nextElement();

                if (group.isMember(id)) {
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

        logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
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
            throws Exception {

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        NameValuePairs params = new NameValuePairs();

        User user = null;

        try {
            user = mMgr.getUser(id);
        } catch (Exception e) {
            logger.error(e.getMessage());
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
            return;
        }

        if (user == null) {
            logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_NOT_EXIST"), null, resp);
            return;
        }

        X509Certificate[] certs =
                user.getX509Certificates();

        if (certs != null) {
            for (int i = 0; i < certs.length; i++) {
                CertPrettyPrint print = new CertPrettyPrint(certs[i]);

                // add base64 encoding
                String base64 = CertUtil.toPEM(certs[i]);

                // pretty print certs
                params.put(getCertificateString(certs[i]),
                        print.toString(clientLocale) + "\n" + base64);
            }
            sendResponse(SUCCESS, null, params, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
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
    private synchronized void findGroups(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        NameValuePairs params = new NameValuePairs();

        Enumeration<Group> e = null;

        try {
            e = mMgr.listGroups(null);
        } catch (Exception ex) {
            ex.printStackTrace();
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        while (e.hasMoreElements()) {
            Group group = e.nextElement();
            String desc = group.getDescription();

            if (desc == null) {
                params.put(group.getGroupID(), "");
            } else {
                params.put(group.getGroupID(), desc);
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
    private synchronized void findGroup(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        NameValuePairs params = new NameValuePairs();

        //get id first
        String id = super.getParameter(req, Constants.RS_ID);

        if (id == null) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        Enumeration<Group> e = null;

        try {
            e = mMgr.findGroups(id);
        } catch (Exception ex) {
            ex.printStackTrace();
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
            return;
        }

        if (e.hasMoreElements()) {
            Group group = e.nextElement();

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
        } else {
            logger.error(CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));

            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"), null, resp);

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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            if (id.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_RS_ID_BS"),
                        null, resp);
                return;
            }

            if (id.equals(SYSTEM_USER)) {
                // backslashes (BS) are not allowed
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", id));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_SPECIAL_ID", id),
                        null, resp);
                return;
            }

            User user = mMgr.createUser(id);
            String fname = super.getParameter(req, Constants.PR_USER_FULLNAME);

            if ((fname == null) || (fname.length() == 0)) {
                String msg = CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED_1", "full name");

                logger.error(msg);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR, msg, null, resp);
                return;
            }
            user.setFullName(fname);

            String email = super.getParameter(req, Constants.PR_USER_EMAIL);

            if (email == null) {
                user.setEmail("");
            } else {
                user.setEmail(email);
            }
            String pword = super.getParameter(req, Constants.PR_USER_PASSWORD);

            if (pword == null || pword.equals("")) {
                user.setPassword("");
            } else {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {

                    auditor.log(new ConfigRoleEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req)));

                    throw new EUsrGrpException(passwdCheck.getReason(pword));
                }

                user.setPassword(pword);
            }
            String phone = super.getParameter(req, Constants.PR_USER_PHONE);

            if (phone == null) {
                user.setPhone("");
            } else {
                user.setPhone(phone);
            }
            String userType = super.getParameter(req, Constants.PR_USER_TYPE);

            if (userType == null) {
                user.setUserType("");
            } else {
                user.setUserType(userType);
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
                    Enumeration<Group> e = null;

                    try {
                        e = mMgr.findGroups(groupName);
                    } catch (Exception ex) {
                        ex.printStackTrace();

                        auditor.log(new ConfigRoleEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req)));

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                        return;
                    }

                    if (e.hasMoreElements()) {
                        Group group = e.nextElement();

                        group.addMemberName(id);
                        try {
                            mMgr.modifyGroup(group);
                        } catch (Exception ex) {
                            logger.error("UsrGrpAdminServlet: " + ex.getMessage(), e);

                            auditor.log(new ConfigRoleEvent(
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditParams(req)));

                            sendResponse(ERROR,
                                    CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                            return;
                        }
                    }
                    // for audit log
                    SessionContext sContext = SessionContext.getContext();
                    String adminId = (String) sContext.get(SessionContext.USER_ID);

                    logger.info(
                            AuditFormat.ADDUSERGROUPFORMAT,
                            adminId,
                            id,
                            groupName
                    );
                }

                NameValuePairs params = new NameValuePairs();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (EUsrGrpException e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                if (user.getUserID() == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED_1", "uid"), null, resp);
                } else {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
                }

            } catch (Exception e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_ADD_FAILED"), null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            User user = mMgr.createUser(id);
            String certS = super.getParameter(req, Constants.PR_USER_CERT);
            String certsString = Cert.stripBrackets(certS);

            // no cert is a success
            if (certsString == null) {
                NameValuePairs params = new NameValuePairs();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
                return;
            }

            // only one cert added per operation
            X509Certificate[] certs = null;

            // Base64 decode cert

            try {
                byte[] bCert = Utils.base64decode(certsString);
                X509Certificate cert = new X509CertImpl(bCert);

                certs = new X509Certificate[1];
                certs[0] = cert;
            } catch (CertificateException e) {
                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));
                byte[] p7Cert = Utils.base64decode(certsString);

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(p7Cert);

                    X509Certificate[] p7certs = pkcs7.getCertificates();

                    if (p7certs.length == 0) {

                        auditor.log(new ConfigRoleEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req)));

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
                        logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));
                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        certs[0] = p7certs[0];
                        logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));
                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        certs[0] = p7certs[p7certs.length - 1];
                    } else {
                        // not a chain, or in random order
                        logger.error("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));

                        auditor.log(new ConfigRoleEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req)));

                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_ERROR"), null, resp);
                        return;
                    }

                    logger.debug("UsrGrpAdminServlet: "
                            + CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }
                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        logger.debug("UsrGrpAdminServlet: "
                                + CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                null;

                        leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof InternalCertificate ic) {
                            ic.setSSLTrust(
                                    PK11Cert.VALID_CA |
                                    PK11Cert.TRUSTED_CA |
                                    PK11Cert.TRUSTED_CLIENT_CA);
                        } else {
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }
                } catch (Exception ex) {
                    //-----
                    logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", ex.toString()), ex);

                    auditor.log(new ConfigRoleEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req)));

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_ERROR"), null, resp);
                    return;
                }
            } catch (Exception e) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_O_ERROR", e.toString()), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_O_ERROR"), null, resp);
                return;
            }

            try {
                logger.debug("UsrGrpAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                certs[0].checkValidity(); // throw exception if fails

                user.setX509Certificates(certs);
                mMgr.addUserCert(id, certs[0]);
                NameValuePairs params = new NameValuePairs();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);

            } catch (CertificateExpiredException e) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(certs[0].getSubjectDN())), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_EXPIRED"), null, resp);
            } catch (CertificateNotYetValidException e) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(certs[0].getSubjectDN())), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_CERT_NOT_YET_VALID"), null, resp);

            } catch (ConflictingOperationException e) {

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_USER_CERT_EXISTS"), null, resp);

            } catch (Exception e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
            }
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            String certDN = super.getParameter(req, Constants.PR_USER_CERT);

            // no certDN is a success
            if (certDN == null) {
                NameValuePairs params = new NameValuePairs();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
                return;
            }

            try {
                mMgr.removeUserCert(id, certDN);
                NameValuePairs params = new NameValuePairs();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
            }
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

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
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }
            // get list of groups, and see if uid belongs to any
            Enumeration<Group> e = null;

            try {
                e = mMgr.findGroups("*");
            } catch (Exception ex) {
                ex.printStackTrace();

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_INTERNAL_ERROR"), null, resp);
                return;
            }

            while (e.hasMoreElements()) {
                Group group = e.nextElement();

                if (group.isMember(id)) {
                    if (mustDelete) {
                        mMgr.removeUserFromGroup(group, id);
                    } else {
                        auditor.log(new ConfigRoleEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditParams(req)));

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

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception ex) {

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_SRVLT_FAIL_USER_RMV"), null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            Group group = mMgr.createGroup(id);

            // add description if specified
            String description = super.getParameter(req, Constants.PR_GROUP_DESC);
            if (description != null && !description.equals("")) {
                group.set(Group.ATTR_DESCRIPTION, description);
            }

            // add members if specified
            String members = super.getParameter(req, Constants.PR_GROUP_USER);
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

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception e) {

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_GROUP_ADD_FAILED"),
                        null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // if fails, let the exception fall through
            mMgr.removeGroup(id);
            NameValuePairs params = new NameValuePairs();

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req)));

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            Group group = mMgr.getGroupFromName(id);

            // update description if specified
            String description = super.getParameter(req, Constants.PR_GROUP_DESC);
            if (description != null) {
                if (description.equals("")) {
                    group.delete(Group.ATTR_DESCRIPTION);
                } else {
                    group.set(Group.ATTR_DESCRIPTION, description);
                }
            }

            // update members if specified
            String members = super.getParameter(req, Constants.PR_GROUP_USER);
            if (members != null) {
                // empty old member list
                group.delete(Group.ATTR_MEMBERS);

                // read new member list
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
                                auditor.log(new ConfigRoleEvent(
                                            auditSubjectID,
                                            ILogger.FAILURE,
                                            auditParams(req)));

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

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_GROUP_MODIFY_FAILED"),
                        null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
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

    /**
     * TODO: replace this with GroupMemberProcessor.isDuplicate()
     */
    private boolean isDuplicate(String groupName, String memberName) {
        Enumeration<Group> groups = null;

        // Let's not mess with users that are already a member of this group
        boolean isMember = false;
        try {
            isMember = mMgr.isMemberOf(memberName, groupName);
        } catch (Exception e) {
        }

        if (isMember) {
            return false;
        }
        try {
            groups = mMgr.listGroups(null);
            while (groups.hasMoreElements()) {
                Group group = groups.nextElement();
                String name = group.getName();
                Enumeration<Group> g = mMgr.findGroups(name);
                Group g1 = g.nextElement();
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

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            //get id first
            String id = super.getParameter(req, Constants.RS_ID);

            if (id == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            User user = mMgr.createUser(id);
            String fname = super.getParameter(req, Constants.PR_USER_FULLNAME);

            if ((fname == null) || (fname.length() == 0)) {
                String msg =
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED", "full name");

                logger.error(msg);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR, msg, null, resp);
                return;
            }
            user.setFullName(fname);

            String email = super.getParameter(req, Constants.PR_USER_EMAIL);

            if (email != null) {
                user.setEmail(email);
            }
            String pword = super.getParameter(req, Constants.PR_USER_PASSWORD);

            if ((pword != null) && (!pword.equals(""))) {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {

                    auditor.log(new ConfigRoleEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req)));

                    throw new EUsrGrpException(passwdCheck.getReason(pword));
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

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditParams(req)));

                sendResponse(SUCCESS, null, params, resp);
            } catch (Exception e) {
                logger.error("UsrGrpAdminServlet: " + e.getMessage(), e);

                auditor.log(new ConfigRoleEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_USRGRP_USER_MOD_FAILED"), null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigRoleEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit2;
        }
    }
}
