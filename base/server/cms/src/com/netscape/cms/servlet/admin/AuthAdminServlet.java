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
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthManagerProxy;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthMgrNotFound;
import com.netscape.certsrv.authentication.EAuthMgrPluginNotFound;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class representing an administration servlet for the
 * Authentication Management subsystem. This servlet is responsible
 * to serve configuration requests for the Auths Management subsystem.
 *
 *
 * @version $Revision$, $Date$
 */
public class AuthAdminServlet extends AdminServlet {

    /**
     *
     */
    private static final long serialVersionUID = -6258411211380144425L;
    private final static String INFO = "AuthAdminServlet";
    private IAuthSubsystem mAuths = null;

    private final static String PW_PASSWORD_CACHE_ADD =
            "PASSWORD_CACHE_ADD";
    private final static String EDIT = ";" + Constants.EDIT;

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_AUTH =
            "LOGGING_SIGNED_AUDIT_CONFIG_AUTH_3";

    public AuthAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mAuths = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
        AUTHZ_RES_NAME = "certServer.auth.configuration";
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * retrieve extended plugin info such as brief description, type info
     * from policy, authentication,
     * need to add: listener, mapper and publishing plugins
     * --- same as policy, should we move this into extendedpluginhelper?
     */
    private void getExtendedPluginInfo(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        int colon = id.indexOf(':');

        String implType = id.substring(0, colon);
        String implName = id.substring(colon + 1);

        NameValuePairs params =
                getExtendedPluginInfo(getLocale(req), implType, implName);

        sendResponse(SUCCESS, null, params, resp);
    }

    private NameValuePairs getExtendedPluginInfo(Locale locale, String implType, String implName) {
        IExtendedPluginInfo ext_info = null;
        Object impl = null;

        impl = mAuths.getAuthManagerPlugin(implName);
        if (impl != null) {
            if (impl instanceof IExtendedPluginInfo) {
                ext_info = (IExtendedPluginInfo) impl;
            }
        }

        NameValuePairs nvps = null;

        if (ext_info == null) {
            nvps = new NameValuePairs();
        } else {
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo(locale));
        }

        return nvps;

    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        if (op == null) {
            //System.out.println("SRVLT_INVALID_PROTOCOL");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        // if it is not authentication, that means it is for CSC admin ping.
        // the best way to do is to define another protocol for ping and move
        // it to the generic servlet which is admin servlet.
        if (!op.equals(OpDef.OP_AUTH)) {
            if (scope.equals(ScopeDef.SC_AUTH)) {
                String id = req.getParameter(Constants.RS_ID);

                // for CSC admin ping only
                if (op.equals(OpDef.OP_READ) &&
                        id.equals(Constants.RS_ID_CONFIG)) {

                    // no need to authenticate this. if we're alive, return true.
                    NameValuePairs params = new NameValuePairs();

                    params.put(Constants.PR_PING, Constants.TRUE);
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                } else {
                    //System.out.println("SRVLT_INVALID_OP_TYPE");
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_TYPE", op),
                            null, resp);
                    return;
                }
            }
        }

        try {
            if (op.equals(OpDef.OP_AUTH)) {
                if (scope.equals(ScopeDef.SC_AUTHTYPE)) {
                    IConfigStore configStore = CMS.getConfigStore();
                    String val = configStore.getString("authType", "pwd");
                    NameValuePairs params = new NameValuePairs();

                    params.put("authType", val);
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
            }
        } catch (Exception e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }
        // for the rest
        try {
            super.authenticate(req);
            if (op.equals(OpDef.OP_AUTH)) { // for admin authentication only
                sendResponse(SUCCESS, null, null, resp);
                return;
            }
        } catch (IOException e) {
            //System.out.println("SRVLT_FAIL_AUTHS");
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        try {
            // perform operation based on scope
            if (scope != null) {
                AUTHZ_RES_NAME = "certServer.auth.configuration";
                if (scope.equals(ScopeDef.SC_EXTENDED_PLUGIN_INFO)) {
                    try {
                        mOp = "read";
                        if ((mToken = super.authorize(req)) == null) {
                            sendResponse(ERROR,
                                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                    null, resp);
                            return;
                        }
                        getExtendedPluginInfo(req, resp);
                        return;
                    } catch (EBaseException e) {
                        sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                        return;
                    }
                }
                if (op.equals(OpDef.OP_SEARCH)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_AUTH_IMPLS)) {
                        listAuthMgrPlugins(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_AUTH_MGR_INSTANCE)) {
                        listAuthMgrInsts(req, resp);
                        return;
                    } else {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                                null, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_READ)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_AUTH_IMPLS)) {
                        getConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_AUTH_MGR_INSTANCE)) {
                        getInstConfig(req, resp);
                        return;
                    } else {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                                null, resp);
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
                    if (scope.equals(ScopeDef.SC_AUTH_IMPLS)) {
                        addAuthMgrPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_AUTH_MGR_INSTANCE)) {
                        addAuthMgrInst(req, resp, scope);
                        return;
                    } else {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                                null, resp);
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
                    if (scope.equals(ScopeDef.SC_AUTH_IMPLS)) {
                        delAuthMgrPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_AUTH_MGR_INSTANCE)) {
                        delAuthMgrInst(req, resp, scope);
                        return;
                    } else {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                                null, resp);
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
                    if (scope.equals(ScopeDef.SC_AUTH_MGR_INSTANCE)) {
                        modAuthMgrInst(req, resp, scope);
                        return;
                    }
                } else {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                            null, resp);
                    return;
                }
            }
        } catch (EBaseException e) {
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        }
        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                null, resp);
        return;
    }

    private void putUserPWPair(String combo) {
        int semicolon;

        semicolon = combo.indexOf(";");
        String user = combo.substring(0, semicolon);
        String pw = combo.substring(semicolon + 1);

        CMS.putPasswordCache(user, pw);
    }

    /**
     * Add authentication manager plug-in
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_AUTH used when configuring authentication
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this authentication
     *            manager's substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */

    private synchronized void addAuthMgrPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_NULL_RS_ID");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }
            // is the manager id unique?
            if (mAuths.getPlugins().containsKey(id)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_DUP_MGR_PLUGIN_ID",
                                id)).toString(),
                        null, resp);
                return;
            }

            String classPath = req.getParameter(Constants.PR_AUTH_CLASS);

            if (classPath == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_NULL_AUTHMGR_CLASSNAME"),
                        null, resp);
                return;
            }

            if (classPath.equals("com.netscape.cmscore.authentication.PasswdUserDBAuthentication") ||
                    classPath.equals("com.netscape.cmscore.authentication.CertUserDBAuthentication")) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_BASE_PERMISSION_DENIED"), null, resp);
                return;
            }

            IConfigStore destStore =
                    mConfig.getSubStore(DestDef.DEST_AUTH_ADMIN);
            IConfigStore instancesConfig =
                    destStore.getSubStore(scope);

            // Does the class exist?

            Class<IAuthManager> newImpl = null;

            try {
                @SuppressWarnings("unchecked")
                Class<IAuthManager> tmpImpl = (Class<IAuthManager>) Class.forName(classPath);
                newImpl = tmpImpl;
            } catch (ClassNotFoundException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_AUTHMGR_PLUGIN_NOT_FOUND"),
                        null, resp);
                return;
            } catch (IllegalArgumentException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_AUTHMGR_PLUGIN_NOT_FOUND"),
                        null, resp);
                return;
            }

            // is the class an IAuthManager?
            try {
                if (IAuthManager.class.isAssignableFrom(newImpl) == false) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_ILL_CLASS"),
                            null, resp);
                    return;
                }
            } catch (NullPointerException e) { // unlikely, only if newImpl null.
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_ILL_CLASS"),
                        null, resp);
                return;
            }

            IConfigStore substore = instancesConfig.makeSubStore(id);

            substore.put(Constants.PR_AUTH_CLASS, classPath);

            // commiting
            try {
                mConfig.commit(true);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_FAIL_COMMIT");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                        null, resp);
                return;
            }

            // add manager to registry.
            AuthMgrPlugin plugin = new AuthMgrPlugin(id, classPath);

            mAuths.getPlugins().put(id, plugin);
            mAuths.log(ILogger.LL_INFO,
                    CMS.getLogMessage("ADMIN_SRVLT_PLUGIN_ADD", id));

            NameValuePairs params = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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
     * Add authentication manager instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_AUTH used when configuring authentication
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this authentication
     *            manager's substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void addAuthMgrInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // is the manager instance id unique?
            if (mAuths.getInstances().containsKey(id)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_ILL_MGR_INST_ID"),
                        null, resp);
                return;
            }

            // get required parameters
            // SC_AUTH_IMPL_NAME is absolutely required, the rest depend on
            // on each authenticaton manager
            String implname = req.getParameter(Constants.PR_AUTH_IMPL_NAME);

            if (implname == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_MISSING_PARAMS"),
                        null, resp);
                return;
            }

            // prevent agent & admin creation.
            if (implname.equals(IAuthSubsystem.PASSWDUSERDB_PLUGIN_ID) ||
                    implname.equals(IAuthSubsystem.CERTUSERDB_PLUGIN_ID)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_BASE_PERMISSION_DENIED"), null, resp);
            }

            // check if implementation exists.
            AuthMgrPlugin plugin =
                    mAuths.getPlugins().get(implname);

            if (plugin == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(
                        ERROR,
                        new EAuthMgrPluginNotFound(CMS.getUserMessage(getLocale(req),
                                "CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implname)).toString(),
                        null, resp);
                return;
            }

            // now the rest of config parameters
            // note that we only check to see if the required parameters
            // are there, but not checking the values are valid
            String[] configParams = mAuths.getConfigParams(implname);

            IConfigStore destStore =
                    mConfig.getSubStore(DestDef.DEST_AUTH_ADMIN);
            IConfigStore instancesConfig =
                    destStore.getSubStore(scope);
            IConfigStore substore = instancesConfig.makeSubStore(id);

            if (configParams != null) {
                for (int i = 0; i < configParams.length; i++) {
                    String key = configParams[i];
                    String val = req.getParameter(key);

                    if (val != null) {
                        substore.put(key, val);
                    }
                }
            }
            substore.put(IAuthSubsystem.PROP_PLUGIN, implname);

            String pwadd = req.getParameter(PW_PASSWORD_CACHE_ADD);

            if (pwadd != null) {
                putUserPWPair(pwadd);
            }

            // Instantiate an object for this implementation
            String className = plugin.getClassPath();
            IAuthManager authMgrInst = null;

            try {
                authMgrInst = (IAuthManager) Class.forName(className).newInstance();
            } catch (ClassNotFoundException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // cleanup
                instancesConfig.removeSubStore(id);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            } catch (InstantiationException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                instancesConfig.removeSubStore(id);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            } catch (IllegalAccessException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                instancesConfig.removeSubStore(id);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            }

            // initialize the authentication manager
            try {
                authMgrInst.init(id, implname, substore);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // don't commit in this case and cleanup the new substore.
                instancesConfig.removeSubStore(id);
                sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                return;
            }

            // commiting
            try {
                mConfig.commit(true);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // clean up.
                instancesConfig.removeSubStore(id);
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                        null, resp);
                return;
            }

            // inited and commited ok. now add manager instance to list.
            mAuths.add(id, authMgrInst);

            mAuths.log(ILogger.LL_INFO,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_MGR_ADD", id));

            NameValuePairs params = new NameValuePairs();

            params.put(Constants.PR_AUTH_IMPL_NAME, implname);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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

    private synchronized void listAuthMgrPlugins(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mAuths.getPlugins().keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            AuthMgrPlugin value = mAuths.getPlugins().get(name);

            if (value.isVisible()) {
                params.put(name, value.getClassPath() + EDIT);
            }
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listAuthMgrInsts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        for (Enumeration<?> e = mAuths.getInstances().keys(); e.hasMoreElements();) {
            String name = (String) e.nextElement();
            AuthManagerProxy proxy = (AuthManagerProxy) mAuths.getInstances().get(name);
            IAuthManager value = proxy.getAuthManager();
            String enableStr = "enabled";

            if (!proxy.isEnable()) {
                enableStr = "disabled";
            }

            AuthMgrPlugin amgrplugin = mAuths.getPlugins().get(value.getImplName());

            if (!amgrplugin.isVisible()) {
                params.put(name, value.getImplName() + ";invisible;" + enableStr);
            } else {
                params.put(name, value.getImplName() + ";visible;" + enableStr);
            }
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * Delete authentication manager plug-in
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_AUTH used when configuring authentication
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this authentication
     *            manager's substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void delAuthMgrPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_NULL_RS_ID");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // prevent deletion of admin and agent.
            if (id.equals(IAuthSubsystem.PASSWDUSERDB_PLUGIN_ID) ||
                    id.equals(IAuthSubsystem.CERTUSERDB_PLUGIN_ID)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_BASE_PERMISSION_DENIED"), null, resp);
            }

            // does auth manager exist?
            if (mAuths.getPlugins().containsKey(id) == false) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(
                        ERROR,
                        new EAuthMgrPluginNotFound(CMS.getUserMessage(getLocale(req),
                                "CMS_AUTHENTICATION_DUP_MGR_PLUGIN_ID", id)).toString(),
                        null, resp);
                return;
            }

            // first check if any instances from this auth manager
            // DON'T remove auth manager if any instance
            for (Enumeration<?> e = mAuths.getInstances().keys(); e.hasMoreElements();) {
                IAuthManager authMgr = mAuths.get((String) e.nextElement());

                if (authMgr.getImplName() == id) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_MGR_IN_USE"),
                            null, resp);
                    return;
                }
            }

            // then delete this auth manager
            mAuths.getPlugins().remove(id);

            IConfigStore destStore =
                    mConfig.getSubStore(DestDef.DEST_AUTH_ADMIN);
            IConfigStore instancesConfig =
                    destStore.getSubStore(scope);

            instancesConfig.removeSubStore(id);
            // commiting
            try {
                mConfig.commit(true);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                        null, resp);
                return;
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit1;
        }
    }

    /**
     * Delete authentication manager instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_AUTH used when configuring authentication
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this authentication
     *            manager's substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void delAuthMgrInst(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_NULL_RS_ID");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // prevent deletion of admin and agent.
            if (id.equals(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID) ||
                    id.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_BASE_PERMISSION_DENIED"), null, resp);
            }

            // does auth manager instance exist?
            if (mAuths.getInstances().containsKey(id) == false) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(
                        ERROR,
                        new EAuthMgrNotFound(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND",
                                id)).toString(),
                        null, resp);
                return;
            }

            // only remove from memory
            // cannot shutdown because we don't keep track of whether it's
            // being used.
            mAuths.getInstances().remove(id);

            // remove the configuration.
            IConfigStore destStore =
                    mConfig.getSubStore(DestDef.DEST_AUTH_ADMIN);
            IConfigStore instancesConfig =
                    destStore.getSubStore(scope);

            instancesConfig.removeSubStore(id);
            // commiting
            try {
                mConfig.commit(true);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_FAIL_COMMIT");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                        null, resp);
                return;
            }

            //This only works in the fact that we only support one instance per
            //auth plugin.
            ILdapAuthInfo authInfo = CMS.getLdapAuthInfo();

            authInfo.removePassword("Rule " + id);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
            // } catch( EBaseException eAudit1 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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
     * used for getting the required configuration parameters (with
     * possible default values) for a particular auth manager plugin
     * implementation name specified in the RS_ID. Actually, there is
     * no logic in here to set any default value here...there's no
     * default value for any parameter in this authentication subsystem
     * at this point. Later, if we do have one (or some), it can be
     * added. The interface remains the same.
     */
    private synchronized void getConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        String implname = req.getParameter(Constants.RS_ID);

        if (implname == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        String[] configParams = mAuths.getConfigParams(implname);
        NameValuePairs params = new NameValuePairs();

        // implName is always required so always send it.
        params.put(Constants.PR_AUTH_IMPL_NAME, "");
        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                params.put(configParams[i], "");
            }
        }
        sendResponse(0, null, params, resp);
        return;
    }

    private synchronized void getInstConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does auth manager instance exist?
        if (mAuths.getInstances().containsKey(id) == false) {
            sendResponse(
                    ERROR,
                    new EAuthMgrNotFound(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", id))
                            .toString(),
                    null, resp);
            return;
        }

        IAuthManager mgrInst = mAuths.get(id);
        IConfigStore config = mgrInst.getConfigStore();
        String[] configParams = mgrInst.getConfigParams();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_AUTH_IMPL_NAME, mgrInst.getImplName());
        // implName is always required so always send it.
        if (configParams != null) {
            for (int i = 0; i < configParams.length; i++) {
                String key = configParams[i];
                String val = config.get(key);

                if (val != null) {
                    params.put(key, val);
                } else {
                    params.put(key, "");
                }
            }
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * Modify authentication manager instance
     * This will actually create a new instance with new configuration
     * parameters and replace the old instance if the new instance is
     * created and initialized successfully.
     * The old instance is left running, so this is very expensive.
     * Restart of server recommended.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_AUTH used when configuring authentication
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param scope string used to obtain the contents of this authentication
     *            manager's substore
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private synchronized void modAuthMgrInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        // expensive operation.

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            if (id == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                //System.out.println("SRVLT_NULL_RS_ID");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                        null, resp);
                return;
            }

            // prevent modification of admin and agent.
            if (id.equals(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID) ||
                    id.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_BASE_PERMISSION_DENIED"), null, resp);
            }

            // Does the manager instance exist?
            if (!mAuths.getInstances().containsKey(id)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage("CMS_AUTHENTICATION_MGR_IMPL_NOT_FOUND"),
                        null, resp);
                return;
            }

            // get new implementation (same or different.)
            String implname = req.getParameter(Constants.PR_AUTH_IMPL_NAME);

            if (implname == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR,
                        CMS.getUserMessage("CMS_AUTHENTICATION_MISSING_PARAMS"),
                        null, resp);
                return;
            }

            // get plugin for implementation
            AuthMgrPlugin plugin = mAuths.getPlugins().get(implname);

            if (plugin == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(
                        ERROR,
                        new EAuthMgrPluginNotFound(CMS.getUserMessage(getLocale(req),
                                "CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implname)).toString(),
                        null, resp);
                return;
            }

            // save old instance substore params in case new one fails.

            IAuthManager oldinst = mAuths.get(id);
            IConfigStore oldConfig = oldinst.getConfigStore();

            String[] oldConfigParms = oldinst.getConfigParams();
            NameValuePairs saveParams = new NameValuePairs();

            // implName is always required so always include it it.
            saveParams.put(IAuthSubsystem.PROP_PLUGIN,
                    oldConfig.get(IAuthSubsystem.PROP_PLUGIN));
            if (oldConfigParms != null) {
                for (int i = 0; i < oldConfigParms.length; i++) {
                    String key = oldConfigParms[i];
                    Object val = oldConfig.get(key);

                    if (val != null) {
                        saveParams.put(key, (String) val);
                    }
                }
            }

            // on to the new instance.

            // remove old substore.

            IConfigStore destStore =
                    mConfig.getSubStore(DestDef.DEST_AUTH_ADMIN);
            IConfigStore instancesConfig =
                    destStore.getSubStore(scope);

            instancesConfig.removeSubStore(id);

            // create new substore.

            String[] configParams = mAuths.getConfigParams(implname);

            IConfigStore substore = instancesConfig.makeSubStore(id);

            substore.put(IAuthSubsystem.PROP_PLUGIN, implname);
            if (configParams != null) {
                for (int i = 0; i < configParams.length; i++) {
                    String key = configParams[i];
                    String val = req.getParameter(key);

                    if (val != null) {
                        substore.put(key, val);
                    }
                }
            }

            // Instantiate an object for new implementation

            String className = plugin.getClassPath();
            IAuthManager newMgrInst = null;

            try {
                newMgrInst = (IAuthManager) Class.forName(className).newInstance();
            } catch (ClassNotFoundException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // cleanup
                restore(instancesConfig, id, saveParams);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            } catch (InstantiationException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                restore(instancesConfig, id, saveParams);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            } catch (IllegalAccessException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                restore(instancesConfig, id, saveParams);
                sendResponse(
                        ERROR,
                        new EAuthException(CMS.getUserMessage(getLocale(req), "CMS_AUTHENTICATION_LOAD_CLASS_FAIL",
                                className)).toString(),
                        null, resp);
                return;
            }

            // initialize the authentication manager

            try {
                newMgrInst.init(id, implname, substore);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // don't commit in this case and cleanup the new substore.
                restore(instancesConfig, id, saveParams);
                sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                return;
            }

            // initialized ok.  commiting
            try {
                mConfig.commit(true);
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                // clean up.
                restore(instancesConfig, id, saveParams);
                //System.out.println("SRVLT_FAIL_COMMIT");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                        null, resp);
                return;
            }

            // commited ok. replace instance.

            mAuths.add(id, newMgrInst);

            mAuths.log(ILogger.LL_INFO,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_MGR_REPL", id));

            NameValuePairs params = new NameValuePairs();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
            return;
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_AUTH,
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

    // convenience routine.
    private static void restore(IConfigStore store,
            String id, NameValuePairs saveParams) {
        store.removeSubStore(id);
        IConfigStore rstore = store.makeSubStore(id);

        for (String key : saveParams.keySet()) {
            String value = saveParams.get(key);

            if (value != null)
                rstore.put(key, value);
        }
    }
}
