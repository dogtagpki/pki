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


import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.cert.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.util.*;
import netscape.security.x509.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*; 
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.ocsp.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.apps.*;


/**
 * A class representings an administration servlet for Certificate
 * Authority. This servlet is responsible to serve OCSP 
 * administrative operations such as configuration parameter 
 * updates.
 *
 * @version $Revision$, $Date$
 */
public class OCSPAdminServlet extends AdminServlet {

    protected static final String PROP_ENABLED = "enabled";

    private final static String INFO = "OCSPAdminServlet";

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE =
        "LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE_3";

    private IOCSPAuthority mOCSP = null;

    public OCSPAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mOCSP = (IOCSPAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_OCSP);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request. Each request is authenticated to
     * the authenticate manager.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
        super.service(req, resp);
			    
        //get all operational flags
        String op = req.getParameter(Constants.OP_TYPE);
        String scope = req.getParameter(Constants.OP_SCOPE);

        //check operational flags
        if ((op == null) || (scope == null)) {
            sendResponse(1, "Invalid Protocol", null, resp);
            return;
        }			    

        super.authenticate(req);
		
        try {
            AUTHZ_RES_NAME = "certServer.ocsp.configuration";
            if (scope.equals(ScopeDef.SC_EXTENDED_PLUGIN_INFO)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                        null, resp);
                    return;
                }
                try {
                    getExtendedPluginInfo(req, resp);
                    return;
                } catch (EBaseException e) {
                    sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
                }
            }

            if (scope.equals(ScopeDef.SC_OCSPSTORE_DEFAULT)) {
                if (op.equals(OpDef.OP_MODIFY)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                        return;
                    }
                    setDefaultStore(req, resp);
                    return;
                }
            }

            if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                        null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    getGeneralConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_OCSPSTORES_RULES)) {
                    getOCSPStoresConfig(req, resp);
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
                if (scope.equals(ScopeDef.SC_GENERAL)) {
                    setGeneralConfig(req, resp);
                    return;
                } else if (scope.equals(ScopeDef.SC_OCSPSTORES_RULES)) {
                    setOCSPStoresConfig(req, resp);
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
                if (scope.equals(ScopeDef.SC_OCSPSTORES_RULES)) {
                    listOCSPStoresConfig(req, resp);
                    return;
                }
            }
        } catch (Exception e) {
            sendResponse(1, e.toString(), null, resp);
            return;
        }
    }

    /**
     * retrieve extended plugin info such as brief description,
     * type info from CRL extensions
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

        impl = getClassByNameAsExtendedPluginInfo(implName);
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
     * Set default OCSP store
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE used when
     * configuring OCSP profile (everything under Online Certificate Status
     * Manager)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setDefaultStore(HttpServletRequest req,
        HttpServletResponse resp)
        throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String id = req.getParameter(Constants.RS_ID);

            mOCSP.getConfigStore().putString(IOCSPAuthority.PROP_DEF_STORE_ID,
                id);
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
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

    private void getOCSPStoresConfig(HttpServletRequest req,
        HttpServletResponse resp)
        throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        IOCSPStore store = mOCSP.getOCSPStore(id);
        NameValuePairs params = store.getConfigParameters();

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Set OCSP store configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE used when
     * configuring OCSP profile (everything under Online Certificate Status
     * Manager)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setOCSPStoresConfig(HttpServletRequest req,
        HttpServletResponse resp)
        throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String id = req.getParameter(Constants.RS_ID);

            IOCSPStore store = mOCSP.getOCSPStore(id);

            Enumeration e = req.getParameterNames();

            while (e.hasMoreElements()) {
                String name = (String) e.nextElement();

                if (name.equals(Constants.OP_TYPE))
                    continue;
                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                if (name.equals(Constants.PR_CRLEXT_IMPL_NAME))
                    continue;
                if (name.equals("RULENAME"))
                    continue;
                String value = req.getParameter(name);

                params.add(name, value);
            }
            store.setConfigParameters(params);
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
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

    private void listOCSPStoresConfig(HttpServletRequest req,
        HttpServletResponse resp)
        throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        IConfigStore config = mOCSP.getConfigStore();
        String defStore = config.getString(mOCSP.PROP_DEF_STORE_ID);
        IConfigStore SubStore = config.getSubStore(mOCSP.PROP_STORE);
        Enumeration enumStores = SubStore.getSubStoreNames();

        while (enumStores.hasMoreElements()) {
            String storeName = (String) enumStores.nextElement();
            boolean storeEnabled = false;

            if (storeName.equals(defStore)) {
                storeEnabled = true;
            }
            params.add(storeName, storeName + ";visible;" + ((storeEnabled) ? "enabled" : "disabled"));
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    private void getGeneralConfig(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        getSigningAlgConfig(params);

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getSigningAlgConfig(NameValuePairs params) {
        params.add(Constants.PR_DEFAULT_ALGORITHM,
            mOCSP.getDefaultAlgorithm());
        String[] algorithms = mOCSP.getOCSPSigningAlgorithms();
        StringBuffer algorStr = new StringBuffer();

        for (int i = 0; i < algorithms.length; i++) {
            if (i == 0)
                algorStr.append(algorithms[i]);
            else
                algorStr.append(":");
                algorStr.append(algorithms[i]);
        }
        params.add(Constants.PR_ALL_ALGORITHMS, algorStr.toString());
    }

    /**
     * Set general OCSP configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE used when
     * configuring OCSP profile (everything under Online Certificate Status
     * Manager)
     * </ul>
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setGeneralConfig(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration enum1 = req.getParameterNames();
            boolean restart = false;

            while (enum1.hasMoreElements()) {
                String key = (String) enum1.nextElement();
                String value = req.getParameter(key);

                if (key.equals(Constants.PR_DEFAULT_ALGORITHM)) {
                    mOCSP.setDefaultAlgorithm(value);
                }
            }

            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE,
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
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
            level, "CAAdminServlet: " + msg);
    }
}    
