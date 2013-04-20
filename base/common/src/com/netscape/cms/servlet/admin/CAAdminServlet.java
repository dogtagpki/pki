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

import java.io.File;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ca.ICMSCRLExtensions;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.cmsutil.util.Utils;

/**
 * A class representings an administration servlet for Certificate
 * Authority. This servlet is responsible to serve CA
 * administrative operations such as configuration parameter
 * updates.
 *
 * @version $Revision$, $Date$
 */
public class CAAdminServlet extends AdminServlet {

    /**
     *
     */
    private static final long serialVersionUID = 6200983242040946840L;

    public final static String PROP_EMAIL_TEMPLATE = "emailTemplate";

    private final static String INFO = "CAAdminServlet";

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE_3";

    private ICertificateAuthority mCA = null;
    protected static final String PROP_ENABLED = "enabled";

    /**
     * Constructs CA servlet.
     */
    public CAAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        mCA = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
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
            AUTHZ_RES_NAME = "certServer.ca.configuration";
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
                if (scope.equals(ScopeDef.SC_GENERAL))
                    getGeneralConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CONNECTOR))
                    getConnectorConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRLIPS))
                    getCRLIPsConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRL))
                    getCRLConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_REQ_COMP))
                    getNotificationReqCompConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_REV_COMP))
                    getNotificationRevCompConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ))
                    getNotificationRIQConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRLEXTS_RULES))
                    getCRLExtsConfig(req, resp);
            } else if (op.equals(OpDef.OP_MODIFY)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_GENERAL))
                    setGeneralConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CONNECTOR))
                    setConnectorConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRLIPS))
                    setCRLIPsConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRL))
                    setCRLConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_REQ_COMP))
                    setNotificationReqCompConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_REV_COMP))
                    setNotificationRevCompConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_NOTIFICATION_RIQ))
                    setNotificationRIQConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRLEXTS_RULES))
                    setCRLExtsConfig(req, resp);
            } else if (op.equals(OpDef.OP_SEARCH)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_CRLEXTS_RULES))
                    listCRLExtsConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_CRLIPS))
                    listCRLIPsConfig(req, resp);
            } else if (op.equals(OpDef.OP_ADD)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_CRLIPS))
                    addCRLIPsConfig(req, resp);
            } else if (op.equals(OpDef.OP_DELETE)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_CRLIPS))
                    deleteCRLIPsConfig(req, resp);
            } else {
                sendResponse(1, "Unknown operation", null, resp);
            }
        } catch (Exception e) {
            sendResponse(1, e.toString(), null, resp);
            return;
        }
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    /*
     * handle request completion (cert issued) notification config requests
     */
    private void getNotificationCompConfig(HttpServletRequest req,
            HttpServletResponse resp, IConfigStore rc) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.put(name, rc.getString(name, ""));
        }

        params.put(Constants.PR_ENABLE,
                rc.getString(PROP_ENABLED, Constants.FALSE));
        sendResponse(SUCCESS, null, params, resp);
    }

    private void getNotificationRevCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);
        IConfigStore rc = nc.getSubStore(ICertificateAuthority.PROP_CERT_REVOKED_SUBSTORE);

        getNotificationCompConfig(req, resp, rc);
    }

    private void getNotificationReqCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);
        IConfigStore rc = nc.getSubStore(ICertificateAuthority.PROP_CERT_ISSUED_SUBSTORE);

        getNotificationCompConfig(req, resp, rc);
    }

    /*
     * handle getting request in queue notification config info
     */
    private void getNotificationRIQConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore riq = nc.getSubStore(ICertificateAuthority.PROP_REQ_IN_Q_SUBSTORE);

        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.put(name, riq.getString(name, ""));
        }

        params.put(Constants.PR_ENABLE,
                riq.getString(PROP_ENABLED, Constants.FALSE));
        sendResponse(SUCCESS, null, params, resp);
    }

    /*
     * handle setting request in queue notification config info
     */
    private void setNotificationRIQConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore riq = nc.getSubStore(ICertificateAuthority.PROP_REQ_IN_Q_SUBSTORE);

        //set rest of the parameters
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            String val = req.getParameter(name);

            // if it's emailTemplate, check to see if the path exists
            if (name.equalsIgnoreCase(PROP_EMAIL_TEMPLATE)) {
                File template = new File(val);

                if ((!template.exists()) || (!template.canRead())
                        || (template.isDirectory())) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_INVALID_PATH"));

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PATH"),
                            null, resp);
                    return;
                }
            }
            riq.putString(name, val);
            mCA.getRequestInQListener().set(name, val);
        }

        // set enable flag
        String enabledString = req.getParameter(Constants.PR_ENABLE);

        riq.putString(PROP_ENABLED, enabledString);
        mCA.getRequestInQListener().set(PROP_ENABLED, enabledString);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    /*
     * handle setting request complete notification config info
     */
    private void setNotificationCompConfig(HttpServletRequest req,
            HttpServletResponse resp, IConfigStore rc, IRequestListener thisListener) throws ServletException,
            IOException, EBaseException {

        //set rest of the parameters
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            String val = req.getParameter(name);

            // if it's emailTemplate, check to see if the path exists
            if (name.equalsIgnoreCase(PROP_EMAIL_TEMPLATE)) {
                File template = new File(val);

                if ((!template.exists()) || (!template.canRead())
                        || (template.isDirectory())) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_INVALID_PATH"));

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PATH"),
                            null, resp);
                    return;
                }
            }
            rc.putString(name, val);
            thisListener.set(name, val);
        }

        // set enable flag
        String enabledString = req.getParameter(Constants.PR_ENABLE);

        rc.putString(PROP_ENABLED, enabledString);
        thisListener.set(PROP_ENABLED, enabledString);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    private void setNotificationRevCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(ICertificateAuthority.PROP_CERT_REVOKED_SUBSTORE);

        setNotificationCompConfig(req, resp, rc, mCA.getCertRevokedListener());
    }

    private void setNotificationReqCompConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore config = mCA.getConfigStore();
        IConfigStore nc =
                config.getSubStore(ICertificateAuthority.PROP_NOTIFY_SUBSTORE);

        IConfigStore rc = nc.getSubStore(ICertificateAuthority.PROP_CERT_ISSUED_SUBSTORE);

        setNotificationCompConfig(req, resp, rc, mCA.getCertIssuedListener());

    }

    private void listCRLIPsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        Enumeration<ICRLIssuingPoint> ips = mCA.getCRLIssuingPoints();

        while (ips.hasMoreElements()) {
            ICRLIssuingPoint ip = ips.nextElement();

            if (ip != null) {
                String ipId = ip.getId();

                if (ipId != null && ipId.length() > 0)
                    params.put(ipId, ip.getDescription());
                params.put(ipId + "." + Constants.PR_ENABLED,
                        (Boolean.valueOf(ip.isCRLIssuingPointEnabled())).toString());
            }
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getCRLIPsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.RS_ID);

        if (id != null && id.length() > 0) {
            ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(id);

            if (ip != null) {

                Enumeration<String> e = req.getParameterNames();
                String value = "";

                while (e.hasMoreElements()) {
                    String name = e.nextElement();

                    if (name.equals(Constants.PR_ENABLED)) {
                        if (ip.isCRLIssuingPointEnabled()) {
                            value = Constants.TRUE;
                        } else {
                            value = Constants.FALSE;
                        }
                    }
                    if (name.equals(Constants.PR_ID))
                        value = id;
                    if (name.equals(Constants.PR_DESCRIPTION))
                        value = ip.getDescription();
                    if (name.equals(Constants.PR_CLASS))
                        value = ip.getClass().getName();

                    params.put(name, value);
                }
            }
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Add CRL issuing points configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE used when configuring CRL profile (extensions,
     * frequency, CRL format)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void addCRLIPsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String ipId = req.getParameter(Constants.PR_ID);

            if (ipId == null || ipId.length() == 0) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Missing CRL IP name", null, resp);
                return;
            }
            params.put(Constants.PR_ID, ipId);

            String desc = req.getParameter(Constants.PR_DESCRIPTION);

            if (desc == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Missing CRL IP description", null, resp);
                return;
            }
            params.put(Constants.PR_DESCRIPTION, desc);

            String sEnable = req.getParameter(Constants.PR_ENABLED);
            boolean enable = true;

            if (sEnable != null && sEnable.length() > 0 &&
                    sEnable.equalsIgnoreCase(Constants.FALSE)) {
                enable = false;
                params.put(Constants.PR_ENABLED, Constants.FALSE);
            } else {
                params.put(Constants.PR_ENABLED, Constants.TRUE);
            }

            IConfigStore crlSubStore =
                    mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
            Enumeration<String> crlNames = crlSubStore.getSubStoreNames();

            while (crlNames.hasMoreElements()) {
                String name = crlNames.nextElement();

                if (ipId.equals(name)) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR, ipId + " CRL IP already exists", null, resp);
                    return;
                }
            }
            if (!mCA.addCRLIssuingPoint(crlSubStore, ipId, enable, desc)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Cannot add or edit CRL IP", null, resp);
                return;
            }
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
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
     * Set CRL issuing points configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE used when configuring CRL profile (extensions,
     * frequency, CRL format)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setCRLIPsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String ipId = req.getParameter(Constants.PR_ID);

            if (ipId == null || ipId.length() == 0) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Missing CRL IP name", null, resp);
                return;
            }
            params.put(Constants.PR_ID, ipId);

            String desc = req.getParameter(Constants.PR_DESCRIPTION);

            if (desc == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Missing CRL IP description", null, resp);
                return;
            }
            params.put(Constants.PR_DESCRIPTION, desc);

            String sEnable = req.getParameter(Constants.PR_ENABLED);
            boolean enable = true;

            if (sEnable != null && sEnable.length() > 0 &&
                    sEnable.equalsIgnoreCase(Constants.FALSE)) {
                enable = false;
                params.put(Constants.PR_ENABLED, Constants.FALSE);
            } else {
                params.put(Constants.PR_ENABLED, Constants.TRUE);
            }

            IConfigStore crlSubStore =
                    mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
            boolean done = false;
            Enumeration<String> crlNames = crlSubStore.getSubStoreNames();

            while (crlNames.hasMoreElements()) {
                String name = crlNames.nextElement();

                if (ipId.equals(name)) {
                    ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(ipId);

                    if (ip != null) {
                        ip.setDescription(desc);
                        ip.enableCRLIssuingPoint(enable);
                    }
                    IConfigStore c = crlSubStore.getSubStore(ipId);

                    if (c != null) {
                        c.putString(Constants.PR_DESCRIPTION, desc);
                        c.putString(Constants.PR_ENABLED,
                                (enable) ? Constants.TRUE : Constants.FALSE);
                    }
                    done = true;
                    break;
                }
            }
            if (!done) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(ERROR, "Missing CRL IP " + ipId, null, resp);
                return;
            }
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
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
     * Delete CRL issuing points configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE used when configuring CRL profile (extensions,
     * frequency, CRL format)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void deleteCRLIPsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String id = req.getParameter(Constants.RS_ID);

            if (id != null && id.length() > 0) {
                IConfigStore crlSubStore =
                        mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
                boolean done = false;
                Enumeration<String> crlNames = crlSubStore.getSubStoreNames();

                while (crlNames.hasMoreElements()) {
                    String name = crlNames.nextElement();

                    if (id.equals(name)) {
                        mCA.deleteCRLIssuingPoint(crlSubStore, id);
                        done = true;
                        break;
                    }
                }
                if (!done) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    audit(auditMessage);

                    sendResponse(ERROR, "Missing CRL IP " + id, null, resp);
                    return;
                }
                commit(true);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
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

    private void getCRLExtsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        String ipId = null;
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            ipId = name;
        }
        if (ipId == null || ipId.length() <= 0) {
            ipId = ICertificateAuthority.PROP_MASTER_CRL;
        }

        ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(ipId);
        ICMSCRLExtensions crlExts = ip.getCRLExtensions();
        String id = req.getParameter(Constants.RS_ID);

        if (id != null) {
            params = crlExts.getConfigParams(id);
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Delete CRL extensions configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE used when configuring CRL profile (extensions,
     * frequency, CRL format)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setCRLExtsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String ipId = req.getParameter(Constants.PR_ID);

            if (ipId == null || ipId.length() <= 0) {
                ipId = ICertificateAuthority.PROP_MASTER_CRL;
            }

            ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(ipId);
            ICMSCRLExtensions crlExts = ip.getCRLExtensions();

            IConfigStore config = mCA.getConfigStore();
            IConfigStore crlsSubStore =
                    config.getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
            IConfigStore crlSubStore = crlsSubStore.getSubStore(ipId);
            IConfigStore crlExtsSubStore =
                    crlSubStore.getSubStore(ICertificateAuthority.PROP_CRLEXT_SUBSTORE);

            String id = req.getParameter(Constants.RS_ID);

            if (id != null) {
                IConfigStore crlExtSubStore = crlExtsSubStore.getSubStore(id);

                Enumeration<String> e = req.getParameterNames();

                while (e.hasMoreElements()) {
                    String name = e.nextElement();

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

                    params.put(name, value);
                }
                crlExts.setConfigParams(id, params, crlExtSubStore);
                commit(true);
                ip.clearCRLCache();
                ip.updateCRLCacheRepository();
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
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

    private void listCRLExtsConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.PR_ID);

        if (id == null || id.length() <= 0) {
            id = ICertificateAuthority.PROP_MASTER_CRL;
        }

        IConfigStore config = mCA.getConfigStore();
        IConfigStore crlsSubStore = config.getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
        IConfigStore crlSubStore = crlsSubStore.getSubStore(id);
        IConfigStore crlExtsSubStore = crlSubStore.getSubStore(ICertificateAuthority.PROP_CRLEXT_SUBSTORE);

        if (crlExtsSubStore != null) {
            Enumeration<String> enumExts = crlExtsSubStore.getSubStoreNames();

            while (enumExts.hasMoreElements()) {
                String extName = enumExts.nextElement();
                boolean crlExtEnabled = false;
                IConfigStore crlExtSubStore = crlExtsSubStore.getSubStore(extName);
                Enumeration<String> properties = crlExtSubStore.getPropertyNames();

                while (properties.hasMoreElements()) {
                    String name = properties.nextElement();

                    if (name.equals(Constants.PR_ENABLE)) {
                        crlExtEnabled = crlExtSubStore.getBoolean(name, false);
                    }
                }
                params.put(extName, extName + ";visible;" + ((crlExtEnabled) ? "enabled" : "disabled"));
            }
        }

        sendResponse(SUCCESS, null, params, resp);
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

        String ipId = null;
        String name = null;

        Enumeration<ICRLIssuingPoint> ips = mCA.getCRLIssuingPoints();
        if (ips.hasMoreElements()) {
            ICRLIssuingPoint ip = ips.nextElement();
            if (ip != null) {
                ipId = ip.getId();
            }
        }
        if (ipId != null) {
            ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(ipId);
            ICMSCRLExtensions crlExts = ip.getCRLExtensions();
            name = crlExts.getClassPath(implName);
        }
        if (name != null) {
            impl = getClassByNameAsExtendedPluginInfo(name);
        }
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
     * Set CRL configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE used when configuring CRL profile (extensions,
     * frequency, CRL format)
     * </ul>
     *
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException an error has occurred
     */
    private void setCRLConfig(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String id = req.getParameter(Constants.RS_ID);

            if (id == null || id.length() <= 0 ||
                    id.equals(Constants.RS_ID_CONFIG)) {
                id = ICertificateAuthority.PROP_MASTER_CRL;
            }
            ICRLIssuingPoint ip = mCA.getCRLIssuingPoint(id);

            //Save New Settings to the config file
            IConfigStore config = mCA.getConfigStore();
            IConfigStore crlsSubStore = config.getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
            IConfigStore crlSubStore = crlsSubStore.getSubStore(id);

            //set reset of the parameters
            Enumeration<String> e = req.getParameterNames();

            while (e.hasMoreElements()) {
                String name = e.nextElement();

                if (name.equals(Constants.OP_TYPE))
                    continue;
                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                if (name.equals(Constants.PR_ENABLE))
                    continue;
                String value = req.getParameter(name);

                params.put(name, value);
                crlSubStore.putString(name, value);
            }
            boolean noRestart = ip.updateConfig(params);

            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            if (noRestart)
                sendResponse(SUCCESS, null, null, resp);
            else
                sendResponse(RESTART, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE,
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

    private void getCRLConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.RS_ID);

        if (id == null || id.length() <= 0 ||
                id.equals(Constants.RS_ID_CONFIG)) {
            id = ICertificateAuthority.PROP_MASTER_CRL;
        }
        IConfigStore crlsSubStore =
                mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
        IConfigStore crlSubStore = crlsSubStore.getSubStore(id);

        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            params.put(name, crlSubStore.getString(name, ""));
        }

        getSigningAlgConfig(params);
        sendResponse(SUCCESS, null, params, resp);
    }

    private void getConnectorConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore caConfig = mCA.getConfigStore();
        IConfigStore connectorConfig = caConfig.getSubStore("connector");
        IConfigStore caConnectorConfig = null;

        if (isKRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("KRA");
        } else if (isCLAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("CLA");
        }

        Enumeration<String> enum1 = req.getParameterNames();
        NameValuePairs params = new NameValuePairs();

        if (caConnectorConfig != null) {
            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();

                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                if (name.equals(Constants.OP_TYPE))
                    continue;

                params.put(name, caConnectorConfig.getString(name, ""));
            }
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    private void setConnectorConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore caConfig = mCA.getConfigStore();
        IConfigStore connectorConfig = caConfig.getSubStore("connector");
        IConfigStore caConnectorConfig = null;

        //        String nickname = CMS.getServerCertNickname();

        if (isKRAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("KRA");
        } else if (isCLAConnector(req)) {
            caConnectorConfig = connectorConfig.getSubStore("CLA");
        }

        Enumeration<String> enum1 = req.getParameterNames();

        if (caConnectorConfig != null) {
            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();

                if (name.equals(Constants.OP_TYPE))
                    continue;
                if (name.equals(Constants.RS_ID))
                    continue;
                if (name.equals(Constants.OP_SCOPE))
                    continue;
                /*
                                if (name.equals("nickName")) {
                                    caConnectorConfig.putString(name, nickname);
                                    continue;
                                }
                */
                if (name.equals("host")) {
                    try {
                        Utils.checkHost(req.getParameter("host"));
                    } catch (UnknownHostException e) {
                        sendResponse(ERROR, "Unknown Host " + req.getParameter("host"), null, resp);
                        return;
                    }
                }
                caConnectorConfig.putString(name, req.getParameter(name));
            }
        }

        commit(true);
        sendResponse(RESTART, null, null, resp);
    }

    private boolean isKRAConnector(HttpServletRequest req) {
        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals("RS_ID")) {
                String val = req.getParameter(key);

                if (val.equals("Data Recovery Manager Connector"))
                    return true;
                else
                    return false;
            }
        }
        return false;
    }

    private boolean isCLAConnector(HttpServletRequest req) {
        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals("RS_ID")) {
                String val = req.getParameter(key);

                if (val.equals("Clone Master Manager Connector"))
                    return true;
                else
                    return false;
            }
        }
        return false;
    }

    private void getGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String value = "false";

        /*
         ISubsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         if (eeGateway != null) {
         IConfigStore eeConfig = eeGateway.getConfigStore();
         if (eeConfig != null)
         value = eeConfig.getString("enabled", "true");
         String ocspValue = "true";
         ocspValue = eeConfig.getString("enableOCSP", "true");
         params.add(Constants.PR_OCSP_ENABLED, ocspValue);
         }
         params.add(Constants.PR_EE_ENABLED, value);
         */

        IConfigStore caConfig = mCA.getConfigStore();

        value = caConfig.getString(ICertificateAuthority.PROP_ENABLE_PAST_CATIME, "false");
        params.put(Constants.PR_VALIDITY, value);

        getSigningAlgConfig(params);
        getSerialConfig(params);
        getMaxSerialConfig(params);
        params.put(Constants.PR_SN_MANAGEMENT,
            Boolean.toString(mCA.getDBSubsystem().getEnableSerialMgmt()));
        params.put(Constants.PR_RANDOM_SN,
            Boolean.toString(mCA.getCertificateRepository().getEnableRandomSerialNumbers()));

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getSigningAlgConfig(NameValuePairs params) {
        params.put(Constants.PR_DEFAULT_ALGORITHM,
                mCA.getDefaultAlgorithm());
        String[] algorithms = mCA.getCASigningAlgorithms();
        StringBuffer algorStr = new StringBuffer();

        for (int i = 0; i < algorithms.length; i++) {
            if (i == 0)
                algorStr.append(algorithms[i]);
            else {
                algorStr.append(":");
                algorStr.append(algorithms[i]);
            }
        }
        params.put(Constants.PR_ALL_ALGORITHMS, algorStr.toString());
    }

    private void getSerialConfig(NameValuePairs params) {
        params.put(Constants.PR_SERIAL,
                mCA.getStartSerial());
    }

    private void getMaxSerialConfig(NameValuePairs params) {
        params.put(Constants.PR_MAXSERIAL,
                mCA.getMaxSerial());
    }

    private void setGeneralConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        /*
         ISubsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         */

        Enumeration<String> enum1 = req.getParameterNames();
        boolean restart = false;

        //mCA.setMaxSerial("");
        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_EE_ENABLED)) {

                /*
                 if (eeConfig != null) {
                 if (((EEGateway)eeGateway).isEnabled() &&
                 value.equals("false") ||
                 !((EEGateway)eeGateway).isEnabled() &&
                 value.equals("true")) {
                 restart=true;;
                 }
                 eeConfig.putString("enabled", value);
                 }
                 */
            } else if (key.equals(Constants.PR_VALIDITY)) {
                mCA.setValidity(value);
            } else if (key.equals(Constants.PR_DEFAULT_ALGORITHM)) {
                mCA.setDefaultAlgorithm(value);
            } else if (key.equals(Constants.PR_SERIAL)) {
                mCA.setStartSerial(value);
            } else if (key.equals(Constants.PR_MAXSERIAL)) {
                mCA.setMaxSerial(value);
            } else if (key.equals(Constants.PR_SN_MANAGEMENT)) {
                mCA.getDBSubsystem().setEnableSerialMgmt(Boolean.valueOf(value));
            } else if (key.equals(Constants.PR_RANDOM_SN)) {
                mCA.getCertificateRepository().setEnableRandomSerialNumbers(Boolean.valueOf(value), true, false);
            }
        }

        commit(true);
        if (restart)
            sendResponse(RESTART, null, null, resp);
        else
            sendResponse(SUCCESS, null, null, resp);
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, "CAAdminServlet: " + msg);
    }
}
