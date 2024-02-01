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
import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.ca.CMSCRLExtensions;
import com.netscape.ca.CRLConfig;
import com.netscape.ca.CRLExtensionConfig;
import com.netscape.ca.CRLExtensionsConfig;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CRLIssuingPointConfig;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.connector.ConnectorConfig;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.logging.Auditor;

/**
 * A class representings an administration servlet for Certificate
 * Authority. This servlet is responsible to serve CA
 * administrative operations such as configuration parameter
 * updates.
 */
@WebServlet(
        name = "caca",
        urlPatterns = "/caadmin",
        initParams = {
                @WebInitParam(name="ID",       value="caca"),
                @WebInitParam(name="AuthzMgr", value="BasicAclAuthz")
        }
)
public class CAAdminServlet extends AdminServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAAdminServlet.class);

    private static final long serialVersionUID = 6200983242040946840L;

    public final static String PROP_EMAIL_TEMPLATE = "emailTemplate";

    private final static String INFO = "CAAdminServlet";

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
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request. Each request is authenticated to
     * the authenticate manager.
     */
    @Override
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
                } catch (IOException e) {
                    sendResponse(ERROR, e.toString(), null, resp);
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
                    getGeneralConfig(resp);
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
                    listCRLIPsConfig(resp);
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
    private void getNotificationCompConfig(HttpServletRequest req, HttpServletResponse resp, ConfigStore rc)
            throws IOException, EBaseException {

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

    private void getNotificationRevCompConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore nc = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore rc = nc.getSubStore(CertificateAuthority.PROP_CERT_REVOKED_SUBSTORE, ConfigStore.class);

        getNotificationCompConfig(req, resp, rc);
    }

    private void getNotificationReqCompConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        ConfigStore nc = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore rc = nc.getSubStore(CertificateAuthority.PROP_CERT_ISSUED_SUBSTORE, ConfigStore.class);

        getNotificationCompConfig(req, resp, rc);
    }

    /*
     * handle getting request in queue notification config info
     */
    private void getNotificationRIQConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        ConfigStore nc = caConfig.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore riq = nc.getSubStore(CertificateAuthority.PROP_REQ_IN_Q_SUBSTORE, ConfigStore.class);

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
    private void setNotificationRIQConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig config = engineConfig.getCAConfig();
        ConfigStore nc = config.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore riq = nc.getSubStore(CertificateAuthority.PROP_REQ_IN_Q_SUBSTORE, ConfigStore.class);

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
                    logger.error(CMS.getLogMessage("ADMIN_SRVLT_INVALID_PATH"));

                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PATH"),
                            null, resp);
                    return;
                }
            }
            riq.putString(name, val);
            engine.getRequestInQueueListener().set(name, val);
        }

        // set enable flag
        String enabledString = req.getParameter(Constants.PR_ENABLE);

        riq.putString(PROP_ENABLED, enabledString);
        engine.getRequestInQueueListener().set(PROP_ENABLED, enabledString);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    /*
     * handle setting request complete notification config info
     */
    private void setNotificationCompConfig(HttpServletRequest req, HttpServletResponse resp, ConfigStore rc,
            RequestListener thisListener) throws IOException, EBaseException {

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
                    logger.error(CMS.getLogMessage("ADMIN_SRVLT_INVALID_PATH"));

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

    private void setNotificationRevCompConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig config = engineConfig.getCAConfig();
        ConfigStore nc = config.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore rc = nc.getSubStore(CertificateAuthority.PROP_CERT_REVOKED_SUBSTORE, ConfigStore.class);

        setNotificationCompConfig(req, resp, rc, engine.getCertRevokedListener());
    }

    private void setNotificationReqCompConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig config = engineConfig.getCAConfig();
        ConfigStore nc = config.getSubStore(CertificateAuthority.PROP_NOTIFY_SUBSTORE, ConfigStore.class);
        ConfigStore rc = nc.getSubStore(CertificateAuthority.PROP_CERT_ISSUED_SUBSTORE, ConfigStore.class);

        setNotificationCompConfig(req, resp, rc, engine.getCertIssuedListener());

    }

    private void listCRLIPsConfig(HttpServletResponse resp) throws IOException {
        NameValuePairs params = new NameValuePairs();

        CAEngine engine = (CAEngine) getCMSEngine();

        for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
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

    private void getCRLIPsConfig(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        CAEngine engine = (CAEngine) getCMSEngine();
        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.RS_ID);

        if (id != null && id.length() > 0) {
            CRLIssuingPoint ip = engine.getCRLIssuingPoint(id);

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

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        Auditor auditor = engine.getAuditor();

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
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

                sendResponse(ERROR, "Missing CRL IP name", null, resp);
                return;
            }
            params.put(Constants.PR_ID, ipId);

            String desc = req.getParameter(Constants.PR_DESCRIPTION);

            if (desc == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

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

            CAConfig caConfig = engineConfig.getCAConfig();
            CRLConfig crlConfig = caConfig.getCRLConfig();
            Enumeration<String> crlNames = crlConfig.getSubStoreNames().elements();

            while (crlNames.hasMoreElements()) {
                String name = crlNames.nextElement();

                if (ipId.equals(name)) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                AuditEvent.CONFIG_CRL_PROFILE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    auditor.log(auditMessage);

                    sendResponse(ERROR, ipId + " CRL IP already exists", null, resp);
                    return;
                }
            }
            if (!engine.addCRLIssuingPoint(crlConfig, ipId, enable, desc)) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

                sendResponse(ERROR, "Cannot add or edit CRL IP", null, resp);
                return;
            }
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
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

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        Auditor auditor = engine.getAuditor();

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
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

                sendResponse(ERROR, "Missing CRL IP name", null, resp);
                return;
            }
            params.put(Constants.PR_ID, ipId);

            String desc = req.getParameter(Constants.PR_DESCRIPTION);

            if (desc == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

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

            CRLConfig crlConfig = caConfig.getCRLConfig();
            boolean done = false;
            Enumeration<String> crlNames = crlConfig.getSubStoreNames().elements();

            while (crlNames.hasMoreElements()) {
                String name = crlNames.nextElement();

                if (ipId.equals(name)) {
                    CRLIssuingPoint ip = engine.getCRLIssuingPoint(ipId);

                    if (ip != null) {
                        ip.setDescription(desc);
                        ip.enableCRLIssuingPoint(enable);
                    }

                    CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(ipId);

                    if (ipConfig != null) {
                        ipConfig.putString(Constants.PR_DESCRIPTION, desc);
                        ipConfig.putString(Constants.PR_ENABLED,
                                (enable) ? Constants.TRUE : Constants.FALSE);
                    }
                    done = true;
                    break;
                }
            }
            if (!done) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CONFIG_CRL_PROFILE,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                auditor.log(auditMessage);

                sendResponse(ERROR, "Missing CRL IP " + ipId, null, resp);
                return;
            }
            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
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

        CAEngine engine = (CAEngine) getCMSEngine();
        CertificateAuthority ca = engine.getCA();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String id = req.getParameter(Constants.RS_ID);

            if (id != null && id.length() > 0) {
                CAConfig caConfig = ca.getConfigStore();
                CRLConfig crlConfig = caConfig.getCRLConfig();
                boolean done = false;
                Enumeration<String> crlNames = crlConfig.getSubStoreNames().elements();

                while (crlNames.hasMoreElements()) {
                    String name = crlNames.nextElement();

                    if (id.equals(name)) {
                        engine.deleteCRLIssuingPoint(ca, crlConfig, id);
                        done = true;
                        break;
                    }
                }
                if (!done) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                AuditEvent.CONFIG_CRL_PROFILE,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                    auditor.log(auditMessage);

                    sendResponse(ERROR, "Missing CRL IP " + id, null, resp);
                    return;
                }
                commit(true);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void getCRLExtsConfig(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        CAEngine engine = (CAEngine) getCMSEngine();

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
            ipId = CertificateAuthority.PROP_MASTER_CRL;
        }

        CRLIssuingPoint ip = engine.getCRLIssuingPoint(ipId);
        CMSCRLExtensions crlExts = ip.getCRLExtensions();
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

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String ipId = req.getParameter(Constants.PR_ID);

            if (ipId == null || ipId.length() <= 0) {
                ipId = CertificateAuthority.PROP_MASTER_CRL;
            }

            CRLIssuingPoint ip = engine.getCRLIssuingPoint(ipId);
            CMSCRLExtensions crlExts = ip.getCRLExtensions();

            CRLConfig crlConfig = caConfig.getCRLConfig();
            CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(ipId);
            CRLExtensionsConfig crlExtsConfig = ipConfig.getExtensionsConfig();

            String id = req.getParameter(Constants.RS_ID);

            if (id != null) {
                CRLExtensionConfig crlExtSubStore = crlExtsConfig.getExtensionConfig(id);

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
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void listCRLExtsConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.PR_ID);

        if (id == null || id.length() <= 0) {
            id = CertificateAuthority.PROP_MASTER_CRL;
        }

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        CRLConfig crlConfig = caConfig.getCRLConfig();
        CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(id);
        CRLExtensionsConfig crlExtsConfig = ipConfig.getExtensionsConfig();

        if (crlExtsConfig != null) {
            Enumeration<String> enumExts = crlExtsConfig.getSubStoreNames().elements();

            while (enumExts.hasMoreElements()) {
                String extName = enumExts.nextElement();
                boolean crlExtEnabled = false;
                CRLExtensionConfig crlExtSubStore = crlExtsConfig.getExtensionConfig(extName);
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
    private void getExtendedPluginInfo(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter(Constants.RS_ID);
        int colon = id.indexOf(':');

        String implName = id.substring(colon + 1);

        NameValuePairs params =
                getExtendedPluginInfo(implName);

        sendResponse(SUCCESS, null, params, resp);
    }

    private NameValuePairs getExtendedPluginInfo(String implName) {
        IExtendedPluginInfo ext_info = null;
        Object impl = null;

        String ipId = null;
        String name = null;

        CAEngine engine = (CAEngine) getCMSEngine();
        Enumeration<CRLIssuingPoint> ips = Collections.enumeration(engine.getCRLIssuingPoints());

        if (ips.hasMoreElements()) {
            CRLIssuingPoint ip = ips.nextElement();
            if (ip != null) {
                ipId = ip.getId();
            }
        }
        if (ipId != null) {
            CRLIssuingPoint ip = engine.getCRLIssuingPoint(ipId);
            CMSCRLExtensions crlExts = ip.getCRLExtensions();
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
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo());
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

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();

            String id = req.getParameter(Constants.RS_ID);

            if (id == null || id.length() <= 0 ||
                    id.equals(Constants.RS_ID_CONFIG)) {
                id = CertificateAuthority.PROP_MASTER_CRL;
            }
            CRLIssuingPoint ip = engine.getCRLIssuingPoint(id);

            //Save New Settings to the config file
            CRLConfig crlConfig = caConfig.getCRLConfig();
            CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(id);

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
                ipConfig.putString(name, value);
            }
            boolean noRestart = ip.updateConfig(params);

            commit(true);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            if (noRestart)
                sendResponse(SUCCESS, null, null, resp);
            else
                sendResponse(RESTART, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_CRL_PROFILE,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void getCRLConfig(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();

        String id = req.getParameter(Constants.RS_ID);

        if (id == null || id.length() <= 0 ||
                id.equals(Constants.RS_ID_CONFIG)) {
            id = CertificateAuthority.PROP_MASTER_CRL;
        }

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        CRLConfig crlConfig = caConfig.getCRLConfig();
        CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(id);

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
            params.put(name, ipConfig.getString(name, ""));
        }

        getSigningAlgConfig(params);
        sendResponse(SUCCESS, null, params, resp);
    }

    private void getConnectorConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig caConnectorConfig = null;

        if (isKRAConnector(req)) {
            caConnectorConfig = connectorsConfig.getConnectorConfig("KRA");
        } else if (isCLAConnector(req)) {
            caConnectorConfig = connectorsConfig.getConnectorConfig("CLA");
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

    private void setConnectorConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig caConnectorConfig = null;

        //        String nickname = CMS.getServerCertNickname();

        if (isKRAConnector(req)) {
            caConnectorConfig = connectorsConfig.getConnectorConfig("KRA");
        } else if (isCLAConnector(req)) {
            caConnectorConfig = connectorsConfig.getConnectorConfig("CLA");
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

                return val.equals("Data Recovery Manager Connector");
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

                return val.equals("Clone Master Manager Connector");
            }
        }
        return false;
    }

    private void getGeneralConfig(HttpServletResponse resp) throws IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String value = "false";

        /*
         Subsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         if (eeGateway != null) {
         ConfigStore eeConfig = eeGateway.getConfigStore();
         if (eeConfig != null)
         value = eeConfig.getString("enabled", "true");
         String ocspValue = "true";
         ocspValue = eeConfig.getString("enableOCSP", "true");
         params.add(Constants.PR_OCSP_ENABLED, ocspValue);
         }
         params.add(Constants.PR_EE_ENABLED, value);
         */

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        DBSubsystem dbSubsystem = engine.getDBSubsystem();
        CertificateRepository cr = engine.getCertificateRepository();

        value = caConfig.getString(CertificateAuthority.PROP_ENABLE_PAST_CATIME, "false");
        params.put(Constants.PR_VALIDITY, value);

        getSigningAlgConfig(params);
        getSerialConfig(params);
        getMaxSerialConfig(params);
        params.put(Constants.PR_SN_MANAGEMENT,
            Boolean.toString(dbSubsystem.getEnableSerialMgmt()));
        params.put(Constants.PR_RANDOM_SN, Boolean.toString(cr.getEnableRandomSerialNumbers()));

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getSigningAlgConfig(NameValuePairs params) {

        CAEngine engine = (CAEngine) getCMSEngine();
        CertificateAuthority ca = engine.getCA();

        params.put(Constants.PR_DEFAULT_ALGORITHM,
                ca.getDefaultAlgorithm());
        String[] algorithms = ca.getCASigningAlgorithms();
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
        CAEngine engine = (CAEngine) getCMSEngine();
        params.put(Constants.PR_SERIAL, engine.getStartSerial());
    }

    private void getMaxSerialConfig(NameValuePairs params) {
        CAEngine engine = (CAEngine) getCMSEngine();
        params.put(Constants.PR_MAXSERIAL, engine.getMaxSerial());
    }

    private void setGeneralConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        /*
         Subsystem eeGateway =
         SubsystemRegistry.getInstance().get("eeGateway");
         */

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig engineConfig = engine.getConfig();
        CAConfig caConfig = engineConfig.getCAConfig();

        DBSubsystem dbSubsystem = engine.getDBSubsystem();
        CertificateRepository cr = engine.getCertificateRepository();

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
                engine.setEnablePastCATime(value);
                caConfig.putString(CertificateAuthority.PROP_ENABLE_PAST_CATIME, value);

            } else if (key.equals(Constants.PR_DEFAULT_ALGORITHM)) {
                CertificateAuthority ca = engine.getCA();
                ca.setDefaultAlgorithm(value);

            } else if (key.equals(Constants.PR_SERIAL)) {
                engine.setStartSerial(value);

            } else if (key.equals(Constants.PR_MAXSERIAL)) {
                engine.setMaxSerial(value);

            } else if (key.equals(Constants.PR_SN_MANAGEMENT)) {
                dbSubsystem.setEnableSerialMgmt(Boolean.valueOf(value));
            } else if (key.equals(Constants.PR_RANDOM_SN)) {
                cr.setEnableRandomSerialNumbers(Boolean.valueOf(value), true, false);
            }
        }

        commit(true);
        if (restart)
            sendResponse(RESTART, null, null, resp);
        else
            sendResponse(SUCCESS, null, null, resp);
    }
}
