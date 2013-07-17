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
// (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.key;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Approve an asynchronous key recovery request
 *
 */
public class GrantAsyncRecovery extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -4200111795169532676L;
    private final static String INFO = "grantAsyncRecovery";
    private final static String TPL_FILE = "grantAsyncRecovery.template";

    private final static String OUT_OP = "op";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_ERROR = "errorDetails";

    private IKeyService mService = null;
    private String mFormPath = null;

    private final static String LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN_4";

    /**
     * Constructs EA servlet.
     */
    public GrantAsyncRecovery() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * 'grantAsyncRecovery.template' to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mService = (IKeyService) mAuthority;

        mTemplates.remove(ICMSRequest.SUCCESS);

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param reqID request ID of the request to approve
     * <li>http.param agentID User ID of the agent approving the request
     *
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        CMS.debug("GrantAsyncRecovery: process() begins");

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "recover");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String agentID = authToken.getInString("uid");
        CMS.debug("GrantAsyncRecovery: process() agent uid=" + agentID);
        CMS.debug("GrantAsyncRecovery: process() request id=" + req.getParameter("reqID"));
        try {
            process(argSet, header,
                    req.getParameter("reqID"),
                    agentID,
                    req, resp, locale[0]);
        } catch (NumberFormatException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        }
        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
    }

    /**
     * Update agent approval list
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN used whenever DRM agents login as recovery agents
     * to approve key recovery requests
     * </ul>
     *
     * @param argSet CMS template parameters
     * @param header argument block
     * @param reqID string containing the recovery request ID
     * @param agentID string containing the agent ID
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param locale the system locale
     */
    private void process(CMSTemplateParams argSet,
            IArgBlock header, String reqID,
            String agentID,
            HttpServletRequest req, HttpServletResponse resp,
            Locale locale) {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequestID = reqID;
        String auditAgentID = agentID;

        // "normalize" the "reqID"
        if (auditRequestID != null) {
            auditRequestID = auditRequestID.trim();

            if (auditRequestID.equals("")) {
                auditRequestID = ILogger.UNIDENTIFIED;
            }
        } else {
            auditRequestID = ILogger.UNIDENTIFIED;
        }

        // "normalize" the "auditAgentID"
        if (auditAgentID != null) {
            auditAgentID = auditAgentID.trim();

            if (auditAgentID.equals("")) {
                auditAgentID = ILogger.UNIDENTIFIED;
            }
        } else {
            auditAgentID = ILogger.UNIDENTIFIED;
        }

        try {
            header.addStringValue(OUT_OP,
                    req.getParameter(OUT_OP));
            header.addStringValue(OUT_SERVICE_URL,
                    req.getRequestURI());

            // update approving agent list
            mService.addAgentAsyncKeyRecovery(reqID, agentID);

            header.addStringValue("requestID", reqID);
            header.addStringValue("agentID", agentID);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequestID,
                        auditAgentID);

            audit(auditMessage);

        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale));

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        auditAgentID);

            audit(auditMessage);
        } catch (Exception e) {
            header.addStringValue(OUT_ERROR, e.toString());

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        auditAgentID);

            audit(auditMessage);
        }
    }
}
