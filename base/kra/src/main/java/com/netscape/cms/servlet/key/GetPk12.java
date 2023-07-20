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
package com.netscape.cms.servlet.key;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.kra.KRAEngine;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * Get the recovered key in PKCS#12 format
 */
@WebServlet(
        name = "kraKRAGetPk12",
        urlPatterns = "/agent/kra/getPk12",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="ID",            value="kraKRAGetPk12"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.kra.key")
        }
)
public class GetPk12 extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetPk12.class);
    private static final long serialVersionUID = 8974964964333880697L;

    private final static String INFO = "getPk12";

    private final static String TPL_FILE = "finishRecovery.template";

    private final static String OUT_ERROR = "errorDetails";

    private KeyRecoveryAuthority mService;

    private String mFormPath = null;

    /**
     * Constructs getPk12 servlet.
     */
    public GetPk12() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "finishRecovery.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/agent/kra/" + TPL_FILE;
        KRAEngine engine = KRAEngine.getInstance();
        mService = engine.getKRA();

        mTemplates.remove(CMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param recoveryID ID of request to recover
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String recoveryID = null;
        String agent = null;

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "download");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        // get status and populate argSet
        try {
            recoveryID = req.getParameter("recoveryID");

            header.addStringValue("recoveryID", recoveryID);

            Hashtable<String, Object> params = mService.getRecoveryParams(recoveryID);

            if (params == null) {
                logger.error(CMS.getLogMessage("CMSGW_NO_RECOVERY_TOKEN_FOUND_1", recoveryID));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_RECOVERY_TOKEN_FOUND", recoveryID));
            }

            // only the init DRM agent can get the pkcs12
            SessionContext sContext = SessionContext.getContext();
            if (sContext != null) {
                agent = (String) sContext.get(SessionContext.USER_ID);
            }

            if (agent == null) {
                logger.error("GetPk12::process() - agent is null!");
                throw new EBaseException("agent is null");
            }

            String initAgent = (String) params.get("agent");

            if (!agent.equals(initAgent)) {
                logger.error(CMS.getLogMessage("CMSGW_INVALID_AGENT_3", recoveryID, initAgent));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_AGENT", agent, initAgent, recoveryID));
            }

            header.addStringValue("serialNumber",
                    (String) params.get("keyID"));

            // got all approval, return pk12
            byte pkcs12[] = mService.getPk12(recoveryID);

            if (pkcs12 != null) {
                mService.destroyRecoveryParams(recoveryID);
                try {
                    resp.setContentType("application/x-pkcs12");
                    resp.getOutputStream().write(pkcs12);
                    mRenderResult = false;

                    auditor.log(new SecurityDataExportEvent(
                            agent,
                            ILogger.SUCCESS,
                            new RequestId(recoveryID),
                            null,
                            null,
                            null));
                    return;
                } catch (IOException e) {
                    header.addStringValue(OUT_ERROR,
                            CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
                }
            } else if (mService.getError(recoveryID) != null) {
                // error in recovery process
                header.addStringValue(OUT_ERROR,
                        mService.getError(recoveryID));
            } else {
                // pk12 hasn't been created yet. Shouldn't get here
            }
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale[0]));
        }

        if ((agent != null) && (recoveryID != null)) {
            auditor.log(new SecurityDataExportEvent(
                    agent,
                    ILogger.FAILURE,
                    new RequestId(recoveryID),
                    null,
                    null,
                    null));
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }
}
