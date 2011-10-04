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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;

import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.base.*;
 
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.keydb.*;

import com.netscape.cms.servlet.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.kra.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;


/**
 * Get the recovered key in PKCS#12 format
 *
 * @version $Revision$, $Date$
 */
public class GetPk12 extends CMSServlet {

    private final static String INFO = "getPk12";

    private final static String TPL_FILE = "finishRecovery.template";

    private final static String OUT_RECOVERY_SUCCESS = "recoverySuccess";
    private final static String OUT_ERROR = "errorDetails";

    private com.netscape.certsrv.kra.IKeyService mService = null;
    private final static String OUT_STATUS = "status";

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
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/agent/" + mAuthority.getId() + "/" + TPL_FILE;
        mService = (com.netscape.certsrv.kra.IKeyService) mAuthority;

        mTemplates.remove(CMSRequest.SUCCESS);
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
     * <li>http.param recoveryID ID of request to recover
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "download");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
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
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);
        int seq = -1;

        // get status and populate argSet
        try {
            String recoveryID = req.getParameter("recoveryID");

            header.addStringValue("recoveryID", recoveryID);

            Hashtable params = mService.getRecoveryParams(recoveryID);

            if (params == null) {
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_NO_RECOVERY_TOKEN_FOUND_1", recoveryID));
                throw new ECMSGWException(
                  CMS.getUserMessage("CMS_GW_NO_RECOVERY_TOKEN_FOUND", recoveryID));
            }

            // only the init DRM agent can get the pkcs12
            SessionContext sContext = SessionContext.getContext();
            String agent = null;

            if (sContext != null) {
                agent = (String) sContext.get(SessionContext.USER_ID);
            }

            if (agent == null ) {
                CMS.debug( "GetPk12::process() - agent is null!" );
                throw new EBaseException( "agent is null" );
            }

            String initAgent = (String) params.get("agent");     

            if (!agent.equals(initAgent)) {
                log(ILogger.LL_SECURITY,
                    
                    CMS.getLogMessage("CMSGW_INVALID_AGENT_3",
                        recoveryID,
                        initAgent));
                throw new ECMSGWException(
                  CMS.getUserMessage("CMS_GW_INVALID_AGENT",
                            agent, initAgent, recoveryID));
            }

            header.addStringValue("serialNumber",
                (String) params.get("keyID"));

            // got all approval, return pk12
            byte pkcs12[] = ((IKeyRecoveryAuthority) mService).getPk12(recoveryID);

            if (pkcs12 != null) {
                mService.destroyRecoveryParams(recoveryID);
                try {
                    resp.setContentType("application/x-pkcs12");
                    resp.getOutputStream().write(pkcs12);
                    mRenderResult = false;
                    return;
                } catch (IOException e) {
                    header.addStringValue(OUT_ERROR,
                        CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
                }
            } else if (((IKeyRecoveryAuthority) mService).getError(recoveryID) != null) {
                // error in recovery process 
                header.addStringValue(OUT_ERROR, 
                    ((IKeyRecoveryAuthority) mService).getError(recoveryID));
            } else {
                // pk12 hasn't been created yet. Shouldn't get here
            }
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale[0]));
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

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }
}
