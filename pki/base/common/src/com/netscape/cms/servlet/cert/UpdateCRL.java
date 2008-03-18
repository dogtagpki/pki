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
package com.netscape.cms.servlet.cert;


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.base.*;

import com.netscape.cms.servlet.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.publish.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;


/**
 * Force the CRL to be updated now.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class UpdateCRL extends CMSServlet {

    private final static String INFO = "UpdateCRL";
    private final static String TPL_FILE = "updateCRL.template";

    private String mFormPath = null;
    private ICertificateAuthority mCA = null;

    /**
     * Constructs UpdateCRL servlet.
     */
    public UpdateCRL() {
        super();
    }

    /**
     * Initializes the servlet. This servlet uses updateCRL.template
     * to render the result
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mAuthority instanceof ICertificateAuthority)
            mCA = (ICertificateAuthority) mAuthority;
		
            // override success to do output orw own template.
        mTemplates.remove(CMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request. 
     * <ul>
     * <li>http.param signatureAlgorithm the algorithm to use to sign the CRL
	 * <li>http.param waitForUpdate true/false - should the servlet wait until
	 *     the CRL update is complete?
     * <li>http.param clearCRLCache true/false - should the CRL cache cleared
     *     before the CRL is generated?
     * <li>http.param crlIssuingPoint the CRL Issuing Point to Update
     * </ul>
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IStatsSubsystem statsSub = (IStatsSubsystem)CMS.getSubsystem("stats");
        if (statsSub != null) {
          statsSub.startTiming("crl", true /* main action */);
        }

        long startTime = CMS.getCurrentDate().getTime();
        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "update");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            if (statsSub != null) {
              statsSub.endTiming("crl");
            }
            return;
        }

        EBaseException error = null;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            if (statsSub != null) {
              statsSub.endTiming("crl");
            }
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            String signatureAlgorithm = 
                req.getParameter("signatureAlgorithm");

            process(argSet, header, req, resp, 
                signatureAlgorithm, locale[0]);
        } catch (EBaseException e) {
            error = e;
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  resp.setContentType("text/html");
                  form.renderOutput(out, argSet);
                  cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE",
                    e.toString()));
            if (statsSub != null) {
              statsSub.endTiming("crl");
            }
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        if (statsSub != null) {
          statsSub.endTiming("crl");
        }
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
        HttpServletRequest req,
        HttpServletResponse resp,
        String signatureAlgorithm,
        Locale locale)
        throws EBaseException {
        long startTime = CMS.getCurrentDate().getTime();
        String waitForUpdate = 
            req.getParameter("waitForUpdate");
        String clearCache = 
            req.getParameter("clearCRLCache");
        String crlIssuingPointId = 
            req.getParameter("crlIssuingPoint");

        if (crlIssuingPointId != null) {
            Enumeration ips = mCA.getCRLIssuingPoints();

            while (ips.hasMoreElements()) {
                ICRLIssuingPoint ip = (ICRLIssuingPoint) ips.nextElement();

                if (crlIssuingPointId.equals(ip.getId())) {
                    break;
                }
                if (!ips.hasMoreElements()) crlIssuingPointId = null;
            }
        }
        if (crlIssuingPointId == null) {
            crlIssuingPointId = mCA.PROP_MASTER_CRL;
        }

        ICRLIssuingPoint crlIssuingPoint = 
            mCA.getCRLIssuingPoint(crlIssuingPointId);
        header.addStringValue("crlIssuingPoint", crlIssuingPointId);
        IPublisherProcessor lpm = mCA.getPublisherProcessor();

        if (crlIssuingPoint != null) {
            if (clearCache != null && clearCache.equals("true") &&
                crlIssuingPoint.isCRLGenerationEnabled() &&
                crlIssuingPoint.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_UPDATE_DONE &&
                crlIssuingPoint.isCRLIssuingPointInitialized()
                                == ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                crlIssuingPoint.clearCRLCache();
            }
            if (waitForUpdate != null && waitForUpdate.equals("true") &&
                crlIssuingPoint.isCRLGenerationEnabled() &&
                crlIssuingPoint.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_UPDATE_DONE &&
                crlIssuingPoint.isCRLIssuingPointInitialized()
                                == ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                try {
                    EBaseException publishError = null;

                    try {
                        long now1 = System.currentTimeMillis();

                        if (signatureAlgorithm != null) {
                            crlIssuingPoint.updateCRLNow(signatureAlgorithm);
                        } else {
                            crlIssuingPoint.updateCRLNow();
                        }

                        long now2 = System.currentTimeMillis();

                        header.addStringValue("time", "" + (now2 - now1));
                    } catch (EErrorPublishCRL e) {
                        publishError = e;
                    }

                    if (lpm != null && lpm.enabled()) {
                        if (publishError != null) {
                            header.addStringValue("crlPublished", "Failure");
                            header.addStringValue("error", 
                                publishError.toString(locale));
                        } else {
                            header.addStringValue("crlPublished", "Success");
                        }
                    }

                    // for audit log
                    SessionContext sContext = SessionContext.getContext();
                    String agentId = (String) sContext.get(SessionContext.USER_ID);
                    IAuthToken authToken = 
                        (IAuthToken) sContext.get(SessionContext.AUTH_TOKEN);
                    String authMgr = AuditFormat.NOAUTH;
        
                    if (authToken != null) {
                        authMgr =
                                authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
                    }
                    long endTime = CMS.getCurrentDate().getTime();

                    if (crlIssuingPoint.getNextUpdate() != null) {
                        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER, 
                            AuditFormat.LEVEL,
                            AuditFormat.CRLUPDATEFORMAT,
                            new Object[] { 
                                AuditFormat.FROMAGENT + " agentID: " + agentId,
                                authMgr,
                                "completed",
                                crlIssuingPoint.getId(),
                                crlIssuingPoint.getCRLNumber(),
                                crlIssuingPoint.getLastUpdate(),
                                crlIssuingPoint.getNextUpdate(),
                                Long.toString(crlIssuingPoint.getCRLSize()) + " time: " + (endTime - startTime)}
                        );
                    }else {
                        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER, 
                            AuditFormat.LEVEL,
                            AuditFormat.CRLUPDATEFORMAT,
                            new Object[] { 
                                AuditFormat.FROMAGENT + " agentID: " + agentId,
                                authMgr,
                                "completed",
                                crlIssuingPoint.getId(),
                                crlIssuingPoint.getCRLNumber(),
                                crlIssuingPoint.getLastUpdate(),
                                "not set",
                                Long.toString(crlIssuingPoint.getCRLSize()) + " time: " + (endTime - startTime)}
                        );
                    }
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_UPDATE_CRL", e.toString()));
                    if ((lpm != null) && lpm.enabled() && (e instanceof ELdapException)) {
                        header.addStringValue("crlPublished", "Failure");
                        header.addStringValue("error", e.toString(locale));
                    } else {
                        throw e;
                    }
                }
            } else {
                if (crlIssuingPoint.isCRLIssuingPointInitialized()
                           != ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                    header.addStringValue("crlUpdate", "notInitialized");
                } else if (crlIssuingPoint.isCRLUpdateInProgress()
                           != ICRLIssuingPoint.CRL_UPDATE_DONE ||
                           crlIssuingPoint.isManualUpdateSet()) {
                    header.addStringValue("crlUpdate", "inProgress");
                } else if (!crlIssuingPoint.isCRLGenerationEnabled()) {
                    header.addStringValue("crlUpdate", "Disabled");
                } else {
                    crlIssuingPoint.setManualUpdate(signatureAlgorithm);
                    header.addStringValue("crlUpdate", "Scheduled");
                }
            }
        }
        return;
    }
}
