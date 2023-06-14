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
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

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

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.security.Credential;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * Check to see if a Key Recovery Request has been approved
 */
@WebServlet(
        name = "kraGenerateKeyPair",
        urlPatterns = "/agent/kra/getApprovalStatus",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="templatePath",  value="/agent/kra/getApprovalStatus.template"),
                @WebInitParam(name="ID",            value="kraKRAGetApprovalStatus"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.kra.request.status")
        }
)
public class GetApprovalStatus extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -8257339915430654983L;
    private final static String INFO = "getApprovalStatus";
    private final static String TPL_FILE = "getApprovalStatus.template";
    private final static String TPL_FINISH = "finishRecovery.template";

    private final static String OUT_ERROR = "errorDetails";
    private final static String OUT_STATUS = "status";

    private KeyRecoveryAuthority mService;
    private String mFormPath = null;

    /**
     * Constructs getApprovalStatus servlet.
     */
    public GetApprovalStatus() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template files
     * "getApprovalStatus.template" and "finishRecovery.template"
     * to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // mFormPath = "/"+authority.getId()+"/"+TPL_FILE;
        KRAEngine engine = KRAEngine.getInstance();
        mService = engine.getKRA();

        mTemplates.remove(CMSRequest.SUCCESS);
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
     * <li>http.param recoveryID request ID to check
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        cmsReq.setStatus(CMSRequest.SUCCESS);
        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);
        int rComplete = 0;

        // get status and populate argSet
        try {
            String recoveryID = req.getParameter("recoveryID");

            header.addStringValue("recoveryID", recoveryID);

            Hashtable<String, Object> params = mService.getRecoveryParams(recoveryID);

            if (params == null) {
                logger.error(CMS.getLogMessage("CMSGW_NO_RECOVERY_TOKEN_FOUND_1", recoveryID));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_RECOVERY_TOKEN_FOUND", recoveryID));
            }
            header.addStringValue("serialNumber",
                    (String) params.get("keyID"));
            header.addStringValue("serialNumberInHex",
                    new BigInteger((String) params.get("keyID")).toString(16));

            int requiredNumber = mService.getNoOfRequiredAgents();

            header.addIntegerValue("noOfRequiredAgents", requiredNumber);

            Vector<Credential> dc = mService.getAppAgents(recoveryID);
            Enumeration<Credential> agents = dc.elements();

            while (agents.hasMoreElements()) {
                ArgBlock rarg = new ArgBlock();

                rarg.addStringValue("agentName", agents.nextElement().getIdentifier());
                argSet.addRepeatRecord(rarg);
            }
            if (dc.size() >= requiredNumber) {
                // got all approval, return pk12
                byte pkcs12[] = mService.getPk12(recoveryID);

                if (pkcs12 != null) {
                    rComplete = 1;
                    header.addStringValue(OUT_STATUS, "complete");

                    /*
                     mService.destroyRecoveryParams(recoveryID);
                     try {
                     resp.setContentType("application/x-pkcs12");
                     resp.getOutputStream().write(pkcs12);
                     return;
                     } catch (IOException e) {
                     header.addStringValue(OUT_ERROR,
                     MessageFormatter.getLocalizedString(
                     locale[0],
                     BaseResources.class.getName(),
                     BaseResources.INTERNAL_ERROR_1,
                     e.toString()));
                     }
                     */
                } else if (mService.getError(recoveryID) != null) {
                    // error in recovery process
                    header.addStringValue(OUT_ERROR, mService.getError(recoveryID));
                    rComplete = 1;
                } else {
                    // pk12 hasn't been created yet.
                }
            }
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale[0]));
            rComplete = 1;
        }

        try {
            if (rComplete == 1) {
                mFormPath = "/" + ((IAuthority) mService).getId() + "/" + TPL_FINISH;
            } else {
                mFormPath = "/" + ((IAuthority) mService).getId() + "/" + TPL_FILE;
            }
            if (mOutputTemplatePath != null)
                mFormPath = mOutputTemplatePath;
            try {
                form = getTemplate(mFormPath, req, locale);
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
            }

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
