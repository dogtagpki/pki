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
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
 
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
 * View the Key Recovery Request 
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ExamineRecovery extends CMSServlet {

    private final static String INFO = "examineRecovery";
    private final static String TPL_FILE = "examineRecovery.template";

    private final static String IN_SERIALNO = "serialNumber";
    private final static String IN_UID = "uid";
    private final static String IN_PWD = "pwd";
    private final static String IN_PASSWORD = "p12Password";
    private final static String IN_DELIVERY = "p12Delivery";
    private final static String IN_CERT = "cert";

    private final static String OUT_OP = "op";
    private final static String OUT_SERIALNO = IN_SERIALNO;
    private final static String OUT_RECOVERY_SUCCESS = "recoverySuccess";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_ERROR = "errorDetails";

    private IKeyService mService = null;
    private String mFormPath = null;

    /**
     * Constructs EA servlet.
     */
    public ExamineRecovery() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mService = (IKeyService) mAuthority;
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

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
     * <li>http.param recoveryID recovery request ID
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
                        mAuthzResourceName, "read");
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

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);
        int seq = -1;

        EBaseException error = null;

        try {
            process(argSet, header, 
                req.getParameter("recoveryID"),
                req, resp, locale[0]);
        } catch (EBaseException e) {
            error = e;
        } catch (Exception e) {
            error = new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        /*
         catch (NumberFormatException e) {
         error = eBaseException(
         
         header.addStringValue(OUT_ERROR,
         MessageFormatter.getLocalizedString(
         locale[0],
         BaseResources.class.getName(),
         BaseResources.INTERNAL_ERROR_1,
         e.toString()));
         }
         */

        try {
            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  ServletOutputStream out = resp.getOutputStream();
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
                CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    /**
     * Recovers a key. The p12 will be protected by the password
     * provided by the administrator.
     */
    private void process(CMSTemplateParams argSet,
        IArgBlock header, String recoveryID,
        HttpServletRequest req, HttpServletResponse resp,
        Locale locale) 
        throws EBaseException {
        try {
            header.addStringValue(OUT_OP,
                req.getParameter(OUT_OP));
            header.addStringValue(OUT_SERVICE_URL,
                req.getRequestURI());
            header.addStringValue("keySplitting",
                CMS.getConfigStore().getString("kra.keySplitting"));
            Hashtable params = mService.getRecoveryParams(
                    recoveryID);

            if (params == null) {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("CMSGW_NO_RECOVERY_TOKEN_FOUND_1", recoveryID));
                throw new ECMSGWException(
                  CMS.getUserMessage("CMS_GW_NO_RECOVERY_TOKEN_FOUND", recoveryID));
            }
            String keyID = (String)params.get("keyID");
            header.addStringValue("serialNumber", keyID); 
            header.addStringValue("recoveryID", recoveryID);

            IKeyRepository mKeyDB = 
              ((IKeyRecoveryAuthority) mAuthority).getKeyRepository();
            IKeyRecord rec = (IKeyRecord) mKeyDB.readKeyRecord(new
                    BigInteger(keyID));
            KeyRecordParser.fillRecordIntoArg(rec, header);
                                                                                

        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, "Error e " + e);
            throw e;
        } 

        /*
         catch (Exception e) {
         header.addStringValue(OUT_ERROR, e.toString());
         }
         */
    }
}
