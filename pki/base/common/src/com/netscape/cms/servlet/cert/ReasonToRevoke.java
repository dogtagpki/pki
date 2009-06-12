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
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.cms.servlet.*;


/**
 * Specify the RevocationReason when revoking a certificate
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ReasonToRevoke extends CMSServlet {

    private final static String TPL_FILE = "reasonToRevoke.template";
    private final static String INFO = "ReasonToRevoke";

    private ICertificateRepository mCertDB = null;
    private String mFormPath = null;
    private ICertificateAuthority mCA = null;
    private Random mRandom = null;
    private Nonces mNonces = null;
    private int mTimeLimits = 30; /* in seconds */

    public ReasonToRevoke() {
        super();
    }

    /**
	 * initialize the servlet. This servlet uses the template file
	 * 'reasonToRevoke.template' to render the response
 	 *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mAuthority instanceof ICertificateAuthority) {
            mCA = (ICertificateAuthority) mAuthority;
            mCertDB = ((ICertificateAuthority) mAuthority).getCertificateRepository();
        }

        if (mCA != null && mCA.noncesEnabled()) {
            mRandom = new Random();
            mNonces = mCA.getNonces();
        }

        mTemplates.remove(CMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        /* Server-Side time limit */
        try {
            mTimeLimits = Integer.parseInt(sc.getInitParameter("timeLimits"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() { 
        return INFO; 
    }

    /**
     * Process the HTTP request. 
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
                        mAuthzResourceName, "revoke");
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

        String revokeAll = null;
        int totalRecordCount = 1;
        EBaseException error = null;

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
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        try {
            if (req.getParameter("totalRecordCount") != null) {
                totalRecordCount = 
                        Integer.parseInt(req.getParameter("totalRecordCount"));
            }

            revokeAll = req.getParameter("revokeAll");

            process(argSet, header, req, resp, 
                revokeAll, totalRecordCount, locale[0]);
        } catch (EBaseException e) {
            error = e;
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_RECORD_COUNT_FORMAT"));
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"));
        } 

        /*
         catch (Exception e) {
         noError = false;
         header.addStringValue(OUT_ERROR,
         MessageFormatter.getLocalizedString(
         errorlocale[0],
         BaseResources.class.getName(),
         BaseResources.INTERNAL_ERROR_1,
         e.toString()));
         }
         */

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
                CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
        HttpServletRequest req,
        HttpServletResponse resp,
        String revokeAll, int totalRecordCount,
        Locale locale) 
        throws EBaseException {

        header.addStringValue("revokeAll", revokeAll);
        header.addIntegerValue("totalRecordCount", totalRecordCount);

        if (mNonces != null) {
            long n = mRandom.nextLong();
            long m = mNonces.addNonce(n, getSSLClientCertificate(req));
            if ((n + m) != 0) {
                header.addStringValue("nonce", Long.toString(m));
            }
        }

        try {
            if (mCA != null) {
                X509CertImpl caCert = mCA.getSigningUnit().getCertImpl();

                //if (isCertFromCA(caCert)) 
                header.addStringValue("caSerialNumber",
                    caCert.getSerialNumber().toString(16));
            }

            /**
             ICertRecordList list = mCertDB.findCertRecordsInList(
             revokeAll, null, totalRecordCount);
             Enumeration e = list.getCertRecords(0, totalRecordCount - 1);
             **/
            Enumeration e = mCertDB.searchCertificates(revokeAll,
                    totalRecordCount, mTimeLimits);

            int count = 0;
            String errorMsg = null;

            while (e != null && e.hasMoreElements()) {
                ICertRecord rec = (ICertRecord) e.nextElement();

                if (rec == null)
                    continue;
                X509CertImpl xcert = rec.getCertificate();

                if (xcert != null)
                    if (!(rec.getStatus().equals(ICertRecord.STATUS_REVOKED))) {
                        count++;
                        IArgBlock rarg = CMS.createArgBlock();

                        rarg.addStringValue("serialNumber", 
                            xcert.getSerialNumber().toString(16));
                        rarg.addStringValue("serialNumberDecimal", 
                            xcert.getSerialNumber().toString());
                        rarg.addStringValue("subject", 
                            xcert.getSubjectDN().toString());
                        rarg.addLongValue("validNotBefore", 
                            xcert.getNotBefore().getTime() / 1000);
                        rarg.addLongValue("validNotAfter", 
                            xcert.getNotAfter().getTime() / 1000);
                        argSet.addRepeatRecord(rarg);
                    }
            }

            header.addIntegerValue("verifiedRecordCount", count);

        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, "Error " + e);
            throw e;
        }
        return;
    }
}

