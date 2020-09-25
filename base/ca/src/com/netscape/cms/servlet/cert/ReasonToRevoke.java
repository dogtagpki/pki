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

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * Specify the RevocationReason when revoking a certificate
 *
 * @version $Revision$, $Date$
 */
public class ReasonToRevoke extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -8447580860330758660L;
    private final static String TPL_FILE = "reasonToRevoke.template";
    private final static String INFO = "ReasonToRevoke";

    private ICertificateRepository mCertDB = null;
    private String mFormPath = null;
    private ICertificateAuthority mCA = null;
    private SecureRandom mRandom = null;
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

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mAuthority instanceof ICertificateAuthority) {
            mCA = (ICertificateAuthority) mAuthority;
            mCertDB = ((ICertificateAuthority) mAuthority).getCertificateRepository();
        }

        if (mCA != null && mCA.noncesEnabled()) {
            mRandom = jssSubsystem.getRandomNumberGenerator();
        }

        mTemplates.remove(ICMSRequest.SUCCESS);
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
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
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
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        ArgBlock header = new ArgBlock();
        ArgBlock ctx = new ArgBlock();
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
            logger.warn(CMS.getLogMessage("CMSGW_INVALID_RECORD_COUNT_FORMAT"), e);
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"), e);
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
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
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

        try {
            if (mCA != null) {
                X509CertImpl caCert = mCA.getSigningUnit().getCertImpl();

                if (isCertFromCA(caCert)) {
                    header.addStringValue("caSerialNumber",
                            caCert.getSerialNumber().toString(16));
                }
            }

            /**
             * ICertRecordList list = mCertDB.findCertRecordsInList(
             * revokeAll, null, totalRecordCount);
             * Enumeration e = list.getCertRecords(0, totalRecordCount - 1);
             **/
            Enumeration<ICertRecord> e = mCertDB.searchCertificates(revokeAll,
                    totalRecordCount, mTimeLimits);

            ArrayList<String> noncesList = new ArrayList<String>();
            int count = 0;

            while (e != null && e.hasMoreElements()) {
                ICertRecord rec = e.nextElement();

                if (rec == null)
                    continue;
                X509CertImpl xcert = rec.getCertificate();

                if (xcert != null)

                    if (mCA != null && mCA.noncesEnabled()) {
                        // generate nonce
                        long n = mRandom.nextLong();
                        // store nonce in session
                        Map<Object, Long> nonces = mCA.getNonces(req, "cert-revoke");
                        nonces.put(xcert.getSerialNumber(), n);
                        // store serial number and nonce
                        noncesList.add(xcert.getSerialNumber()+":"+n);
                    }

                    if (!(rec.getStatus().equals(ICertRecord.STATUS_REVOKED))) {
                        count++;
                        ArgBlock rarg = new ArgBlock();

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

            if (mCA != null && mCA.noncesEnabled()) {
                // return serial numbers and nonces to client
                header.addStringValue("nonce", StringUtils.join(noncesList.toArray(), ","));
            }

        } catch (EBaseException e) {
            logger.error("ReasonToRevoke: " + e.getMessage(), e);
            throw e;
        }
    }
}
