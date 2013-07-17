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
package com.netscape.cms.servlet.ocsp;

import java.io.IOException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmsutil.util.Cert;

/**
 * Check the status of a specific certificate
 *
 * @version $Revision$ $Date$
 */
public class CheckCertServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 7782198059640825050L;
    public static final String BEGIN_HEADER =
            "-----BEGIN CERTIFICATE-----";
    public static final String END_HEADER =
            "-----END CERTIFICATE-----";

    public static final String ATTR_STATUS = "status";
    public static final String ATTR_ISSUERDN = "issuerDN";
    public static final String ATTR_SUBJECTDN = "subjectDN";
    public static final String ATTR_SERIALNO = "serialno";

    public static final String STATUS_GOOD = "good";
    public static final String STATUS_REVOKED = "revoked";
    public static final String STATUS_UNKNOWN = "unknown";

    private final static String TPL_FILE = "checkCert.template";
    private String mFormPath = null;
    private IOCSPAuthority mOCSPAuthority = null;

    public CheckCertServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "checkCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to display own output.

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mTemplates.remove(ICMSRequest.SUCCESS);
        mOCSPAuthority = (IOCSPAuthority) mAuthority;
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param cert certificate to check. Base64, DER encoded, wrapped in -----BEGIN CERTIFICATE-----, -----END
     * CERTIFICATE----- strings
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "validate");
        } catch (Exception e) {
            // do nothing for now
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

        IDefStore defStore = mOCSPAuthority.getDefaultStore();

        String b64 = cmsReq.getHttpReq().getParameter("cert");

        if (b64.indexOf(BEGIN_HEADER) == -1) {
            // error
            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CERT_HEADER"));

        }
        if (b64.indexOf(END_HEADER) == -1) {
            // error
            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CERT_FOOTER"));
        }

        X509Certificate cert = null;

        try {
            cert = Cert.mapCert(b64);
        } catch (Exception e) {
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DECODING_CERT_ERROR"));
        }
        if (cert == null) {
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DECODING_CERT_ERROR"));
        }

        ICRLIssuingPointRecord pt = defStore.readCRLIssuingPoint(
                cert.getIssuerDN().getName());

        header.addStringValue(ATTR_ISSUERDN, cert.getIssuerDN().getName());
        header.addStringValue(ATTR_SUBJECTDN, cert.getSubjectDN().getName());
        header.addStringValue(ATTR_SERIALNO, "0x" + cert.getSerialNumber().toString(16));
        try {
            X509CRLImpl crl = null;

            crl = new X509CRLImpl(pt.getCRL());
            X509CRLEntry crlentry = crl.getRevokedCertificate(cert.getSerialNumber());

            if (crlentry == null) {
                if (defStore.isNotFoundGood()) {
                    header.addStringValue(ATTR_STATUS, STATUS_GOOD);
                } else {
                    header.addStringValue(ATTR_STATUS, STATUS_UNKNOWN);
                }
            } else {
                header.addStringValue(ATTR_STATUS, STATUS_REVOKED);
            }
        } catch (Exception e) {
            header.addStringValue(ATTR_STATUS, STATUS_UNKNOWN);
        }
        log(ILogger.EV_AUDIT, AuditFormat.LEVEL, "Checked Certificate Status "
                + cert.getIssuerDN().getName() + " " + cert.getSerialNumber().toString());

        try {
            ServletOutputStream out = resp.getOutputStream();

            String xmlOutput = req.getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                outputXML(resp, argSet);
            } else {
                resp.setContentType("text/html");
                form.renderOutput(out, argSet);
                cmsReq.setStatus(ICMSRequest.SUCCESS);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }
}
