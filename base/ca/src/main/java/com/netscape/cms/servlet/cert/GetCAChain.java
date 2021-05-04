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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.cert.CertUtils;

/**
 * Retrieve the Certificates comprising the CA Chain for this CA.
 *
 * @version $Revision$, $Date$
 */
public class GetCAChain extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetCAChain.class);

    private static final long serialVersionUID = -8189048155415074581L;
    private final static String TPL_FILE = "displayCaCert.template";
    private String mFormPath = null;

    public GetCAChain() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        // override success to display own output.
        mTemplates.remove(ICMSRequest.SUCCESS);
        // coming from ee
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        // Construct an ArgBlock
        IArgBlock args = cmsReq.getHttpParams();

        // Get the operation code
        String op = null;

        op = args.getValueAsString("op", null);
        if (op == null) {
            logger.error(CMS.getLogMessage("CMSGW_NO_OPTIONS_SELECTED"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_OPTIONS_SELECTED"));
        }

        cmsReq.setStatus(ICMSRequest.SUCCESS);

        AuthzToken authzToken = null;

        if (op.startsWith("download")) {
            try {
                authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "download");
            } catch (EAuthzAccessDenied e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            }

            if (authzToken == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                return;
            }

            downloadChain(op, args, httpReq, httpResp, cmsReq);
        } else if (op.startsWith("display")) {
            try {
                authzToken = mAuthz.authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
            } catch (EAuthzAccessDenied e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            }

            if (authzToken == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                return;
            }

            displayChain(op, args, httpReq, httpResp, cmsReq);
        } else {
            logger.error(CMS.getLogMessage("CMSGW_INVALID_OPTIONS_CA_CHAIN"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_OPTIONS_SELECTED"));
        }
        //		cmsReq.setResult(null);
        return;
    }

    private void downloadChain(String op,
            IArgBlock args,
            HttpServletRequest httpReq,
            HttpServletResponse httpResp,
            CMSRequest cmsReq)
            throws EBaseException {

        /* check browser info ? */

        /* check if pkcs7 will work for both nav and ie */

        byte[] bytes = null;

        /*
         * Some IE actions - IE doesn't want PKCS7 for "download" CA Cert.
         * This means that we can only hand out the root CA, and not
         * the whole chain.
         */

        if (clientIsMSIE(httpReq) && (op.equals("download") || op.equals("downloadBIN"))) {
            X509Certificate[] caCerts =
                    ((ICertAuthority) mAuthority).getCACertChain().getChain();

            try {
                bytes = caCerts[0].getEncoded();
            } catch (CertificateEncodingException e) {
                cmsReq.setStatus(ICMSRequest.ERROR);
                logger.error(CMS.getLogMessage("CMSGW_ERROR_GETTING_CACERT_ENCODED", e.toString()), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_GETTING_CA_CERT_ERROR"), e);
            }
        } else {
            CertificateChain certChain =
                    ((ICertAuthority) mAuthority).getCACertChain();

            if (certChain == null) {
                logger.error(CMS.getLogMessage("CMSGW_CA_CHAIN_EMPTY"));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CA_CHAIN_EMPTY"));
            }

            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();

                certChain.encode(encoded, false);
                bytes = encoded.toByteArray();
            } catch (IOException e) {
                cmsReq.setStatus(ICMSRequest.ERROR);
                logger.error(CMS.getLogMessage("CMSGW_ERROR_ENCODING_CA_CHAIN_1", e.toString()), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ENCODING_CA_CHAIN_ERROR"), e);
            }
        }

        String mimeType = null;

        if (op.equals("downloadBIN")) {
            mimeType = "application/octet-stream";
        } else {
            try {
                mimeType = args.getValueAsString("mimeType");
            } catch (EBaseException e) {
                mimeType = "application/octet-stream";
            }
        }

        try {
            if (op.equals("downloadBIN")) {
                // file suffixes changed to comply with RFC 5280
                // requirements for AIA extensions
                if (clientIsMSIE(httpReq)) {
                    httpResp.setHeader("Content-disposition",
                            "attachment; filename=ca.cer");
                } else {
                    httpResp.setHeader("Content-disposition",
                            "attachment; filename=ca.p7c");
                }
            }
            httpResp.setContentType(mimeType);
            httpResp.getOutputStream().write(bytes);
            httpResp.setContentLength(bytes.length);
            httpResp.getOutputStream().flush();
        } catch (IOException e) {
            cmsReq.setStatus(ICMSRequest.ERROR);
            logger.error(CMS.getLogMessage("CMSGW_ERROR_DISPLAYING_CACHAIN_1", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAYING_CACHAIN_ERROR"), e);
        }
    }

    private void displayChain(String op,
            IArgBlock args,
            HttpServletRequest httpReq,
            HttpServletResponse httpResp,
            CMSRequest cmsReq)
            throws EBaseException {

        CertificateChain certChain =
                ((ICertAuthority) mAuthority).getCACertChain();

        if (certChain == null) {
            cmsReq.setStatus(ICMSRequest.ERROR);
            logger.error(CMS.getLogMessage("CMSGW_CA_CHAIN_NOT_AVAILABLE"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CA_CHAIN_NOT_AVAILABLE"));
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String displayFormat = null;

        if (op.equals("displayIND")) {
            displayFormat = "individual";
        } else {
            try {
                displayFormat = args.getValueAsString("displayFormat");
            } catch (EBaseException e) {
                displayFormat = "chain";
            }
        }

        header.addStringValue("displayFormat", displayFormat);

        if (displayFormat.equals("chain")) {
            String subjectdn = null;
            byte[] bytes = null;

            try {
                subjectdn =
                        certChain.getFirstCertificate().getSubjectDN().toString();
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();

                certChain.encode(encoded);
                bytes = encoded.toByteArray();
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERROR_ENCODING_CA_CHAIN_1", e.toString()), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ENCODING_CA_CHAIN_ERROR"), e);
            }

            String chainBase64 = getBase64(bytes);

            header.addStringValue("subjectdn", subjectdn);
            header.addStringValue("chainBase64", chainBase64);
        } else {
            try {
                X509Certificate[] certs = certChain.getChain();

                header.addIntegerValue("length", certs.length);
                locale[0] = getLocale(httpReq);
                for (int i = 0; i < certs.length; i++) {
                    byte[] bytes = null;

                    try {
                        bytes = certs[i].getEncoded();
                    } catch (CertificateEncodingException e) {
                        throw new IOException("Internal Error");
                    }
                    String subjectdn = certs[i].getSubjectDN().toString();
                    String finger = null;
                    try {
                        finger = CertUtils.getFingerPrints(certs[i]);
                    } catch (Exception e) {
                        throw new IOException("Internal Error");
                    }

                    CertPrettyPrint certDetails = new CertPrettyPrint(certs[i]);

                    ArgBlock rarg = new ArgBlock();

                    rarg.addStringValue("fingerprints", finger);
                    rarg.addStringValue("subjectdn", subjectdn);
                    rarg.addStringValue("base64", getBase64(bytes));
                    rarg.addStringValue("certDetails",
                            certDetails.toString(locale[0]));
                    argSet.addRepeatRecord(rarg);
                }
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERROR_DISPLAYING_CACHAIN_1", e.toString()), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAYING_CACHAIN_ERROR"), e);
            }
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
    }

    /**
     * gets base 64 encoded cert
     */
    private String getBase64(byte[] certBytes) {
        String certBase64 = Utils.base64encode(certBytes, true);

        return certBase64;
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                        UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
