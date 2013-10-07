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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Retrieve certificate by serial number.
 *
 * @version $Revision$, $Date$
 */
public class GetBySerial extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -2276677839178370838L;

    private final static String IMPORT_CERT_TEMPLATE = "ImportCert.template";
    private String mImportTemplate = null;
    private String mIETemplate = null;
    private ICMSTemplateFiller mImportTemplateFiller = null;
    IRequestQueue mReqQ = null;

    public GetBySerial() {
        super();
    }

    /**
     * Initialize the servlet. This servlet uses the template file
     * "ImportCert.template" to import the cert to the users browser,
     * if that is what the user requested
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        try {
            mImportTemplate = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            mIETemplate = sc.getInitParameter("importCertTemplate");
            if (mImportTemplate == null)
                mImportTemplate = IMPORT_CERT_TEMPLATE;
        } catch (Exception e) {
            mImportTemplate = null;
        }
        mImportTemplateFiller = new ImportCertsTemplateFiller();

        // override success and error templates to null -
        // handle templates locally.
        mTemplates.remove(ICMSRequest.SUCCESS);

        ICertificateAuthority mCa = (ICertificateAuthority) CMS.getSubsystem("ca");
        if (mCa == null) {
            return;
        }

        mReqQ = mCa.getRequestQueue();
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param serialNumber serial number of certificate in HEX
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();
        IArgBlock args = cmsReq.getHttpParams();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "import");
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

        String serial = args.getValueAsString("serialNumber", null);
        String browser = args.getValueAsString("browser", null);
        BigInteger serialNo = null;

        try {
            serialNo = new BigInteger(serial, 16);
        } catch (NumberFormatException e) {
            serialNo = null;
        }
        if (serial == null || serialNo == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_INVALID_SERIAL_NUMBER"));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_INVALID_SERIAL_NUMBER")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        ICertRecord certRecord = getCertRecord(serialNo);
        if (certRecord == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_CERT_SERIAL_NOT_FOUND_1", serialNo.toString(16)));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CERT_SERIAL_NOT_FOUND", "0x" + serialNo.toString(16))));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        // if RA, needs requestOwner to match
        // first, find the user's group
        if (authToken != null) {
            String group = authToken.getInString("group");

            if ((group != null) && (group != "")) {
                CMS.debug("GetBySerial process: auth group=" + group);
                if (group.equals("Registration Manager Agents")) {
                    boolean groupMatched = false;
                    // find the cert record's orig. requestor's group
                    MetaInfo metai = certRecord.getMetaInfo();
                    if (metai != null) {
                        String reqId = (String) metai.get(ICertRecord.META_REQUEST_ID);
                        RequestId rid = new RequestId(reqId);
                        IRequest creq = mReqQ.findRequest(rid);
                        if (creq != null) {
                            String reqOwner = creq.getRequestOwner();
                            if (reqOwner != null) {
                                CMS.debug("GetBySerial process: req owner=" + reqOwner);
                                if (reqOwner.equals(group))
                                    groupMatched = true;
                            }
                        }
                    }
                    if (groupMatched == false) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSGW_CERT_SERIAL_NOT_FOUND_1", serialNo.toString(16)));
                        cmsReq.setError(new ECMSGWException(
                                CMS.getUserMessage("CMS_GW_CERT_SERIAL_NOT_FOUND", "0x" + serialNo.toString(16))));
                        cmsReq.setStatus(ICMSRequest.ERROR);
                        return;
                    }
                }
            }
        }

        X509CertImpl cert = certRecord.getCertificate();

        if (cert != null) {
            // if there's a crmf request id, set that too.
            if (browser != null && browser.equals("ie")) {
                IArgBlock header = CMS.createArgBlock();
                IArgBlock ctx = CMS.createArgBlock();
                Locale[] locale = new Locale[1];
                CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);
                ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                CertificateChain cachain = ca.getCACertChain();
                X509Certificate[] cacerts = cachain.getChain();
                X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
                int m = 1, n = 0;

                for (; n < cacerts.length; m++, n++) {
                    userChain[m] = (X509CertImpl) cacerts[n];
                }

                userChain[0] = cert;
                PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                        new ContentInfo(new byte[0]), userChain, new SignerInfo[0]);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                try {
                    p7.encodeSignedData(bos);
                } catch (Exception eee) {
                }

                byte[] p7Bytes = bos.toByteArray();
                String p7Str = CMS.BtoA(p7Bytes);

                header.addStringValue("pkcs7", CryptoUtil.normalizeCertStr(p7Str));
                try {
                    CMSTemplate form = getTemplate(mIETemplate, req, locale);
                    ServletOutputStream out = response.getOutputStream();
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                    response.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    return;
                } catch (Exception ee) {
                    CMS.debug("GetBySerial process: Exception=" + ee.toString());
                }
            } //browser is IE

            MetaInfo metai = certRecord.getMetaInfo();
            String crmfReqId = null;

            if (metai != null) {
                crmfReqId = (String) metai.get(ICertRecord.META_CRMF_REQID);
                if (crmfReqId != null)
                    cmsReq.setResult(IRequest.CRMF_REQID, crmfReqId);
            }

            if (crmfReqId == null && checkImportCertToNav(
                    cmsReq.getHttpResp(), cmsReq.getHttpParams(), cert)) {
                cmsReq.setStatus(ICMSRequest.SUCCESS);
                return;
            }

            // use import cert template to return cert.
            X509CertImpl[] certs = new X509CertImpl[] { cert };

            cmsReq.setResult(certs);

            cmsReq.setStatus(ICMSRequest.SUCCESS);

            // XXX follow request in cert record to set certtype, which will
            // import cert only if it's client. For now assume "client" if
            // someone clicked to import this cert.
            cmsReq.getHttpParams().set("certType", "client");

            try {
                renderTemplate(cmsReq, mImportTemplate, mImportTemplateFiller);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
            }
        }

        return;
    }
}
