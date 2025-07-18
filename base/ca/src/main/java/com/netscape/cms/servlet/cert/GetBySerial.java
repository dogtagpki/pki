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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.common.CAServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Retrieve certificate by serial number.
 */
@WebServlet(
        name = "caGetBySerial",
        urlPatterns = "/ee/ca/getBySerial",
        initParams = {
                @WebInitParam(name="GetClientCert",      value="false"),
                @WebInitParam(name="successTemplate",    value="/ee/ca/ImportCert.template"),
                @WebInitParam(name="importCertTemplate", value="/ee/ca/ImportAdminCert.template"),
                @WebInitParam(name="AuthzMgr",           value="BasicAclAuthz"),
                @WebInitParam(name="authority",          value="ca"),
                @WebInitParam(name="interface",          value="ee"),
                @WebInitParam(name="ID",                 value="caGetBySerial"),
                @WebInitParam(name="resourceID",         value="certServer.ee.certificate")
        }
)
public class GetBySerial extends CAServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetBySerial.class);
    private static final long serialVersionUID = -2276677839178370838L;

    private final static String IMPORT_CERT_TEMPLATE = "ImportCert.template";
    private String mImportTemplate = null;
    private String mIETemplate = null;
    private ICMSTemplateFiller mImportTemplateFiller = null;
    RequestQueue mReqQ;

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
    @Override
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
        mTemplates.remove(CMSRequest.SUCCESS);

        CAEngine engine = CAEngine.getInstance();
        mReqQ = engine.getRequestQueue();
    }

    /**
     * handy routine for getting a cert record given a serial number.
     */
    protected CertRecord getCertRecord(BigInteger serialNo) {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certdb = engine.getCertificateRepository();

        if (certdb == null) {
            logger.error(CMS.getLogMessage("CMSGW_CERT_DB_NULL", "ca"));
            return null;
        }

        try {
            return certdb.readCertificateRecord(serialNo);

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSGW_NO_CERT_REC", serialNo.toString(16), e.toString()), e);
            return null;
        }
    }

    /**
     * check if a certificate (serial number) is revoked on a CA.
     *
     * @return true if cert is marked revoked in the CA's database.
     * @return false if cert is not marked revoked.
     */
    protected boolean certIsRevoked(BigInteger serialNum)
            throws EBaseException {
        CertRecord certRecord = getCertRecord(serialNum);

        if (certRecord == null) {
            logger.error(CMS.getLogMessage("CMSGW_BAD_CERT_SER_NUM", String.valueOf(serialNum)));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_INVALID_CERT"));
        }
        return certRecord.getStatus().equals(CertRecord.STATUS_REVOKED);
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param serialNumber serial number of certificate in HEX
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();
        ArgBlock args = cmsReq.getHttpParams();

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "import");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
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

        CAEngine engine = CAEngine.getInstance();

        if (serial == null || serialNo == null) {
            logger.warn(CMS.getLogMessage("CMSGW_INVALID_SERIAL_NUMBER"));
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_SERIAL_NUMBER")));
            cmsReq.setStatus(CMSRequest.ERROR);
            return;
        }

        CertRecord certRecord = getCertRecord(serialNo);
        if (certRecord == null) {
            logger.warn(CMS.getLogMessage("CMSGW_CERT_SERIAL_NOT_FOUND_1", serialNo.toString(16)));
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_CERT_SERIAL_NOT_FOUND", "0x" + serialNo.toString(16))));
            cmsReq.setStatus(CMSRequest.ERROR);
            return;
        }

        // if RA, needs requestOwner to match
        // first, find the user's group
        if (authToken != null) {
            String group = authToken.getInString("group");

            if ((group != null) && (group != "")) {
                logger.debug("GetBySerial process: auth group=" + group);
                if (group.equals("Registration Manager Agents")) {
                    boolean groupMatched = false;
                    // find the cert record's orig. requestor's group
                    MetaInfo metai = certRecord.getMetaInfo();
                    if (metai != null) {
                        String reqId = (String) metai.get(CertRecord.META_REQUEST_ID);
                        RequestId rid = new RequestId(reqId);
                        Request creq = requestRepository.readRequest(rid);
                        if (creq != null) {
                            String reqOwner = creq.getRequestOwner();
                            if (reqOwner != null) {
                                logger.debug("GetBySerial process: req owner=" + reqOwner);
                                if (reqOwner.equals(group))
                                    groupMatched = true;
                            }
                        }
                    }
                    if (groupMatched == false) {
                        logger.warn(CMS.getLogMessage("CMSGW_CERT_SERIAL_NOT_FOUND_1", serialNo.toString(16)));
                        cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_CERT_SERIAL_NOT_FOUND", "0x" + serialNo.toString(16))));
                        cmsReq.setStatus(CMSRequest.ERROR);
                        return;
                    }
                }
            }
        }

        X509CertImpl cert = certRecord.getCertificate();

        if (cert != null) {
            // if there's a crmf request id, set that too.
            if (browser != null && browser.equals("ie")) {
                ArgBlock header = new ArgBlock();
                ArgBlock ctx = new ArgBlock();
                Locale[] locale = new Locale[1];
                CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

                CertificateAuthority ca = engine.getCA();
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

                byte[] p7Bytes;
                try {
                    p7Bytes = p7.getBytes();
                } catch (Exception e) {
                    throw new EBaseException(e);
                }

                String p7Str = Utils.base64encode(p7Bytes, true);

                header.addStringValue("pkcs7", CryptoUtil.normalizeCertStr(p7Str));
                try {
                    CMSTemplate form = getTemplate(mIETemplate, req, locale);
                    ServletOutputStream out = response.getOutputStream();
                    cmsReq.setStatus(CMSRequest.SUCCESS);
                    response.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    return;
                } catch (Exception ee) {
                    logger.warn("GetBySerial process: Exception=" + ee.getMessage(), ee);
                }
            } //browser is IE

            MetaInfo metai = certRecord.getMetaInfo();
            String crmfReqId = null;

            if (metai != null) {
                crmfReqId = (String) metai.get(CertRecord.META_CRMF_REQID);
                if (crmfReqId != null)
                    cmsReq.setResult(Request.CRMF_REQID, crmfReqId);
            }

            if (crmfReqId == null && checkImportCertToNav(
                    cmsReq.getHttpResp(), cmsReq.getHttpParams(), cert)) {
                cmsReq.setStatus(CMSRequest.SUCCESS);
                return;
            }

            // use import cert template to return cert.
            X509CertImpl[] certs = new X509CertImpl[] { cert };

            cmsReq.setResult(certs);

            cmsReq.setStatus(CMSRequest.SUCCESS);

            // XXX follow request in cert record to set certtype, which will
            // import cert only if it's client. For now assume "client" if
            // someone clicked to import this cert.
            cmsReq.getHttpParams().set("certType", "client");

            try {
                renderTemplate(cmsReq, mImportTemplate, mImportTemplateFiller);
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"), e);
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
            }
        }
    }
}
