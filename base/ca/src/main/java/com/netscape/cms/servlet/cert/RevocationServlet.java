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
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;

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
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * Perform the first step in revoking a certificate
 */
@WebServlet(
        name = "caRevocation",
        urlPatterns = "/ee/ca/revocation",
        initParams = {
                @WebInitParam(name="GetClientCert",   value="true"),
                @WebInitParam(name="successTemplate", value="/ee/ca/reasonToRevoke.template"),
                @WebInitParam(name="AuthzMgr",        value="BasicAclAuthz"),
                @WebInitParam(name="authority",       value="ca"),
                @WebInitParam(name="ID",              value="caRevocation"),
                @WebInitParam(name="resourceID",      value="certServer.ee.request.revocation"),
                @WebInitParam(name="AuthMgr",         value="sslClientCertAuthMgr"),
                @WebInitParam(name="interface",       value="ee")
        }
)
public class RevocationServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -9086730404084717413L;
    private final static String PROP_REVOKEBYDN = "revokeByDN";
    // revocation templates.
    private final static String TPL_FILE = "reasonToRevoke.template";

    // http params
    public static final String SERIAL_NO = "serialNo";
    // XXX can't do pkcs10 cause it's got no serial no.
    // (unless put serial no in pki attributes)
    // public static final String PKCS10 = "pkcs10";
    public static final String REASON_CODE = "reasonCode";

    private String mFormPath = null;
    private boolean mRevokeByDN = true;

    private SecureRandom mRandom = null;

    public RevocationServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses
     * the template file "reasonToRevoke.template" to render the
     * result.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        // override success template. has same info as enrollment.
        mTemplates.remove(CMSRequest.SUCCESS);

        mFormPath = "/" + TPL_FILE;
        try {
            mFormPath = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mFormPath == null)
                mFormPath = "/" + TPL_FILE;

            if (engine.getEnableNonces()) {
                mRandom = jssSubsystem.getRandomNumberGenerator();
            }

            // set to false by revokeByDN=false in web.xml
            mRevokeByDN = false;
            String tmp = sc.getInitParameter(PROP_REVOKEBYDN);

            if (tmp == null || tmp.trim().equalsIgnoreCase("false"))
                mRevokeByDN = false;
            else if (tmp.trim().equalsIgnoreCase("true"))
                mRevokeByDN = true;
        } catch (Exception e) {
        }
    }

    /**
     * Process the HTTP request. Note that this servlet does not
     * actually perform the certificate revocation. This is the first
     * step in the multi-step revocation process. (the next step is
     * in the ReasonToRevoke servlet.
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        ArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        // revocation requires either:
        //  - coming from ee:
        //		- old cert from ssl client auth
        //		- old certs from auth manager
        // 	- coming from agent or trusted RA:
        //  	- serial no of cert to be revoked.

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        BigInteger old_serial_no = null;
        X509CertImpl old_cert = null;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        ArgBlock header = new ArgBlock();
        ArgBlock ctx = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "submit");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        // coming from agent
        if (mAuthMgr != null && mAuthMgr.equals(AuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            X509Certificate[] cert = new X509Certificate[1];

            old_serial_no = getCertFromAgent(httpParams, cert);
            old_cert = (X509CertImpl) cert[0];
        } // coming from client
        else {
            // from auth manager
            X509CertImpl[] cert = new X509CertImpl[1];

            old_serial_no = getCertFromAuthMgr(authToken, cert);
            old_cert = cert[0];
        }

        header.addStringValue("serialNumber", old_cert.getSerialNumber().toString(16));
        header.addStringValue("serialNumberDecimal", old_cert.getSerialNumber().toString());
        //		header.addStringValue("subject", old_cert.getSubjectDN().toString());
        //		header.addLongValue("validNotBefore", old_cert.getNotBefore().getTime()/1000);
        //		header.addLongValue("validNotAfter", old_cert.getNotAfter().getTime()/1000);

        boolean noInfo = false;
        X509CertImpl[] certsToRevoke = null;

        if (engine.getEnableNonces()) {
            // generate nonce
            long n = mRandom.nextLong();
            // store nonce in session
            Map<Object, Long> nonces = engine.getNonces(cmsReq.getHttpReq(), "cert-revoke");
            nonces.put(old_serial_no, n);
            // return serial number and nonce to client
            header.addStringValue("nonce", old_serial_no+":"+n);
        }

        certsToRevoke = cr.getX509Certificates(
                    old_cert.getSubjectName().toString(),
                    CertificateRepository.ALL_UNREVOKED_CERTS);

        boolean authorized = false;

        if (certsToRevoke != null && certsToRevoke.length > 0) {
            for (int i = 0; i < certsToRevoke.length; i++) {
                if (old_cert.getSerialNumber().equals(certsToRevoke[i].getSerialNumber())) {
                    authorized = true;
                    break;
                }
            }
        }

        if (!noInfo && (certsToRevoke == null || certsToRevoke.length == 0 ||
                (!authorized))) {
            logger.error(CMS.getLogMessage("CA_CERT_ALREADY_REVOKED_1", old_serial_no.toString(16)));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CERT_ALREADY_REVOKED"));
        }

        if (!mRevokeByDN || noInfo) {
            certsToRevoke = new X509CertImpl[1];
            certsToRevoke[0] = old_cert;
            try {
                byte[] ba = old_cert.getEncoded();
                // Do base 64 encoding

                header.addStringValue("b64eCertificate", Utils.base64encode(ba, true));
            } catch (CertificateEncodingException e) {
            }
        }

        if (certsToRevoke != null && certsToRevoke.length > 0) {
            header.addIntegerValue("totalRecordCount", certsToRevoke.length);
            header.addIntegerValue("verifiedRecordCount", certsToRevoke.length);

            for (int i = 0; i < certsToRevoke.length; i++) {
                ArgBlock rarg = new ArgBlock();

                rarg.addStringValue("serialNumber",
                        certsToRevoke[i].getSerialNumber().toString(16));
                rarg.addStringValue("serialNumberDecimal",
                        certsToRevoke[i].getSerialNumber().toString());
                rarg.addStringValue("subject",
                        certsToRevoke[i].getSubjectDN().toString());
                rarg.addLongValue("validNotBefore",
                        certsToRevoke[i].getNotBefore().getTime() / 1000);
                rarg.addLongValue("validNotAfter",
                        certsToRevoke[i].getNotAfter().getTime() / 1000);
                argSet.addRepeatRecord(rarg);
            }
        } else {
            header.addIntegerValue("totalRecordCount", 0);
            header.addIntegerValue("verifiedRecordCount", 0);
        }

        // set revocation reason, default to unspecified if not set.
        int reasonCode = httpParams.getValueAsInt(REASON_CODE, 0);

        header.addIntegerValue("reason", reasonCode);

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(CMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        return;
    }

    /**
     * get cert to revoke from agent.
     */
    private BigInteger getCertFromAgent(
            ArgBlock httpParams, X509Certificate[] certContainer)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certRepository = engine.getCertificateRepository();

        BigInteger serialno = null;
        X509Certificate cert = null;

        // get serial no
        serialno = httpParams.getValueAsBigInteger(SERIAL_NO, null);
        if (serialno == null) {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_REVOKE"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_SERIALNO_FOR_REVOKE"));
        }

        // get cert from db
        cert = certRepository.getX509Certificate(serialno);
        if (cert == null) {
            logger.error(CMS.getLogMessage("CMSGW_INVALID_CERT_FOR_REVOCATION"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_REVOCATION"));
        }

        certContainer[0] = cert;
        return serialno;
    }

    /**
     * get cert to revoke from auth manager
     */
    private BigInteger getCertFromAuthMgr(
            AuthToken authToken, X509Certificate[] certContainer)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certRepository = engine.getCertificateRepository();

        X509CertImpl cert = authToken.getInCert(AuthToken.TOKEN_CERT);

        if (cert == null) {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_CERTS_REVOKE_FROM_AUTHMGR"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_CERTS_REVOKE_FROM_AUTHMGR"));
        }

        X509CertImpl certInDB = certRepository.getX509Certificate(cert.getSerialNumber());

        if (certInDB == null || !certInDB.equals(cert)) {
            logger.error(CMS.getLogMessage("CMSGW_INVALID_CERT_FOR_REVOCATION"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_REVOCATION"));
        }
        certContainer[0] = cert;
        BigInteger serialno = ((X509Certificate) cert).getSerialNumber();

        return serialno;
    }

}
