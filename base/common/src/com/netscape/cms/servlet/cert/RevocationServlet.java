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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmsutil.util.Utils;

/**
 * Perform the first step in revoking a certificate
 *
 * @version $Revision$, $Date$
 */
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

    private Random mRandom = null;

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
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success template. has same info as enrollment.
        mTemplates.remove(ICMSRequest.SUCCESS);

        mFormPath = "/" + TPL_FILE;
        try {
            mFormPath = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mFormPath == null)
                mFormPath = "/" + TPL_FILE;

            if (mAuthority instanceof ICertificateAuthority) {
                if (((ICertificateAuthority) mAuthority).noncesEnabled()) {
                    mRandom = new Random();
                }
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
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        IArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        // revocation requires either:
        //  - coming from ee:
        //		- old cert from ssl client auth
        //		- old certs from auth manager
        // 	- coming from agent or trusted RA:
        //  	- serial no of cert to be revoked.

        BigInteger old_serial_no = null;
        X509CertImpl old_cert = null;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "submit");
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

        // coming from agent
        if (mAuthMgr != null && mAuthMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
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

        if (mAuthority instanceof ICertificateAuthority) {

            if (certAuthority.noncesEnabled()) {
                // generate nonce
                long n = mRandom.nextLong();
                // store nonce in session
                Map<Object, Long> nonces = certAuthority.getNonces(cmsReq.getHttpReq(), "cert-revoke");
                nonces.put(old_serial_no, n);
                // return serial number and nonce to client
                header.addStringValue("nonce", old_serial_no+":"+n);
            }

            certsToRevoke = ((ICertificateAuthority) mAuthority).getCertificateRepository().getX509Certificates(
                        old_cert.getSubjectDN().toString(),
                        ICertificateRepository.ALL_UNREVOKED_CERTS);

        } else if (mAuthority instanceof IRegistrationAuthority) {
            IRequest req = mRequestQueue.newRequest(IRequest.GETCERTS_REQUEST);
            String filter = "(&(" + ICertRecord.ATTR_X509CERT + "." +
                    X509CertInfo.SUBJECT + "=" +
                    old_cert.getSubjectDN().toString() + ")(|(" +
                    ICertRecord.ATTR_CERT_STATUS + "=" +
                    ICertRecord.STATUS_VALID + ")(" +
                    ICertRecord.ATTR_CERT_STATUS + "=" +
                    ICertRecord.STATUS_EXPIRED + ")))";

            req.setExtData(IRequest.CERT_FILTER, filter);
            mRequestQueue.processRequest(req);
            RequestStatus status = req.getRequestStatus();

            if (status == RequestStatus.COMPLETE) {
                header.addStringValue("request", req.getRequestId().toString());
                Enumeration<String> enum1 = req.getExtDataKeys();

                while (enum1.hasMoreElements()) {
                    String name = enum1.nextElement();

                    if (name.equals(IRequest.OLD_CERTS)) {
                        X509CertImpl[] certs = req.getExtDataInCertArray(IRequest.OLD_CERTS);

                        certsToRevoke = certs;
                    }
                }
            } else {
                noInfo = true;
            }
        }

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
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CA_CERT_ALREADY_REVOKED_1", old_serial_no.toString(16)));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CERT_ALREADY_REVOKED"));
        }

        if (!mRevokeByDN || noInfo) {
            certsToRevoke = new X509CertImpl[1];
            certsToRevoke[0] = old_cert;
            try {
                byte[] ba = old_cert.getEncoded();
                // Do base 64 encoding

                header.addStringValue("b64eCertificate", Utils.base64encode(ba));
            } catch (CertificateEncodingException e) {
            }
        }

        if (certsToRevoke != null && certsToRevoke.length > 0) {
            header.addIntegerValue("totalRecordCount", certsToRevoke.length);
            header.addIntegerValue("verifiedRecordCount", certsToRevoke.length);

            for (int i = 0; i < certsToRevoke.length; i++) {
                IArgBlock rarg = CMS.createArgBlock();

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
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        return;
    }

    /**
     * get cert to revoke from agent.
     */
    private BigInteger getCertFromAgent(
            IArgBlock httpParams, X509Certificate[] certContainer)
            throws EBaseException {
        BigInteger serialno = null;
        X509Certificate cert = null;

        // get serial no
        serialno = httpParams.getValueAsBigInteger(SERIAL_NO, null);
        if (serialno == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_REVOKE"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_MISSING_SERIALNO_FOR_REVOKE"));
        }

        // get cert from db if we're cert authority.
        if (mAuthority instanceof ICertificateAuthority) {
            cert = getX509Certificate(serialno);
            if (cert == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_INVALID_CERT_FOR_REVOCATION"));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_REVOCATION"));
            }
        }
        certContainer[0] = cert;
        return serialno;
    }

    /**
     * get cert to revoke from auth manager
     */
    private BigInteger getCertFromAuthMgr(
            IAuthToken authToken, X509Certificate[] certContainer)
            throws EBaseException {
        X509CertImpl cert =
                authToken.getInCert(AuthToken.TOKEN_CERT);

        if (cert == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_CERTS_REVOKE_FROM_AUTHMGR"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_MISSING_CERTS_REVOKE_FROM_AUTHMGR"));
        }
        if (mAuthority instanceof ICertificateAuthority &&
                !isCertFromCA(cert)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_CERT_FOR_REVOCATION"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_REVOCATION"));
        }
        certContainer[0] = cert;
        BigInteger serialno = ((X509Certificate) cert).getSerialNumber();

        return serialno;
    }

}
