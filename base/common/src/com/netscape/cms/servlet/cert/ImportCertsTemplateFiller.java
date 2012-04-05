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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.pkix.cmmf.CertOrEncCert;
import org.mozilla.jss.pkix.cmmf.CertRepContent;
import org.mozilla.jss.pkix.cmmf.CertResponse;
import org.mozilla.jss.pkix.cmmf.CertifiedKeyPair;
import org.mozilla.jss.pkix.cmmf.PKIStatusInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.util.Utils;

/**
 * Set up HTTP response to import certificate into browsers
 *
 * The result must have been populate with the set of certificates
 * to return.
 *
 * <pre>
 * inputs: certtype.
 * outputs:
 * 	- cert type from http input (if any)
 *      - CA chain
 * 	- authority name (RM, CM, DRM)
 *      - scheme:host:port of server.
 *  array of one or more
 *      - cert serial number
 *      - cert pretty print
 * 	- cert in base 64 encoding.
 * 	- cmmf blob to import
 * </pre>
 *
 * @version $Revision$, $Date$
 */
public class ImportCertsTemplateFiller implements ICMSTemplateFiller {
    public static final String CRMF_REQID = "crmfReqId";
    public static final String ISSUED_CERT_SERIAL = "serialNo";
    public static final String CERT_TYPE = "certType";
    public static final String BASE64_CERT = "base64Cert";
    public static final String CERT_PRETTYPRINT = "certPrettyPrint";
    public static final String CERT_FINGERPRINT = "certFingerprint"; // cisco
    public static final String CERT_NICKNAME = "certNickname";
    public static final String CMMF_RESP = "cmmfResponse";
    public static final String PKCS7_RESP = "pkcs7ChainBase64"; // for MSIE

    public ImportCertsTemplateFiller() {
    }

    /**
     * @param cmsReq CMS Request
     * @param authority this authority
     * @param locale locale of template.
     * @param e unexpected exception e. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e)
            throws Exception {
        Certificate[] certs = (Certificate[]) cmsReq.getResult();

        if (certs instanceof X509CertImpl[])
            return getX509TemplateParams(cmsReq, authority, locale, e);
        else
            return null;
    }

    public CMSTemplateParams getX509TemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e)
            throws Exception {
        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(header, fixed);

        // set host name and port.
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        String host = httpReq.getServerName();
        int port = httpReq.getServerPort();
        String scheme = httpReq.getScheme();
        String format = httpReq.getParameter("format");
        if (format != null && format.equals("cmc"))
            fixed.set("importCMC", "false");
        String agentPort = "" + port;
        fixed.set("agentHost", host);
        fixed.set("agentPort", agentPort);
        fixed.set(ICMSTemplateFiller.HOST, host);
        fixed.set(ICMSTemplateFiller.PORT, Integer.valueOf(port));
        fixed.set(ICMSTemplateFiller.SCHEME, scheme);
        IRequest r = cmsReq.getIRequest();

        if (r != null) {
            fixed.set(ICMSTemplateFiller.REQUEST_ID, r.getRequestId().toString());
        }

        // set key record (if KRA enabled)
        if (r != null) {
            BigInteger keyRecSerialNo = r.getExtDataInBigInteger("keyRecord");

            if (keyRecSerialNo != null) {
                fixed.set(ICMSTemplateFiller.KEYREC_ID, keyRecSerialNo.toString());
            }
        }

        // set cert type.
        IArgBlock httpParams = cmsReq.getHttpParams();
        String certType =
                httpParams.getValueAsString(CERT_TYPE, null);

        if (certType != null)
            fixed.set(CERT_TYPE, certType);

        // this authority
        fixed.set(ICMSTemplateFiller.AUTHORITY, authority.getOfficialName());

        // CA chain.
        CertificateChain cachain =
                ((ICertAuthority) authority).getCACertChain();
        X509Certificate[] cacerts = cachain.getChain();

        String replyTo = httpParams.getValueAsString("replyTo", null);

        if (replyTo != null)
            fixed.set("replyTo", replyTo);

        // set user + CA cert chain and pkcs7 for MSIE.
        X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
        int m = 1, n = 0;

        for (; n < cacerts.length; m++, n++)
            userChain[m] = (X509CertImpl) cacerts[n];

        // certs.
        X509CertImpl[] certs = (X509CertImpl[]) cmsReq.getResult();

        // expose CRMF request id
        String crmfReqId = cmsReq.getExtData(IRequest.CRMF_REQID);

        if (crmfReqId == null) {
            crmfReqId = (String) cmsReq.getResult(
                        IRequest.CRMF_REQID);
        }
        if (crmfReqId != null) {
            fixed.set(CRMF_REQID, crmfReqId);
        }

        // set CA certs in cmmf, initialize CertRepContent
        // note cartman can't trust ca certs yet but it'll import them.
        // also set cert nickname for cartman.
        CertRepContent certRepContent = null;

        if (CMSServlet.doCMMFResponse(httpParams)) {
            byte[][] caPubs = new byte[cacerts.length][];

            for (int j = 0; j < cacerts.length; j++)
                caPubs[j] = ((X509CertImpl) cacerts[j]).getEncoded();
            certRepContent = new CertRepContent(caPubs);

            String certnickname =
                    cmsReq.getHttpParams().getValueAsString(CERT_NICKNAME, null);

            // if nickname is not requested set to subject name by default.
            if (certnickname == null)
                fixed.set(CERT_NICKNAME, certs[0].getSubjectDN().toString());
            else
                fixed.set(CERT_NICKNAME, certnickname);
        }

        // make pkcs7 for MSIE
        if (CMSServlet.clientIsMSIE(cmsReq.getHttpReq()) &&
                (certType == null || certType.equals("client"))) {
            userChain[0] = certs[0];
            PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                    new ContentInfo(new byte[0]),
                    userChain,
                    new SignerInfo[0]);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            p7.encodeSignedData(bos);
            byte[] p7Bytes = bos.toByteArray();
            //		String p7Str = encoder.encodeBuffer(p7Bytes);
            String p7Str = CMS.BtoA(p7Bytes);

            header.set(PKCS7_RESP, p7Str);
        }

        // set base 64, pretty print and cmmf response for each issued cert.
        for (int i = 0; i < certs.length; i++) {
            IArgBlock repeat = CMS.createArgBlock();
            X509CertImpl cert = certs[i];

            // set serial number.
            BigInteger serialNo =
                    ((X509Certificate) cert).getSerialNumber();

            repeat.addBigIntegerValue(ISSUED_CERT_SERIAL, serialNo, 16);

            // set base64 encoded blob.
            byte[] certEncoded = cert.getEncoded();
            //			String b64 = encoder.encodeBuffer(certEncoded);
            String b64 = CMS.BtoA(certEncoded);
            String b64cert = "-----BEGIN CERTIFICATE-----\n" +
                    b64 + "\n-----END CERTIFICATE-----";

            repeat.set(BASE64_CERT, b64cert);

            // set cert pretty print.

            String prettyPrintRequested =
                    cmsReq.getHttpParams().getValueAsString(CERT_PRETTYPRINT, null);

            if (prettyPrintRequested == null) {
                prettyPrintRequested = "true";
            }
            String ppStr = "";

            if (!prettyPrintRequested.equals("false")) {
                ICertPrettyPrint pp = CMS.getCertPrettyPrint(cert);

                ppStr = pp.toString(locale);
            }
            repeat.set(CERT_PRETTYPRINT, ppStr);

            // Now formulate a PKCS#7 blob
            X509CertImpl[] certsInChain = new X509CertImpl[1];
            ;
            if (cacerts != null) {
                for (int j = 0; j < cacerts.length; j++) {
                    if (cert.equals(cacerts[j])) {
                        certsInChain = new
                                X509CertImpl[cacerts.length];
                        break;
                    }
                    certsInChain = new X509CertImpl[cacerts.length + 1];
                }
            }

            // Set the EE cert
            certsInChain[0] = cert;

            // Set the Ca certificate chain
            if (cacerts != null) {
                for (int j = 0; j < cacerts.length; j++) {
                    if (!cert.equals(cacerts[j]))
                        certsInChain[j + 1] = (X509CertImpl) cacerts[j];
                }
            }
            // Wrap the chain into a degenerate P7 object
            String p7Str;

            try {
                PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                        new ContentInfo(new byte[0]),
                        certsInChain,
                        new SignerInfo[0]);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                p7.encodeSignedData(bos);
                byte[] p7Bytes = bos.toByteArray();

                //p7Str = encoder.encodeBuffer(p7Bytes);
                p7Str = CMS.BtoA(p7Bytes);
                repeat.addStringValue("pkcs7ChainBase64", p7Str);
            } catch (Exception ex) {
                //p7Str = "PKCS#7 B64 Encoding error - " + ex.toString()
                //+ "; Please contact your administrator";
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_FORMING_PKCS7_ERROR"));
            }

            // set cert fingerprint (for Cisco routers)
            String fingerprint = null;

            try {
                fingerprint = CMS.getFingerPrints(cert);
            } catch (CertificateEncodingException ex) {
                // should never happen
                throw new EBaseException(
                        CMS.getUserMessage(locale, "CMS_BASE_INTERNAL_ERROR", ex.toString()));
            } catch (NoSuchAlgorithmException ex) {
                // should never happen
                throw new EBaseException(
                        CMS.getUserMessage(locale, "CMS_BASE_INTERNAL_ERROR", ex.toString()));
            }
            if (fingerprint != null && fingerprint.length() > 0)
                repeat.set(CERT_FINGERPRINT, fingerprint);

            // cmmf response for this cert.
            if (CMSServlet.doCMMFResponse(httpParams) && crmfReqId != null &&
                    (certType == null || certType.equals("client"))) {
                PKIStatusInfo status = new PKIStatusInfo(PKIStatusInfo.granted);
                CertifiedKeyPair certifiedKP =
                        new CertifiedKeyPair(new CertOrEncCert(certEncoded));
                CertResponse resp =
                        new CertResponse(new INTEGER(crmfReqId), status,
                                certifiedKP);

                certRepContent.addCertResponse(resp);
            }

            params.addRepeatRecord(repeat);
        }

        // if cartman set whole cmmf response (CertRepContent) string.
        if (CMSServlet.doCMMFResponse(httpParams)) {
            ByteArrayOutputStream certRepOut = new ByteArrayOutputStream();

            certRepContent.encode(certRepOut);
            byte[] certRepBytes = certRepOut.toByteArray();
            String certRepB64 = Utils.base64encode(certRepBytes);
            // add CR to each return as required by cartman
            BufferedReader certRepB64lines =
                    new BufferedReader(new StringReader(certRepB64));
            StringWriter certRepStringOut = new StringWriter();
            String oneLine = null;
            boolean first = true;

            while ((oneLine = certRepB64lines.readLine()) != null) {
                if (first) {
                    //certRepStringOut.write("\""+oneLine+"\"");
                    certRepStringOut.write(oneLine);
                    first = false;
                } else {
                    //certRepStringOut.write("+\"\\n"+oneLine+"\"");
                    certRepStringOut.write("\n" + oneLine);
                }
            }
            String certRepString = certRepStringOut.toString();

            fixed.set(CMMF_RESP, certRepString);
        }

        return params;
    }
}
