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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.extensions.NSCertTypeExtension;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;

/**
 * Display detailed information about a certificate
 *
 * The template 'displayBySerial.template' is used to
 * render the response for this servlet.
 *
 * @version $Revision$, $Date$
 */
public class DisplayBySerial extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DisplayBySerial.class);
    private static final long serialVersionUID = -4143700762995036597L;
    private final static String TPL_FILE1 = "displayBySerial.template";
    private final static BigInteger MINUS_ONE = new BigInteger("-1");

    private CertificateRepository mCertDB;
    private String mForm1Path = null;
    private X509Certificate mCACerts[] = null;

    /**
     * Constructs DisplayBySerial servlet.
     */
    public DisplayBySerial() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CAEngine engine = CAEngine.getInstance();

        if (mAuthority instanceof ICertificateAuthority) {
            mCertDB = engine.getCertificateRepository();
        }

        try {
            mCACerts = ((ICertAuthority) mAuthority).getCACertChain().getChain();
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CMSGW_CA_CHAIN_NOT_AVAILABLE"), e);
        }

        // coming from ee
        mForm1Path = "/" + mAuthority.getId() + "/" + TPL_FILE1;

        if (mOutputTemplatePath != null)
            mForm1Path = mOutputTemplatePath;

        // override success and error templates to null -
        // handle templates locally.
        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Serves HTTP request. The format of this request is as follows:
     * <ul>
     * <li>http.param serialNumber Decimal serial number of certificate to display (or hex if serialNumber preceded by
     * 0x)
     * </ul>
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        BigInteger serialNumber = MINUS_ONE;
        EBaseException error = null;
        String certType[] = new String[1];

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "read");
            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            }

            if (authzToken == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                return;
            }

            serialNumber = getSerialNumber(req);
            getCertRecord(serialNumber, certType); //throw exception on error

            if (certType[0].equalsIgnoreCase("x509")) {
                form = getTemplate(mForm1Path, req, locale);
            }

        } catch (NumberFormatException e) {
            logger.error(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT_1", String.valueOf(serialNumber)), e);
            error = new ECMSGWException(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mForm1Path, e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"), e);

        } catch (EDBRecordNotFoundException e) {
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_CERT_SERIAL_NOT_FOUND_1", "0x" + serialNumber.toString(16)), e);
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        try {
            if (serialNumber.compareTo(MINUS_ONE) > 0) {
                process(argSet, header, serialNumber,
                        req, resp, locale[0]);
            } else {
                error = new ECMSGWException(
                            CMS.getLogMessage("CMSGW_INVALID_SERIAL_NUMBER"));
            }
        } catch (EBaseException e) {
            error = e;
        }

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
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"), e);
        }

    }

    /**
     * Display information about a particular certificate
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
            BigInteger seq, HttpServletRequest req,
            HttpServletResponse resp,
            Locale locale)
            throws EBaseException {
        String certType[] = new String[1];

        try {
            getCertRecord(seq, certType); // throw exception on error

            if (certType[0].equalsIgnoreCase("x509")) {
                processX509(argSet, header, seq, req, resp, locale);
                return;
            }
        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_DISP_BY_SERIAL", e.toString()), e);
            throw e;
        }

        return;
    }

    private void processX509(CMSTemplateParams argSet, IArgBlock header,
            BigInteger seq, HttpServletRequest req,
            HttpServletResponse resp,
            Locale locale)
            throws EBaseException {
        boolean b64CertOnly = false; // for request that needs only b64 cert
        String isB64CertOnly = req.getParameter("b64CertOnly");
        if (isB64CertOnly != null && isB64CertOnly.equals("true")) {
            b64CertOnly = true;
        }

        CAEngine engine = CAEngine.getInstance();

        try {
            CertRecord rec = mCertDB.readCertificateRecord(seq);
            if (rec == null) {
                logger.error("DisplayBySerial: failed to read record");
                throw new ECMSGWException(
                        CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"));
            }
            X509CertImpl cert = rec.getCertificate();
            if (cert == null) {
                logger.error("DisplayBySerial: no certificate in record");
                throw new ECMSGWException(
                        CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"));
            }

            try {
                X509CertInfo info = (X509CertInfo) cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
                if (info == null) {
                    logger.error("DisplayBySerial: no info found");
                    throw new ECMSGWException(
                            CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"));
                }
                CertificateExtensions extensions = (CertificateExtensions) info.get(X509CertInfo.EXTENSIONS);

                boolean emailCert = false;

                if (extensions != null) {
                    for (int i = 0; i < extensions.size(); i++) {
                        Extension ext = extensions.elementAt(i);

                        if (ext instanceof NSCertTypeExtension) {
                            NSCertTypeExtension type = (NSCertTypeExtension) ext;

                            if (((Boolean) type.get(NSCertTypeExtension.EMAIL)).booleanValue())
                                emailCert = true;
                        }
                        if (ext instanceof KeyUsageExtension) {
                            KeyUsageExtension usage =
                                    (KeyUsageExtension) ext;

                            try {
                                if (((Boolean) usage.get(KeyUsageExtension.DIGITAL_SIGNATURE)).booleanValue() ||
                                        ((Boolean) usage.get(KeyUsageExtension.DATA_ENCIPHERMENT)).booleanValue())
                                    emailCert = true;
                            } catch (ArrayIndexOutOfBoundsException e) {
                                // bug356108:
                                // In case there is only DIGITAL_SIGNATURE,
                                // don't report error
                            }
                        }
                    }
                }
                header.addBooleanValue("emailCert", emailCert);

                boolean noCertImport = true;
                MetaInfo metaInfo = (MetaInfo) rec.get(CertRecord.ATTR_META_INFO);

                if (metaInfo != null) {
                    String rid = (String) metaInfo.get(CertRecord.META_REQUEST_ID);

                    if (rid != null && mAuthority instanceof ICertificateAuthority) {
                        IRequest r = requestRepository.readRequest(new RequestId(rid));
                        String certType = r.getExtDataInString(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);

                        if (certType != null && certType.equals(IRequest.CLIENT_CERT)) {
                            noCertImport = false;
                        }
                        header.addStringValue("reqId", rid);
                    }
                }
                header.addBooleanValue("noCertImport", noCertImport);

            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("CMSGW_ERROR_PARSING_EXTENS", e.toString()), e);
            }

            byte[] ba = cert.getEncoded();
            // Do base 64 encoding
            header.addStringValue("certChainBase64", Utils.base64encode(ba, true));

            IRevocationInfo revocationInfo = rec.getRevocationInfo();

            if (revocationInfo != null) {
                CRLExtensions crlExts = revocationInfo.getCRLEntryExtensions();

                if (crlExts != null) {
                    Enumeration<Extension> enumx = crlExts.getElements();
                    int reason = 0;

                    while (enumx.hasMoreElements()) {
                        Extension ext = enumx.nextElement();

                        if (ext instanceof CRLReasonExtension) {
                            reason = ((CRLReasonExtension) ext).getReason().toInt();
                        }
                    }
                    header.addIntegerValue("revocationReason", reason);
                }
            }

            if (!b64CertOnly) {
                CertPrettyPrint certDetails = new CertPrettyPrint(cert);
                header.addStringValue("certPrettyPrint",
                    certDetails.toString(locale));
            }

            /*
             String scheme = req.getScheme();
             if (scheme.equals("http") && connectionIsSSL(req))
             scheme = "https";
             String requestURI = req.getRequestURI();
             int i = requestURI.indexOf('?');
             String newRequestURI =
             (i > -1)? requestURI.substring(0, i): requestURI;
             header.addStringValue("serviceURL", scheme +"://"+
             req.getServerName() + ":"+
             req.getServerPort() + newRequestURI);
             */
            header.addStringValue("authorityid", mAuthority.getId());

            if (!b64CertOnly) {
                String certFingerprints = "";

                try {
                    certFingerprints = CertUtils.getFingerPrints(cert);
                } catch (Exception e) {
                    logger.warn(CMS.getLogMessage("CMSGW_ERR_DIGESTING_CERT", e.toString()), e);
                }

                if (certFingerprints.length() > 0)
                    header.addStringValue("certFingerprint", certFingerprints);
            }

            header.addStringValue("serialNumber", seq.toString(16));

            /*
             String userAgent = req.getHeader("user-agent");
             String agent =
             (userAgent != null)? UserInfo.getUserAgent(userAgent): "";
             */
            // Now formulate a PKCS#7 blob
            X509CertImpl[] certsInChain = new X509CertImpl[1];
            ;
            if (mCACerts != null) {
                for (int i = 0; i < mCACerts.length; i++) {
                    if (cert.equals(mCACerts[i])) {
                        certsInChain = new
                                X509CertImpl[mCACerts.length];
                        break;
                    }
                    certsInChain = new X509CertImpl[mCACerts.length + 1];
                }
            }

            // Set the EE cert
            certsInChain[0] = cert;

            // Set the Ca certificate chain
            if (mCACerts != null) {
                for (int i = 0; i < mCACerts.length; i++) {
                    if (!cert.equals(mCACerts[i]))
                        certsInChain[i + 1] = (X509CertImpl) mCACerts[i];
                }
            }

            if (!b64CertOnly) {
                // Wrap the chain into a degenerate P7 object
                String p7Str;

                try {
                    PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                        new ContentInfo(new byte[0]),
                        certsInChain,
                        new SignerInfo[0]);
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();

                    p7.encodeSignedData(bos, false);
                    byte[] p7Bytes = bos.toByteArray();

                    p7Str = Utils.base64encode(p7Bytes, true);
                    header.addStringValue("pkcs7ChainBase64", p7Str);
                } catch (Exception e) {
                    //p7Str = "PKCS#7 B64 Encoding error - " + e.toString()
                    //+ "; Please contact your administrator";
                    logger.error(CMS.getLogMessage("CMSGW_ERROR_FORMING_PKCS7_1", e.toString()), e);
                    throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_FORMING_PKCS7"), e);
                }
            }

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("MSGW_ERR_DISP_BY_SERIAL", e.toString()), e);
            throw e;

        } catch (CertificateEncodingException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_ENCODE_CERT", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_ENCODING_ISSUED_CERT"), e);
        }

        return;
    }

    private CertRecord getCertRecord(BigInteger seq, String certtype[])
            throws EBaseException {
        CertRecord rec = null;

        try {
            rec = mCertDB.readCertificateRecord(seq);
            X509CertImpl x509cert = rec.getCertificate();

            if (x509cert != null) {
                certtype[0] = "x509";
                return rec;
            }
        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_DISP_BY_SERIAL", e.toString()), e);
            throw e;
        }

        return rec;
    }

    private BigInteger getSerialNumber(HttpServletRequest req)
            throws NumberFormatException {
        String serialNumString = req.getParameter("serialNumber");

        if (serialNumString != null) {
            serialNumString = serialNumString.trim();
            if (serialNumString.startsWith("0x") || serialNumString.startsWith("0X")) {
                return new BigInteger(serialNumString.substring(2), 16);
            } else {
                return new BigInteger(serialNumString);
            }
        } else {
            throw new NumberFormatException();
        }
    }
}
