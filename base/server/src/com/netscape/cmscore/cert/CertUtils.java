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
package com.netscape.cmscore.cert;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.CertificateUsage;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.extensions.NSCertTypeExtension;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.xml.sax.SAXException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.CertInfoProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Utility class with assorted methods to check for
 * smime pairs, determining the type of cert - signature
 * or encryption ..etc.
 *
 * @author kanda
 * @version $Revision$, $Date$
 */
public class CertUtils {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertUtils.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String CERT_NEW_REQUEST_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String CERT_NEW_REQUEST_TRAILER = "-----END NEW CERTIFICATE REQUEST-----";
    public static final String CERT_RENEWAL_HEADER = "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
    public static final String CERT_RENEWAL_TRAILER = "-----END RENEWAL CERTIFICATE REQUEST-----";
    public static final String BEGIN_CRL_HEADER =
            "-----BEGIN CERTIFICATE REVOCATION LIST-----";
    public static final String END_CRL_HEADER =
            "-----END CERTIFICATE REVOCATION LIST-----";

    public static DerInputStream parseKeyGen(Locale locale, String certreq) throws Exception {
        byte[] data = Utils.base64decode(certreq);
        return new DerInputStream(data);
    }

    /**
     * Remove the header and footer in the PKCS10 request.
     */
    public static String unwrapPKCS10(String request, boolean checkHeader)
            throws EBaseException {
        String unwrapped;
        String header = null;
        int head = -1;
        int trail = -1;

        // check for "-----BEGIN NEW CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(CERT_NEW_REQUEST_HEADER);
            trail = request.indexOf(CERT_NEW_REQUEST_TRAILER);

            if (!(head == -1 && trail == -1)) {
                header = CERT_NEW_REQUEST_HEADER;
            }
        }

        // check for "-----BEGIN CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(Cert.REQUEST_HEADER);
            trail = request.indexOf(Cert.REQUEST_FOOTER);

            // If this is not a request header, check if this is a renewal header.
            if (!(head == -1 && trail == -1)) {
                header = Cert.REQUEST_HEADER;

            }
        }

        // check for "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
        if (header == null) {
            head = request.indexOf(CERT_RENEWAL_HEADER);
            trail = request.indexOf(CERT_RENEWAL_TRAILER);
            if (!(head == -1 && trail == -1)) {
                header = CERT_RENEWAL_HEADER;
            }
        }

        // Now validate if any headers or trailers are in place
        if (head == -1 && checkHeader) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_MISSING_PKCS10_HEADER"));
        }
        if (trail == -1 && checkHeader) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_MISSING_PKCS10_TRAILER"));
        }

        if (header != null) {
            unwrapped = request.substring(head + header.length(), trail);
        } else {
            unwrapped = request;
        }

        // strip all the crtl-characters (i.e. \r\n)
        StringTokenizer st = new StringTokenizer(unwrapped, "\t\r\n ");
        StringBuffer stripped = new StringBuffer();

        while (st.hasMoreTokens()) {
            stripped.append(st.nextToken());
        }

        return stripped.toString();
    }

    public static PKCS10 decodePKCS10(String req) throws EBaseException {
        String normalized = unwrapPKCS10(req, true);
        PKCS10 pkcs10 = null;

        try {
            byte[] decodedBytes = Utils.base64decode(normalized);

            pkcs10 = new PKCS10(decodedBytes);
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }
        return pkcs10;
    }

    public static PKCS10 parsePKCS10(Locale locale, String certreq) throws Exception {

        logger.debug("CertUtils: Parsing PKCS #10 request");

        if (certreq == null) {
            logger.error("CertUtils: Missing PKCS #10 request");
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }

        logger.debug(certreq);

        byte[] data = CertUtil.parseCSR(certreq);

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken savedToken = null;
        boolean sigver = true;

        try {
            sigver = cs.getBoolean("ca.requestVerify.enabled", true);

            if (sigver) {
                logger.debug("CertUtils: signature verification enabled");
                String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                savedToken = cm.getThreadToken();
                CryptoToken signToken = CryptoUtil.getCryptoToken(tokenName);

                logger.debug("CertUtils: setting thread token");
                cm.setThreadToken(signToken);
                return new PKCS10(data);

            } else {
                logger.debug("CertUtils: signature verification disabled");
                return new PKCS10(data, sigver);
            }

        } catch (Exception e) {
            logger.error("Unable to parse PKCS #10 request: " + e.getMessage(), e);
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);

        } finally {
            if (sigver) {
                logger.debug("CertUtils: restoring thread token");
                cm.setThreadToken(savedToken);
            }
        }
    }

    public static CertReqMsg[] parseCRMF(Locale locale, String certreq) throws Exception {

        logger.debug("CertUtils: Parsing CRMF request");

        if (certreq == null) {
            logger.error("CertUtils: Missing CRMF request");
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }

        byte[] data = CertUtil.parseCSR(certreq);

        try {
            ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(data);
            SEQUENCE crmfMsgs = (SEQUENCE) new SEQUENCE.OF_Template(
                    new CertReqMsg.Template()).decode(crmfBlobIn);
            int nummsgs = crmfMsgs.size();

            if (nummsgs <= 0) {
                return null;
            }

            CertReqMsg[] msgs = new CertReqMsg[crmfMsgs.size()];
            for (int i = 0; i < nummsgs; i++) {
                msgs[i] = (CertReqMsg) crmfMsgs.elementAt(i);
            }

            return msgs;

        } catch (Exception e) {
            logger.error("Unable to parse CRMF request: " + e.getMessage(), e);
            throw new EProfileException(CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    public static void setRSAKeyToCertInfo(X509CertInfo info,
            byte encoded[]) throws EBaseException {
        try {
            if (info == null) {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
            }
            X509Key key = new X509Key(AlgorithmId.get("RSAEncryption"), encoded);

            info.set(X509CertInfo.KEY, key);
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
        }
    }

    public static X509CertInfo createCertInfo(int ver,
            BigInteger serialno, String alg, String issuerName,
            Date notBefore, Date notAfter) throws EBaseException {
        try {
            X509CertInfo info = new X509CertInfo();

            info.set(X509CertInfo.VERSION, new CertificateVersion(ver));
            info.set(X509CertInfo.SERIAL_NUMBER, new
                    CertificateSerialNumber(serialno));
            info.set(X509CertInfo.ALGORITHM_ID, new
                    CertificateAlgorithmId(AlgorithmId.get(alg)));
            info.set(X509CertInfo.ISSUER, new
                    CertificateIssuerName(new X500Name(issuerName)));
            info.set(X509CertInfo.VALIDITY, new
                    CertificateValidity(notBefore, notAfter));
            return info;
        } catch (Exception e) {
            System.out.println(e.toString());
            return null;
        }
    }

    public static void sortCerts(X509CertImpl[] arr) {
        Arrays.sort(arr, new CertDateCompare());
    }

    public static boolean isSigningCert(X509CertImpl cert) {
        boolean[] keyUsage = null;

        try {
            keyUsage = cert.getKeyUsage();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (keyUsage == null) ? false : keyUsage[0];
    }

    public static boolean isEncryptionCert(X509CertImpl cert) {
        boolean[] keyUsage = null;

        try {
            keyUsage = cert.getKeyUsage();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (keyUsage == null)
            return false;
        if (keyUsage.length < 3)
            return false;
        else if (keyUsage.length == 3)
            return keyUsage[2];
        else
            return keyUsage[2] || keyUsage[3];
    }

    public static boolean haveSameValidityPeriod(X509CertImpl cert1,
            X509CertImpl cert2) {
        long notBefDiff = 0;
        long notAfterDiff = 0;

        try {
            notBefDiff = Math.abs(cert1.getNotBefore().getTime() -
                        cert2.getNotBefore().getTime());
            notAfterDiff = Math.abs(cert1.getNotAfter().getTime() -
                        cert2.getNotAfter().getTime());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (notBefDiff > 1000 || notAfterDiff > 1000)
            return false;
        else
            return true;
    }

    public static boolean isSmimePair(X509CertImpl cert1, X509CertImpl cert2, boolean matchSubjectDN) {
        // Check for subjectDN equality.
        if (matchSubjectDN) {
            String dn1 = cert1.getSubjectDN().toString();
            String dn2 = cert2.getSubjectDN().toString();

            if (!sameSubjectDN(dn1, dn2))
                return false;
        }

        // Check for the presence of signing and encryption certs.
        boolean hasSigningCert = isSigningCert(cert1) || isSigningCert(cert2);

        if (!hasSigningCert)
            return false;

        boolean hasEncryptionCert = isEncryptionCert(cert1) || isEncryptionCert(cert2);

        if (!hasEncryptionCert)
            return false;

        // If both certs have signing & encryption usage set, they are
        // not really pairs.
        if ((isSigningCert(cert1) && isEncryptionCert(cert1)) ||
                (isSigningCert(cert2) && isEncryptionCert(cert2)))
            return false;

        // See if the certs have the same validity.
        boolean haveSameValidity =
                haveSameValidityPeriod(cert1, cert2);

        return haveSameValidity;
    }

    public static boolean isNotYetValidCert(X509CertImpl cert) {
        boolean ret = false;

        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
        } catch (CertificateNotYetValidException e) {
            ret = true;
        } catch (Exception e) {
        }
        return ret;
    }

    public static boolean isValidCert(X509CertImpl cert) {
        boolean ret = true;

        try {
            cert.checkValidity();
        } catch (Exception e) {
            ret = false;
        }
        return ret;
    }

    public static boolean isExpiredCert(X509CertImpl cert) {
        boolean ret = false;

        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            ret = true;
        } catch (Exception e) {
        }
        return ret;
    }

    public static boolean sameSubjectDN(String dn1, String dn2) {
        boolean ret = false;

        // The dn cannot be null.
        if (dn1 == null || dn2 == null)
            return false;
        try {
            X500Name n1 = new X500Name(dn1);
            X500Name n2 = new X500Name(dn2);

            ret = n1.equals(n2);
        } catch (Exception e) {
        }
        return ret;
    }

    public static String getValidCertsDisplayInfo(String cn, X509CertImpl[] validCerts) {
        StringBuffer sb = new StringBuffer(1024);

        sb.append(cn + "'s Currently Valid Certificates\n\n");
        sb.append(getCertsDisplayInfo(validCerts));
        return new String(sb);
    }

    public static String getExpiredCertsDisplayInfo(String cn, X509CertImpl[] expiredCerts) {
        StringBuffer sb = new StringBuffer(1024);

        sb.append(cn + "'s Expired Certificates\n\n");
        sb.append(getCertsDisplayInfo(expiredCerts));
        return new String(sb);
    }

    public static String getRenewedCertsDisplayInfo(String cn,
            X509CertImpl[] validCerts, X509CertImpl[] renewedCerts) {
        StringBuffer sb = new StringBuffer(1024);

        if (validCerts != null) {
            sb.append(cn + "'s Currently Valid Certificates\n\n");
            sb.append(getCertsDisplayInfo(validCerts));
            sb.append("\n\nRenewed Certificates\n\n\n");
        } else
            sb.append(cn + "'s Renewed Certificates\n\n");
        sb.append(getCertsDisplayInfo(renewedCerts));
        return new String(sb);
    }

    public static String getCertsDisplayInfo(X509CertImpl[] validCerts) {
        // We assume that the given pair is a valid S/MIME pair.
        StringBuffer sb = new StringBuffer(1024);

        sb.append("Subject DN: " + validCerts[0].getSubjectDN().toString());
        sb.append("\n");
        X509CertImpl signingCert, encryptionCert;

        if (isSigningCert(validCerts[0])) {
            signingCert = validCerts[0];
            encryptionCert = validCerts[1];
        } else {
            signingCert = validCerts[1];
            encryptionCert = validCerts[0];
        }
        sb.append("Signing      Certificate Serial No: " + signingCert.getSerialNumber().toString(16).toUpperCase());
        sb.append("\n");
        sb.append("Encryption Certificate Serial No: " + encryptionCert.getSerialNumber().toString(16).toUpperCase());
        sb.append("\n");
        sb.append("Validity: From: "
                + signingCert.getNotBefore().toString() + "  To: " + signingCert.getNotAfter().toString());
        sb.append("\n");
        return new String(sb);
    }

    /**
     * Returns the index of the given cert in an array of certs.
     *
     * Assumptions: The certs are issued by the same CA
     *
     * @param certArray The array of certs.
     * @param givenCert The certificate we are lokking for in the array.
     * @return -1 if not found or the index of the given cert in the array.
     */
    public static int getCertIndex(X509CertImpl[] certArray, X509CertImpl givenCert) {
        int i = 0;

        for (; i < certArray.length; i++) {
            if (certArray[i].getSerialNumber().equals(
                    givenCert.getSerialNumber())) {
                break;
            }
        }

        return ((i == certArray.length) ? -1 : i);
    }

    /**
     * Returns the most recently issued signing certificate from an
     * an array of certs.
     *
     * Assumptions: The certs are issued by the same CA
     *
     * @param certArray The array of certs.
     * @param givenCert The certificate we are lokking for in the array.
     * @return null if there is no recent cert or the most recent cert.
     */
    public static X509CertImpl getRecentSigningCert(X509CertImpl[] certArray,
            X509CertImpl currentCert) {
        if (certArray == null || currentCert == null)
            return null;

        // Sort the certificate array.
        Arrays.sort(certArray, new CertDateCompare());

        // Get the index of the current cert in the array.
        int i = getCertIndex(certArray, currentCert);

        if (i < 0)
            return null;

        X509CertImpl recentCert = currentCert;

        for (; i < certArray.length; i++) {
            // Check if it is a signing cert and has its
            // NotAfter later than the current cert.
            if (isSigningCert(certArray[i]) &&
                    certArray[i].getNotAfter().after(recentCert.getNotAfter()))
                recentCert = certArray[i];
        }
        return ((recentCert == currentCert) ? null : recentCert);
    }

    public static String getCertType(X509CertImpl cert) throws CertificateParsingException, IOException {
        StringBuffer sb = new StringBuffer();

        if (isSigningCert(cert))
            sb.append("signing");
        if (isEncryptionCert(cert)) {
            if (sb.length() > 0)
                sb.append("  ");
            sb.append("encryption");
        }

        // Is is object signing cert?
        CertificateExtensions extns = (CertificateExtensions)
                cert.get(X509CertImpl.NAME + "." +
                        X509CertImpl.INFO + "." +
                        X509CertInfo.EXTENSIONS);

        if (extns != null) {
            NSCertTypeExtension nsExtn = (NSCertTypeExtension)
                    extns.get(NSCertTypeExtension.NAME);

            if (nsExtn != null) {
                String nsType = getNSExtensionInfo(nsExtn);

                if (nsType != null) {
                    if (sb.length() > 0)
                        sb.append("  ");
                    sb.append(nsType);
                }
            }
        }
        return (sb.length() > 0) ? sb.toString() : null;
    }

    public static String getNSExtensionInfo(NSCertTypeExtension nsExtn) {
        StringBuffer sb = new StringBuffer();

        try {
            Boolean res;

            res = (Boolean) nsExtn.get(NSCertTypeExtension.SSL_CLIENT);
            if (res.equals(Boolean.TRUE))
                sb.append("   ssl_client");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.SSL_SERVER);
            if (res.equals(Boolean.TRUE))
                sb.append("   ssl_server");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.EMAIL);
            if (res.equals(Boolean.TRUE))
                sb.append("   email");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.OBJECT_SIGNING);
            if (res.equals(Boolean.TRUE))
                sb.append("   object_signing");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.SSL_CA);
            if (res.equals(Boolean.TRUE))
                sb.append("   ssl_CA");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.EMAIL_CA);
            if (res.equals(Boolean.TRUE))
                sb.append("   email_CA");
            res = (Boolean) nsExtn.get(NSCertTypeExtension.OBJECT_SIGNING_CA);
            if (res.equals(Boolean.TRUE))
                sb.append("   object_signing_CA");
        } catch (Exception e) {
        }

        return (sb.length() > 0) ? sb.toString() : null;
    }

    public static byte[] readFromFile(String fileName)
            throws IOException {
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(fileName);
            int available = fin.available();
            byte[] ba = new byte[available];
            int nRead = fin.read(ba);

            if (nRead != available)
                throw new IOException("Error reading data from file: " + fileName);

            return ba;
        } finally {
            if (fin != null)
                fin.close();
        }
    }

    public static void storeInFile(String fileName, byte[] ba)
            throws IOException {
        FileOutputStream fout = null;
        try {
            fout = new FileOutputStream(fileName);

            fout.write(ba);
        } finally {
            if (fout != null)
                fout.close();
        }
    }

    public static X509Certificate mapCert(String mime64)
            throws IOException {
        mime64 = stripCertBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        byte rawPub[] = Utils.base64decode(newval);
        X509Certificate cert = null;

        try {
            cert = new X509CertImpl(rawPub);
        } catch (CertificateException e) {
        }
        return cert;
    }

    public static X509Certificate[] mapCertFromPKCS7(String mime64)
            throws IOException {
        mime64 = stripCertBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        byte rawPub[] = Utils.base64decode(newval);
        PKCS7 p7 = null;

        try {
            p7 = new PKCS7(rawPub);
            return p7.getCertificates();
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
    }

    public static X509CRL mapCRL(String mime64)
            throws IOException {
        mime64 = stripCRLBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        byte rawPub[] = Utils.base64decode(newval);
        X509CRL crl = null;

        try {
            crl = new X509CRLImpl(rawPub);
        } catch (Exception e) {
        }
        return crl;
    }

    public static X509CRL mapCRL1(String mime64)
            throws IOException {
        mime64 = stripCRLBrackets(mime64.trim());
        byte rawPub[] = Utils.base64decode(mime64);
        X509CRL crl = null;

        try {
            crl = new X509CRLImpl(rawPub);
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        return crl;
    }

    public static String normalizeCertStr(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }

    public static String stripCRLBrackets(String s) {
        if (s == null) {
            return s;
        }
        if ((s.startsWith("-----BEGIN CERTIFICATE REVOCATION LIST-----")) &&
                (s.endsWith("-----END CERTIFICATE REVOCATION LIST-----"))) {
            return (s.substring(43, (s.length() - 41)));
        }
        return s;
    }

    /**
     * strips out the begin and end certificate brackets
     *
     * @param s the string potentially bracketed with
     *            "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
     * @return string without the brackets
     */
    public static String stripCertBrackets(String s) {
        if (s == null) {
            return s;
        }

        if ((s.startsWith(Cert.HEADER)) &&
                (s.endsWith(Cert.FOOTER))) {
            return (s.substring(27, (s.length() - 25)));
        }

        // To support Thawte's header and footer
        if ((s.startsWith("-----BEGIN PKCS #7 SIGNED DATA-----")) &&
                (s.endsWith("-----END PKCS #7 SIGNED DATA-----"))) {
            return (s.substring(35, (s.length() - 33)));
        }

        return s;
    }

    /**
     * Returns a string that represents a cert's fingerprint.
     * The fingerprint is a MD5 digest of the DER encoded certificate.
     *
     * @param cert Certificate to get the fingerprint of.
     * @return a String that represents the cert's fingerprint.
     */
    public static String getFingerPrint(Certificate cert)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        byte certDer[] = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("MD5");

        md.update(certDer);
        byte digestedCert[] = md.digest();
        PrettyPrintFormat pp = new PrettyPrintFormat(":");
        StringBuffer sb = new StringBuffer();

        sb.append(pp.toHexString(digestedCert, 4, 20));
        return sb.toString();
    }

    /**
     * Returns a string that has the certificate's fingerprint using
     * MD5, MD2 and SHA1 hashes.
     * A certificate's fingerprint is a hash digest of the DER encoded
     * certificate.
     *
     * @param cert Certificate to get the fingerprints of.
     * @return a String with fingerprints using the MD5, MD2 and SHA1 hashes.
     *         For example,
     *
     *         <pre>
     * MD2:   78:7E:D1:F9:3E:AF:50:18:68:A7:29:50:C3:21:1F:71
     *
     * MD5:   0E:89:91:AC:40:50:F7:BE:6E:7B:39:4F:56:73:75:75
     *
     * SHA1:  DC:D9:F7:AF:E2:83:10:B2:F7:0A:77:E8:50:E2:F7:D1:15:9A:9D:00
     * </pre>
     */
    public static String getFingerPrints(Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        byte certDer[] = cert.getEncoded();
        /*
        String[] hashes = new String[] {"MD2", "MD5", "SHA1"};
        String certFingerprints = "";
        PrettyPrintFormat pp = new PrettyPrintFormat(":");

        for (int i = 0; i < hashes.length; i++) {
            MessageDigest md = MessageDigest.getInstance(hashes[i]);

            md.update(certDer);
            certFingerprints += "    " + hashes[i] + ":" +
                    pp.toHexString(md.digest(), 6 - hashes[i].length());
        }
        return certFingerprints;
        */
        return getFingerPrints(certDer);
    }

    /**
     * Returns a string that has the certificate's fingerprint using
     * MD5, MD2 and SHA1 hashes.
     * A certificate's fingerprint is a hash digest of the DER encoded
     * certificate.
     *
     * @param cert Certificate to get the fingerprints of.
     * @return a String with fingerprints using the MD5, MD2 and SHA1 hashes.
     *         For example,
     *
     *         <pre>
     * MD2:   78:7E:D1:F9:3E:AF:50:18:68:A7:29:50:C3:21:1F:71
     *
     * MD5:   0E:89:91:AC:40:50:F7:BE:6E:7B:39:4F:56:73:75:75
     *
     * SHA1:  DC:D9:F7:AF:E2:83:10:B2:F7:0A:77:E8:50:E2:F7:D1:15:9A:9D:00
     * </pre>
     */
    public static String getFingerPrints(byte[] certDer)
            throws NoSuchAlgorithmException/*, CertificateEncodingException*/{
        //        byte certDer[] = cert.getEncoded();
        String[] hashes = new String[] { "MD2", "MD5", "SHA1", "SHA256", "SHA512" };
        StringBuffer certFingerprints = new StringBuffer();
        PrettyPrintFormat pp = new PrettyPrintFormat(":");

        for (int i = 0; i < hashes.length; i++) {
            MessageDigest md = MessageDigest.getInstance(hashes[i]);

            md.update(certDer);
            certFingerprints.append(hashes[i] + ":\n" +
                    pp.toHexString(md.digest(), 8, 16));
        }
        return certFingerprints.toString();
    }

    /**
     * Check if a object identifier in string form is valid,
     * that is a string in the form n.n.n.n and der encode and decode-able.
     *
     * @param attrName attribute name (from the configuration file)
     * @param value object identifier string.
     */
    public static ObjectIdentifier checkOID(String attrName, String value)
            throws EBaseException {
        String msg = "value must be a object identifier in the form n.n.n.n";
        String msg1 = "not a valid object identifier.";
        ObjectIdentifier oid;

        try {
            oid = ObjectIdentifier.getObjectIdentifier(value);
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        attrName, msg));
        }

        // if the OID isn't valid (ex. n.n) the error isn't caught til
        // encoding time leaving a bad request in the request queue.
        DerOutputStream derOut = null;
        try {
            derOut = new DerOutputStream();

            derOut.putOID(oid);
            new ObjectIdentifier(new DerInputStream(derOut.toByteArray()));
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                    attrName, msg1));
        } finally {
            try {
                derOut.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return oid;
    }

    public static String trimB64E(String b64e) {
        StringBuffer tmp = new StringBuffer("");
        String line = null;
        StringTokenizer tokens = new StringTokenizer(b64e, "\n");

        while (tokens.hasMoreTokens()) {
            line = tokens.nextToken();
            line = line.trim();
            tmp.append(line.trim());
            if (tokens.hasMoreTokens())
                tmp.append("\n");
        }

        return tmp.toString();
    }

    // Dynamically apply the SubjectAlternativeName extension to a
    // remote PKI instance's request for its SSL Server Certificate.
    //
    // Since this information may vary from instance to
    // instance, obtain the necessary information from the
    // 'service.sslserver.san' value(s) in the instance's
    // CS.cfg, process these values converting each item into
    // its individual SubjectAlternativeName components, and
    // build an SSL Server Certificate URL extension consisting
    // of this information.
    //
    // 03/27/2013 - Should consider removing this
    //              "buildSANSSLserverURLExtension()"
    //              method if it becomes possible to
    //              embed a certificate extension into
    //              a PKCS #10 certificate request.
    //
    public static void buildSANSSLserverURLExtension(IConfigStore config, MultivaluedMap<String, String> content)
           throws Exception {

        logger.debug("CertUtils: buildSANSSLserverURLExtension() " +
                  "building SAN SSL Server Certificate URL extension . . .");

        if (config == null) {
            throw new EBaseException("injectSANextensionIntoRequest: parameter config cannot be null");
        }

        String sanHostnames = config.getString("service.sslserver.san");
        String sans[] = StringUtils.split(sanHostnames, ",");

        int i = 0;
        for (String san : sans) {
            logger.debug("CertUtils: buildSANSSLserverURLExtension() processing " +
                      "SAN hostname: " + san);
            // Add the DNSName for all SANs
            content.putSingle("req_san_pattern_" + i, san);
            i++;
        }

        content.putSingle("req_san_entries", "" + i);

        logger.debug("CertUtils: buildSANSSLserverURLExtension() " + "placed " +
                  i + " SAN entries into SSL Server Certificate URL.");
    }

    /*
     * create requests so renewal can work on these initial certs
     */
    public static IRequest createLocalRequest(
            IRequestQueue queue,
            CertInfoProfile profile,
            X509CertInfo info,
            X509Key x509key,
            String[] sanHostnames,
            boolean installAdjustValidity)
            throws Exception {

        //        RequestId rid = new RequestId(serialNum);
        // just need a request, no need to get into a queue
        //        IRequest r = new EnrollmentRequest(rid);

        logger.info("CertUtils: Creating local request");

        IRequest req = queue.newRequest("enrollment");

        req.setExtData("profile", "true");
        req.setExtData("requestversion", "1.0.0");
        req.setExtData("req_seq_num", "0");

        req.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
        req.setExtData(EnrollProfile.REQUEST_EXTENSIONS, new CertificateExtensions());

        req.setExtData("requesttype", "enrollment");
        req.setExtData("requestor_name", "");
        req.setExtData("requestor_email", "");
        req.setExtData("requestor_phone", "");
        req.setExtData("profileRemoteHost", "");
        req.setExtData("profileRemoteAddr", "");
        req.setExtData("requestnotes", "");
        req.setExtData("isencryptioncert", "false");
        req.setExtData("profileapprovedby", "system");

        if (sanHostnames != null) {

            logger.info("CertUtils: Injecting SAN extension:");

            // Dynamically inject the SubjectAlternativeName extension to a
            // local/self-signed master CA's request for its SSL Server Certificate.
            //
            // Since this information may vary from instance to
            // instance, obtain the necessary information from the
            // 'service.sslserver.san' value(s) in the instance's
            // CS.cfg, process these values converting each item into
            // its individual SubjectAlternativeName components, and
            // inject these values into the local request.

            int i = 0;
            for (String sanHostname : sanHostnames) {
                logger.info("CertUtils: - " + sanHostname);
                req.setExtData("req_san_pattern_" + i, sanHostname);
                i++;
            }
        }

        req.setExtData("req_key", x509key.toString());

        String origProfileID = profile.getID();
        int idx = origProfileID.lastIndexOf('.');
        if (idx > 0) {
            origProfileID = origProfileID.substring(0, idx);
        }

        // store original profile id in cert request
        req.setExtData("origprofileid", origProfileID);

        // store mapped profile ID for use in renewal
        req.setExtData("profileid", profile.getProfileIDMapping());
        req.setExtData("profilesetid", profile.getProfileSetIDMapping());

        if (installAdjustValidity) {
            /*
             * (applies to non-CA-signing cert only)
             * installAdjustValidity tells ValidityDefault to adjust the
             * notAfter value to that of the CA's signing cert if needed
             */
            req.setExtData("installAdjustValidity", "true");
        }

        // mark request as complete
        logger.debug("CertUtils: calling setRequestStatus");
        req.setRequestStatus(RequestStatus.COMPLETE);

        return req;
    }

    /**
     * update local cert request with the actual request
     * called from CertRequestPanel.java
     * @throws EBaseException
     * @throws EPropertyNotFound
     */
    public static void updateLocalRequest(
            String reqId,
            byte[] certReq,
            String reqType,
            String subjectName
            ) throws Exception {

        logger.debug("CertUtils: updateLocalRequest(" + reqId + ")");

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        IRequestQueue queue = ca.getRequestQueue();

        IRequest req = queue.findRequest(new RequestId(reqId));

        if (certReq != null) {
            logger.debug("CertUtils: updating cert request");
            String certReqs = CryptoUtil.base64Encode(certReq);
            String certReqf = CryptoUtil.reqFormat(certReqs);
            req.setExtData("cert_request", certReqf);
        }

        req.setExtData("cert_request_type", reqType);

        if (subjectName != null) {
            logger.debug("CertUtils: updating request subject: " + subjectName);
            req.setExtData("subject", subjectName);
            new X500Name(subjectName); // check for errors
        }

        queue.updateRequest(req);
    }

    public static X509CertInfo createCertInfo(
            String dn,
            String issuerdn,
            String keyAlgorithm,
            X509Key x509key,
            String type) throws Exception {

        logger.info("CertUtils: Creating certificate info for " + dn);

        Date date = new Date();

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();
        BigInteger serialNo = cr.getNextSerialNumber();

        X509CertInfo info;

        if (type.equals("selfsign")) {

            logger.debug("CertUtils: Creating self-signed certificate");
            CertificateIssuerName issuerdnObj = new CertificateIssuerName(new X500Name(dn));
            info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);

        } else {

            logger.debug("CertUtils: Creating CA-signed certificate");
            CertificateIssuerName issuerdnObj = ca.getIssuerObj();

            if (issuerdnObj != null) {

                logger.debug("CertUtils: Reusing CA's CertificateIssuerName to preserve the DN encoding");
                info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);

            } else {

                logger.debug("CertUtils: Creating new CertificateIssuerName");
                issuerdnObj = new CertificateIssuerName(new X500Name(issuerdn));
                info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);
            }
        }

        logger.info("CertUtils: Cert info:\n" + info);
        return info;
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509CertImpl cert) throws Exception {

        logger.debug("CertUtils: createCertRecord(" +
                cert.getSerialNumber() + ", " +
                cert.getSubjectDN() + ")");

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();

        MetaInfo meta = new MetaInfo();
        meta.set(ICertRecord.META_REQUEST_ID, request.getRequestId().toString());
        meta.set(ICertRecord.META_PROFILE_ID, profile.getProfileIDMapping());

        ICertRecord record = cr.createCertRecord(cert.getSerialNumber(), cert, meta);
        cr.addCertificateRecord(record);
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509Certificate cert) throws Exception {

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        createCertRecord(request, profile, certImpl);
    }

    public static X509CertImpl createLocalCert(
            IRequest req,
            CertInfoProfile profile,
            X509CertInfo info,
            java.security.PrivateKey signingPrivateKey,
            String caSigningKeyAlgo) throws Exception {

        profile.populate(req, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, caSigningKeyAlgo);

        createCertRecord(req, profile, cert);

        // update request with cert
        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        return cert;
    }

    public static X509CertImpl createRemoteCert(
            PKIClient client,
            MultivaluedMap<String, String> content)
            throws Exception {

        logger.debug("CertUtils: Calling profileSubmit");
        logger.debug("CertUtils: content: " + content);

        String c = client.post("/ca/ee/ca/profileSubmit", content);

        if (c == null) {
            logger.error("CertUtils: Missing CA response");
            throw new Exception("Missing CA response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser;
        try {
            parser = new XMLObject(bis);
        } catch (SAXException e) {
            logger.error("Response: " + c);
            logger.error("CertUtils: Unable to parse XML response: " + e, e);
            throw e;
        }

        String status = parser.getValue("Status");
        logger.debug("CertUtils: status: " + status);

        if (!status.equals("0")) {
            String error = parser.getValue("Error");
            logger.error("CertUtils: error: " + error);
            throw new IOException(error);
        }

        String b64 = parser.getValue("b64");
        logger.debug("CertUtils: cert: " + b64);

        b64 = CryptoUtil.normalizeCertAndReq(b64);
        byte[] b = CryptoUtil.base64Decode(b64);

        return new X509CertImpl(b);
    }

    public static boolean isAlgorithmValid(String signingKeyType, String algorithm) {
       return ((signingKeyType.equals("rsa") && algorithm.contains("RSA")) ||
               (signingKeyType.equals("ecc") && algorithm.contains("EC"))  ||
               (signingKeyType.equals("dsa") && algorithm.contains("DSA")));
    }

    /**
     * reads from the admin cert profile caAdminCert.profile and determines the algorithm as follows:
     *
     * 1.  First gets list of allowed algorithms from profile (constraint.params.signingAlgsAllowed)
     *     If entry does not exist, uses entry "ca.profiles.defaultSigningAlgsAllowed" from CS.cfg
     *     If that entry does not exist, uses basic default
     *
     * 2.  Gets default.params.signingAlg from profile.
     *     If entry does not exist or equals "-", selects first algorithm in allowed algorithm list
     *     that matches CA signing key type
     *     Otherwise returns entry if it matches signing CA key type.
     *
     * @throws EBaseException
     * @throws IOException
     * @throws FileNotFoundException
     */

    public static String getAdminProfileAlgorithm(
            String caSigningKeyType,
            String profileFilename,
            String defaultSigningAlgsAllowed) throws Exception {

        Properties props = new Properties();
        props.load(new FileInputStream(profileFilename));

        Set<String> keys = props.stringPropertyNames();
        Iterator<String> iter = keys.iterator();
        String defaultAlg = null;
        String[] algsAllowed = null;

        while (iter.hasNext()) {
            String key = iter.next();
            if (key.endsWith("default.params.signingAlg")) {
                defaultAlg = props.getProperty(key);
            }
            if (key.endsWith("constraint.params.signingAlgsAllowed")) {
                algsAllowed = StringUtils.split(props.getProperty(key), ",");
            }
        }

        if (algsAllowed == null) { //algsAllowed not defined in profile, use a global setting
            algsAllowed = StringUtils.split(defaultSigningAlgsAllowed, ",");
        }

        if (ArrayUtils.isEmpty(algsAllowed)) {
            throw new EBaseException("No allowed signing algorithms defined.");
        }

        if (StringUtils.isNotEmpty(defaultAlg) && !defaultAlg.equals("-")) {
            // check if the defined default algorithm is valid
            if (! isAlgorithmValid(caSigningKeyType, defaultAlg)) {
                throw new EBaseException("Administrator cert cannot be signed by specfied algorithm." +
                                         "Algorithm incompatible with signing key");
            }

            for (String alg : algsAllowed) {
                if (defaultAlg.trim().equals(alg.trim())) {
                    return defaultAlg;
                }
            }
            throw new EBaseException(
                    "Administrator Certificate cannot be signed by the specified algorithm " +
                    "as it is not one of the allowed signing algorithms.  Check the admin cert profile.");
        }

        // no algorithm specified.  Pick the first allowed algorithm.
        for (String alg : algsAllowed) {
            if (isAlgorithmValid(caSigningKeyType, alg)) return alg;
        }

        throw new EBaseException(
                "Admin certificate cannot be signed by any of the specified possible algorithms." +
                "Algorithm is incompatible with the CA signing key type" );
    }

    public static void verifySystemCertValidityByNickname(String nickname) throws Exception {

        logger.info("CertUtils: Validating certificate " + nickname);

        try {
            CryptoManager cm = CryptoManager.getInstance();
            org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(nickname);

            X509CertImpl impl = new X509CertImpl(cert.getEncoded());
            impl.checkValidity();

        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            String message = "Invalid certificate " + nickname + ": " + e.getMessage();
            logger.error(message, e);
            throw new Exception(message, e);

        } catch (Exception e) {
            String message = "Unable to validate certificate " + nickname + ": " + e.getMessage();
            logger.error(message, e);
            throw new Exception(message, e);
        }
    }

    /*
     * verify a certificate by its nickname
     * @throws Exception if something is wrong
     */
    public static void verifySystemCertByNickname(String nickname, String certusage) throws Exception {
        logger.debug("CertUtils: verifySystemCertByNickname(" + nickname + ", " + certusage + ")");
        CertificateUsage cu = getCertificateUsage(certusage);
        int ccu = 0;

        if (cu == null) {
            logger.debug("CertUtils: verifySystemCertByNickname() failed: " +
                    nickname + " with unsupported certusage =" + certusage);
            throw new Exception("Unsupported certificate usage " + certusage + " in certificate " + nickname);
        }

        if (certusage == null || certusage.equals(""))
            logger.debug("CertUtils: verifySystemCertByNickname(): required certusage not defined, getting current certusage");

        try {
            CryptoManager cm = CryptoManager.getInstance();
            if (cu.getUsage() != CertificateUsage.CheckAllUsages.getUsage()) {
                logger.debug("CertUtils: verifySystemCertByNickname(): calling verifyCertificate(" + nickname + ", true, " + cu + ")");
                try {
                    cm.verifyCertificate(nickname, true, cu);
                } catch (CertificateException e) {
                    throw new Exception("Certificate " + nickname + " is invalid: " + e.getMessage(), e);
                }

            } else {
                logger.debug("CertUtils: verifySystemCertByNickname(): calling isCertValid(" + nickname + ", true)");
                // find out about current cert usage
                ccu = cm.isCertValid(nickname, true);
                if (ccu == CertificateUsage.basicCertificateUsages) {
                    /* cert is good for nothing */
                    logger.error("CertUtils: verifySystemCertByNickname() failed: cert is good for nothing:" + nickname);
                    throw new Exception("Unusable certificate " + nickname);

                } else {
                    logger.debug("CertUtils: verifySystemCertByNickname() passed: " + nickname);

                    if ((ccu & CertificateUsage.SSLServer.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is SSLServer");
                    if ((ccu & CertificateUsage.SSLClient.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is SSLClient");
                    if ((ccu & CertificateUsage.SSLServerWithStepUp.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is SSLServerWithStepUp");
                    if ((ccu & CertificateUsage.SSLCA.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is SSLCA");
                    if ((ccu & CertificateUsage.EmailSigner.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is EmailSigner");
                    if ((ccu & CertificateUsage.EmailRecipient.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is EmailRecipient");
                    if ((ccu & CertificateUsage.ObjectSigner.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is ObjectSigner");
                    if ((ccu & CertificateUsage.UserCertImport.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is UserCertImport");
                    if ((ccu & CertificateUsage.VerifyCA.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is VerifyCA");
                    if ((ccu & CertificateUsage.ProtectedObjectSigner.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is ProtectedObjectSigner");
                    if ((ccu & CertificateUsage.StatusResponder.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is StatusResponder");
                    if ((ccu & CertificateUsage.AnyCA.getUsage()) != 0)
                        logger.debug("CertUtils: verifySystemCertByNickname(): cert is AnyCA");
                }
            }

        } catch (Exception e) {
            logger.error("CertUtils: verifySystemCertByNickname() failed: " + e.getMessage(), e);
            throw e;
        }
    }

    /*
     * verify a certificate by its tag name, do a full verification
     * @throws Exception if something is wrong
     */
    public static void verifySystemCertByTag(String tag) throws Exception {
        verifySystemCertByTag(tag,false);
    }
    /*
     * verify a certificate by its tag name
     * @throws Exception if something is wrong
     * perform optional validity check only
     */
    public static void verifySystemCertByTag(String tag,boolean checkValidityOnly) throws Exception {

        logger.debug("CertUtils: verifySystemCertByTag(" + tag + ")");

        CMSEngine engine = CMS.getCMSEngine();
        String auditMessage = null;
        EngineConfig config = engine.getConfig();

        try {
            String subsysType = config.getType();
            if (subsysType.equals("")) {
                logger.error("CertUtils: verifySystemCertByTag() cs.type not defined in CS.cfg. System certificates verification not done");
                throw new Exception("Missing cs.type in CS.cfg");
            }

            subsysType = toLowerCaseSubsystemType(subsysType);
            if (subsysType == null) {
                logger.error("CertUtils: verifySystemCerts() invalid cs.type in CS.cfg. System certificates verification not done");
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CIMC_CERT_VERIFICATION,
                            ILogger.SYSTEM_UID,
                            ILogger.FAILURE,
                            "");

                audit(auditMessage);
                throw new Exception("Invalid cs.type in CS.cfg");
            }

            String nickname = config.getString(subsysType + ".cert." + tag + ".nickname", "");
            if (nickname.equals("")) {
                logger.error("CertUtils: verifySystemCertByTag() nickname for cert tag " + tag + " undefined in CS.cfg");
                throw new Exception("Missing nickname for " + tag + " certificate");
            }

            String certusage = config.getString(subsysType + ".cert." + tag + ".certusage", "");
            if (certusage.equals("")) {
                logger.warn("CertUtils: verifySystemCertByTag() certusage for cert tag "
                        + tag + " undefined in CS.cfg, getting current certificate usage");
                // throw new Exception("Missing certificate usage for " + tag + " certificate"); ?
            }

            if(!checkValidityOnly) {
                verifySystemCertByNickname(nickname, certusage);
            } else {
                verifySystemCertValidityByNickname(nickname);
            }

            auditMessage = CMS.getLogMessage(
                    AuditEvent.CIMC_CERT_VERIFICATION,
                    ILogger.SYSTEM_UID,
                    ILogger.SUCCESS,
                        nickname);

            audit(auditMessage);

        } catch (Exception e) {
            logger.error("CertUtils: verifySystemCertsByTag() failed: " + e.getMessage(), e);
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CIMC_CERT_VERIFICATION,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE,
                        "");

            audit(auditMessage);
            throw e;
        }
    }

    /*
     * returns CertificateUsage mapping to JSS
     */
    public static CertificateUsage getCertificateUsage(String certusage) {
        CertificateUsage cu = null;
        if ((certusage == null) || certusage.equals(""))
            cu = CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("CheckAllUsages"))
            cu = CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("SSLServer"))
            cu = CertificateUsage.SSLServer;
        else if (certusage.equalsIgnoreCase("SSLServerWithStepUp"))
            cu = CertificateUsage.SSLServerWithStepUp;
        else if (certusage.equalsIgnoreCase("SSLClient"))
            cu = CertificateUsage.SSLClient;
        else if (certusage.equalsIgnoreCase("SSLCA"))
            cu = CertificateUsage.SSLCA;
        else if (certusage.equalsIgnoreCase("AnyCA"))
            cu = CertificateUsage.AnyCA;
        else if (certusage.equalsIgnoreCase("StatusResponder"))
            cu = CertificateUsage.StatusResponder;
        else if (certusage.equalsIgnoreCase("ObjectSigner"))
            cu = CertificateUsage.ObjectSigner;
        else if (certusage.equalsIgnoreCase("UserCertImport"))
            cu = CertificateUsage.UserCertImport;
        else if (certusage.equalsIgnoreCase("ProtectedObjectSigner"))
            cu = CertificateUsage.ProtectedObjectSigner;
        else if (certusage.equalsIgnoreCase("VerifyCA"))
            cu = CertificateUsage.VerifyCA;
        else if (certusage.equalsIgnoreCase("EmailSigner"))
            cu = CertificateUsage.EmailSigner;
        else if (certusage.equalsIgnoreCase("EmailRecipient"))
            cu = CertificateUsage.EmailRecipient;

        return cu;
    }

    /*
     * goes through all system certs and check to see if they are good
     * and audit the result
     * @throws Exception if something is wrong
     * optionally only check certs validity.
     */
    public static void verifySystemCerts(boolean checkValidityOnly) throws Exception {

        CMSEngine engine = CMS.getCMSEngine();
        String auditMessage = null;
        EngineConfig config = engine.getConfig();

        try {
            String subsysType = config.getType();
            if (subsysType.equals("")) {
                logger.error("CertUtils: verifySystemCerts() cs.type not defined in CS.cfg. System certificates verification not done");
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CIMC_CERT_VERIFICATION,
                            ILogger.SYSTEM_UID,
                            ILogger.FAILURE,
                            "");

                audit(auditMessage);
                throw new Exception("Missing cs.type in CS.cfg");
            }

            subsysType = toLowerCaseSubsystemType(subsysType);
            if (subsysType == null) {
                logger.error("CertUtils: verifySystemCerts() invalid cs.type in CS.cfg. System certificates verification not done");
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CIMC_CERT_VERIFICATION,
                            ILogger.SYSTEM_UID,
                            ILogger.FAILURE,
                            "");

                audit(auditMessage);
                throw new Exception("Invalid cs.type in CS.cfg");
            }

            String certlist = config.getString(subsysType + ".cert.list", "");
            if (certlist.equals("")) {
                logger.error("CertUtils: verifySystemCerts() "
                        + subsysType + ".cert.list not defined in CS.cfg. System certificates verification not done");
                auditMessage = CMS.getLogMessage(
                            AuditEvent.CIMC_CERT_VERIFICATION,
                            ILogger.SYSTEM_UID,
                            ILogger.FAILURE,
                            "");

                audit(auditMessage);
                throw new Exception("Missing " + subsysType + ".cert.list in CS.cfg");
            }

            StringTokenizer tokenizer = new StringTokenizer(certlist, ",");
            while (tokenizer.hasMoreTokens()) {
                String tag = tokenizer.nextToken();
                tag = tag.trim();
                logger.debug("CertUtils: verifySystemCerts() cert tag=" + tag);

                if (!checkValidityOnly) {
                    verifySystemCertByTag(tag);
                } else {
                    verifySystemCertByTag(tag, true);
                }
            }

        } catch (Exception e) {
            // audit here
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CIMC_CERT_VERIFICATION,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE,
                        "");

            audit(auditMessage);
            throw e;
        }
    }

    public static String toLowerCaseSubsystemType(String s) {
        if (s == null) {
            return null;
        }
        if (s.equalsIgnoreCase("CA")) {
            return "ca";
        } else if (s.equalsIgnoreCase("KRA")) {
            return "kra";
        } else if (s.equalsIgnoreCase("OCSP")) {
            return "ocsp";
        } else if (s.equalsIgnoreCase("TKS")) {
            return "tks";
        } else if (s.equalsIgnoreCase("TPS")) {
            return "tps";
        }
        return null;
    }

    public static void printRequestContent(IRequest request) {
        String method = "CertUtils.printRequestContent: ";
        logger.debug(method + "Content of request: ");
        Enumeration<String> ereq = request.getExtDataKeys();
        while (ereq.hasMoreElements()) {
            String reqKey = ereq.nextElement();
            String reqVal = request.getExtDataInString(reqKey);
            if (reqVal != null) {
                logger.debug("  req entry - " + reqKey + ": " + reqVal);
            } else {
                logger.debug("  req entry - " + reqKey + ": no value");
            }
        }
    }

    /*
     * addCTpoisonExt adds the Certificate Transparency V1 poison extension
     * to the Ceritificate Info
     *
     * @param certinfo X509CertInfo where the poison extension is to be added
     *
     * @author cfu
     */
    public static final String CT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3";
    public static final boolean CT_POISON_CRITICAL = true;
    public static final byte CT_POISON_DATA[] =  new byte[] { 0x05, 0x00 };

    public static void addCTv1PoisonExt(X509CertInfo certinfo)
                throws CertificateException, IOException, EBaseException {
        String method = "CryptoUtil:addCTv1PoisonExt: ";
        ObjectIdentifier ct_poison_oid = new ObjectIdentifier(CT_POISON_OID);
        Extension ct_poison_ext = null;
        CertificateExtensions exts =  null;

        exts = (CertificateExtensions)
                certinfo.get(X509CertInfo.EXTENSIONS);
        if (exts == null) {
            logger.debug(method + " X509CertInfo.EXTENSIONS not found inf cetinfo");
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", " X509CertInfo.EXTENSIONS not found inf cetinfo"));
        }
        DerOutputStream out = new DerOutputStream();
        out.putOctetString(CT_POISON_DATA);
        ct_poison_ext = new Extension(ct_poison_oid, CT_POISON_CRITICAL, out.toByteArray());
        //System.out.println(method + " ct_poison_ext id = " +
        //        ct_poison_ext.getExtensionId().toString());
        certinfo.set(X509CertInfo.EXTENSIONS, exts);

        exts.set(CT_POISON_OID, ct_poison_ext);
        certinfo.delete(X509CertInfo.EXTENSIONS);
        certinfo.set(X509CertInfo.EXTENSIONS, exts);
    }

    /*
     * for debugging
     */
    public static void printExtensions(CertificateExtensions exts) {

        String method = "CryptoUtil.printExtensions: ";
        System.out.println(method + "begins");
        try {
            if (exts == null)
                return;

            Enumeration<String> e = exts.getNames();
            while (e.hasMoreElements()) {
                String n = e.nextElement();
                Extension ext = (Extension) exts.get(n);

                System.out.println(" ---- " + ext.getExtensionId().toString());
            }
        } catch (Exception e) {
            System.out.println(method + e.toString());
        }
        System.out.println(method + "ends");
    }

    /**
     * Write the int as a big-endian byte[] of fixed width (in bytes).
     */
    public static byte[] intToFixedWidthBytes(int n, int width) {
        byte[] out = new byte[width];
        for (int i = 0; i < width; i++) {
            out[i] = (byte) (n >> ((width - i - 1) * 8));
        }
        return out;
    }

    /*
     * from byte array to hex in String
     */
    public static String bytesToHex(byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Signed Audit Log
     * This method is called to store messages to the signed audit log.
     *
     * @param msg signed audit log message
     */
    private static void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    public static boolean certInCertChain(X509Certificate[] certChain, X509Certificate cert) {

        for (X509Certificate c : certChain) {
            if (!cert.equals(c)) continue;
            return true;
        }

        return false;
    }
}
