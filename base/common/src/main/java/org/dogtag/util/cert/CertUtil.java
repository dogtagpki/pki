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
package org.dogtag.util.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.StringTokenizer;

import org.mozilla.jss.CertificateUsage;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkcs11.PK11Store;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertUtil {

    public final static Logger logger = LoggerFactory.getLogger(CertUtil.class);

    public static final String CERT_NEW_REQUEST_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String CERT_NEW_REQUEST_FOOTER = "-----END NEW CERTIFICATE REQUEST-----";

    public static final String CERT_RENEWAL_HEADER = "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
    public static final String CERT_RENEWAL_FOOTER = "-----END RENEWAL CERTIFICATE REQUEST-----";

    public static final String CRL_HEADER = "-----BEGIN CERTIFICATE REVOCATION LIST-----";
    public static final String CRL_FOOTER = "-----END CERTIFICATE REVOCATION LIST-----";

    public static final int LINE_COUNT = 76;

    /**
     * Convert PKCS #10 request from PEM to Base64.
     */
    public static String unwrapPKCS10(String request, boolean checkHeader) throws EBaseException {

        // check for "-----BEGIN NEW CERTIFICATE REQUEST-----"
        int headerIndex = request.indexOf(CERT_NEW_REQUEST_HEADER);
        int footerIndex = request.indexOf(CERT_NEW_REQUEST_FOOTER);

        String header = null;
        if (headerIndex >= 0 || footerIndex >= 0) {
            header = CERT_NEW_REQUEST_HEADER;
        }

        // check for "-----BEGIN CERTIFICATE REQUEST-----"
        if (header == null) {
            headerIndex = request.indexOf(Cert.REQUEST_HEADER);
            footerIndex = request.indexOf(Cert.REQUEST_FOOTER);

            if (headerIndex >= 0 || footerIndex >= 0) {
                header = Cert.REQUEST_HEADER;
            }
        }

        // check for "-----BEGIN RENEWAL CERTIFICATE REQUEST-----"
        if (header == null) {
            headerIndex = request.indexOf(CERT_RENEWAL_HEADER);
            footerIndex = request.indexOf(CERT_RENEWAL_FOOTER);

            if (headerIndex >= 0 || footerIndex >= 0) {
                header = CERT_RENEWAL_HEADER;
            }
        }

        // check for missing header/footer
        if (headerIndex < 0 && checkHeader) {
            throw new EBaseException("Missing PKCS #10 header");
        }

        if (footerIndex < 0 && checkHeader) {
            throw new EBaseException("Missing PKCS #10 footer");
        }

        // unwrap request
        if (header != null) {
            request = request.substring(headerIndex + header.length(), footerIndex);
        }

        // strip whitespaces
        StringTokenizer st = new StringTokenizer(request, "\t\r\n ");
        StringBuilder sb = new StringBuilder();

        while (st.hasMoreTokens()) {
            sb.append(st.nextToken());
        }

        return sb.toString();
    }

    public static byte[] parseCSR(String csr) {

        if (csr == null) {
            return null;
        }

        csr = csr.replaceAll(Cert.REQUEST_HEADER, "");
        csr = csr.replaceAll(CERT_NEW_REQUEST_HEADER, "");
        csr = csr.replaceAll(Cert.REQUEST_FOOTER, "");
        csr = csr.replaceAll(CERT_NEW_REQUEST_FOOTER, "");

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(csr, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();

            nextLine = nextLine.trim();
            if (nextLine.equals(Cert.REQUEST_HEADER))
                continue;
            if (nextLine.equals(CERT_NEW_REQUEST_HEADER))
                continue;
            if (nextLine.equals(Cert.REQUEST_FOOTER))
                continue;
            if (nextLine.equals(CERT_NEW_REQUEST_FOOTER))
                continue;
            sb.append(nextLine);
        }

        return Utils.base64decode(sb.toString());
    }

    public static CertReqMsg[] parseCRMF(Locale locale, String certreq) throws Exception {

        logger.debug("CertUtil: Parsing CRMF request");

        if (certreq == null) {
            logger.error("CertUtil: Missing CRMF request");
            throw new EProfileException("Missing CRMF request");
        }

        byte[] data = parseCSR(certreq);

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
            throw new EProfileException("Unable to parse CRMF request: " + e.getMessage(), e);
        }
    }

    public static PKCS10 decodePKCS10(String req) throws EBaseException {
        String normalized = unwrapPKCS10(req, true);

        try {
            byte[] decodedBytes = Utils.base64decode(normalized);
            return new PKCS10(decodedBytes);

        } catch (Exception e) {
            throw new EBaseException("Unable to decode PKCS #10 request: " + e.getMessage(), e);
        }
    }

    public static String toPEM(PKCS10 pkcs10) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(os)) {
            pkcs10.print(out);
        }
        return os.toString();
    }

    public static String toPEM(X509Certificate cert) throws Exception {
        return Cert.HEADER + "\n" +
                Utils.base64encodeMultiLine(cert.getEncoded()) +
                Cert.FOOTER + "\n";
    }

    /*
     * formats a cert fingerprints
     */
    public static String fingerPrintFormat(String content) {
        if (content == null || content.length() == 0) {
            return "";
        }

        StringBuffer result = new StringBuffer();
        result.append("Fingerprints:\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT));
            result.append("\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0)
            result.append(content);
        result.append("\n");

        return result.toString();
    }

    public static void deleteCert(String tokenname, org.mozilla.jss.crypto.X509Certificate cert)
            throws Exception {

        logger.debug("CertUtil: deleting cert " + cert.getNickname());

        CryptoToken tok = CryptoUtil.getKeyStorageToken(tokenname);
        CryptoStore store = tok.getCryptoStore();

        if (store instanceof PK11Store) {
            PK11Store pk11store = (PK11Store) store;
            pk11store.deleteCertOnly(cert);
            logger.debug("CertUtil: cert deleted successfully");

        } else {
            logger.warn("CertUtil: unsupported crypto store: " + store.getClass().getName());
        }
    }

    public static CertificateExtensions createRequestExtensions(PKCS10 pkcs10) throws Exception {

        PKCS10Attributes attrs = pkcs10.getAttributes();
        PKCS10Attribute extsAttr = attrs.getAttribute(CertificateExtensions.NAME);

        CertificateExtensions extensions;

        if (extsAttr != null && extsAttr.getAttributeId().equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {

            Extensions exts = (Extensions) extsAttr.getAttributeValue();

            // convert Extensions into CertificateExtensions
            DerOutputStream os = new DerOutputStream();
            exts.encode(os);
            DerInputStream is = new DerInputStream(os.toByteArray());

            extensions = new CertificateExtensions(is);

        } else {
            extensions = new CertificateExtensions();
        }

        return extensions;
    }

    /**
     * Get SAN extension from a collection of extensions.
     */
    public static SubjectAlternativeNameExtension getSANExtension(Extensions extensions) throws Exception {

        Enumeration<Extension> e = extensions.elements();

        while (e.hasMoreElements()) {
            Extension extension = e.nextElement();

            if (extension instanceof SubjectAlternativeNameExtension) {
                return (SubjectAlternativeNameExtension) extension;
            }
        }

        return null;
    }

    /**
     * Get SAN extension from PKCS #10 request.
     */
    public static SubjectAlternativeNameExtension getSANExtension(PKCS10 pkcs10) throws Exception {

        PKCS10Attributes attributes = pkcs10.getAttributes();

        for (PKCS10Attribute attribute : attributes) {
            CertAttrSet attrValues = attribute.getAttributeValue();

            if (attrValues instanceof Extensions) {
                Extensions extensions = (Extensions) attrValues;
                return getSANExtension(extensions);
            }
        }

        return null;
    }

    /**
     * Get DNS names from SAN extension.
     */
    public static Set<String> getDNSNames(SubjectAlternativeNameExtension sanExtension) throws Exception {

        Set<String> dnsNames = new HashSet<>();

        GeneralNames generalNames = sanExtension.getGeneralNames();
        for (GeneralNameInterface generalName : generalNames) {

            if (generalName instanceof GeneralName) {
                generalName = ((GeneralName) generalName).unwrap();
            }

            if (generalName instanceof DNSName) {
                String dnsName = ((DNSName) generalName).getValue();
                dnsNames.add(dnsName.toLowerCase());
                continue;
            }

            // Unsupported identifier type
            //
            // We cannot allow this to pass through, otherwise a CSR
            // with unvalidated SAN values will be passed along to the
            // CA, and these are likely to be accepted as-is.
            //
            // This is also required by RFC 8555 Section 7.4:
            //
            //    The CSR MUST indicate the exact same set of requested
            //    identifiers as the initial newOrder request.
            //
            throw new Exception("Unsupported identifier: " + generalName);
        }

        return dnsNames;
    }

    public static String getCommonName(X500Name name) throws Exception {
        try {
            return name.getCommonName();
        } catch (NullPointerException e) {
            // X500Name.getCommonName() throws NPE if the X.500 name is blank
            // TODO: fix X500Name.getCommonName() to return null instead
            return null;
        }
    }

    /**
     * Get DNS names from PKCS #10 request.
     */
    public static Set<String> getDNSNames(PKCS10 pkcs10) throws Exception {

        Set<String> dnsNames = new HashSet<>();

        X500Name subjectDN = pkcs10.getSubjectName();
        logger.info("Getting CN from subject DN: " + subjectDN);

        String cn = getCommonName(subjectDN);
        if (cn != null) {
            dnsNames.add(cn.toLowerCase());
        }

        logger.info("Getting SAN extension from CSR");
        SubjectAlternativeNameExtension sanExtension = getSANExtension(pkcs10);
        if (sanExtension != null) {
            logger.info("Getting DNS names from SAN extension");
            dnsNames.addAll(getDNSNames(sanExtension));
        }

        return dnsNames;
    }

    /**
     * Convert cert usage string into CertificateUsage object.
     */
    public static CertificateUsage toCertificateUsage(String certUsage) throws Exception {

        if (certUsage == null || certUsage.equals(""))
            return CertificateUsage.CheckAllUsages;

        if (certUsage.equalsIgnoreCase("CheckAllUsages"))
            return CertificateUsage.CheckAllUsages;

        if (certUsage.equalsIgnoreCase("SSLClient"))
            return CertificateUsage.SSLClient;

        if (certUsage.equalsIgnoreCase("SSLServer"))
            return CertificateUsage.SSLServer;

        if (certUsage.equalsIgnoreCase("SSLServerWithStepUp"))
            return CertificateUsage.SSLServerWithStepUp;

        if (certUsage.equalsIgnoreCase("SSLCA"))
            return CertificateUsage.SSLCA;

        if (certUsage.equalsIgnoreCase("EmailSigner"))
            return CertificateUsage.EmailSigner;

        if (certUsage.equalsIgnoreCase("EmailRecipient"))
            return CertificateUsage.EmailRecipient;

        if (certUsage.equalsIgnoreCase("ObjectSigner"))
            return CertificateUsage.ObjectSigner;

        if (certUsage.equalsIgnoreCase("UserCertImport"))
            return CertificateUsage.UserCertImport;

        if (certUsage.equalsIgnoreCase("VerifyCA"))
            return CertificateUsage.VerifyCA;

        if (certUsage.equalsIgnoreCase("ProtectedObjectSigner"))
            return CertificateUsage.ProtectedObjectSigner;

        if (certUsage.equalsIgnoreCase("StatusResponder"))
            return CertificateUsage.StatusResponder;

        if (certUsage.equalsIgnoreCase("AnyCA"))
            return CertificateUsage.AnyCA;

        if (certUsage.equalsIgnoreCase("IPsec"))
            return CertificateUsage.IPsec;

        throw new Exception("Unsupported certificate usage: " + certUsage);
    }

    /**
     * Get certificate usages.
     */
    public static Set<CertificateUsage> getCertificateUsages(String nickname) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        logger.debug("CertUtil: Calling CryptoManager.isCertValid(" + nickname + ", true)");
        int currentUsages = cm.isCertValid(nickname, true);

        logger.debug("CertUtil: Certificate usages: " + currentUsages);
        Set<CertificateUsage> usages = new LinkedHashSet<>();

        if ((currentUsages & CertificateUsage.SSLClient.getUsage()) != 0)
            usages.add(CertificateUsage.SSLClient);

        if ((currentUsages & CertificateUsage.SSLServer.getUsage()) != 0)
            usages.add(CertificateUsage.SSLServer);

        if ((currentUsages & CertificateUsage.SSLServerWithStepUp.getUsage()) != 0)
            usages.add(CertificateUsage.SSLServerWithStepUp);

        if ((currentUsages & CertificateUsage.SSLCA.getUsage()) != 0)
            usages.add(CertificateUsage.SSLCA);

        if ((currentUsages & CertificateUsage.EmailSigner.getUsage()) != 0)
            usages.add(CertificateUsage.EmailSigner);

        if ((currentUsages & CertificateUsage.EmailRecipient.getUsage()) != 0)
            usages.add(CertificateUsage.EmailRecipient);

        if ((currentUsages & CertificateUsage.ObjectSigner.getUsage()) != 0)
            usages.add(CertificateUsage.ObjectSigner);

        if ((currentUsages & CertificateUsage.UserCertImport.getUsage()) != 0)
            usages.add(CertificateUsage.UserCertImport);

        if ((currentUsages & CertificateUsage.VerifyCA.getUsage()) != 0)
            usages.add(CertificateUsage.VerifyCA);

        if ((currentUsages & CertificateUsage.ProtectedObjectSigner.getUsage()) != 0)
            usages.add(CertificateUsage.ProtectedObjectSigner);

        if ((currentUsages & CertificateUsage.StatusResponder.getUsage()) != 0)
            usages.add(CertificateUsage.StatusResponder);

        if ((currentUsages & CertificateUsage.AnyCA.getUsage()) != 0)
            usages.add(CertificateUsage.AnyCA);

        if ((currentUsages & CertificateUsage.IPsec.getUsage()) != 0)
            usages.add(CertificateUsage.IPsec);

        return usages;
    }

    /**
     * Verify certificate usage.
     */
    public static void verifyCertificateUsage(String nickname, String certUsage) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CertificateUsage cu = CertUtil.toCertificateUsage(certUsage);

        if (cu.getUsage() == CertificateUsage.CheckAllUsages.getUsage()) {
            // check all possible usages
            int currentUsages = cm.isCertValid(nickname, true);
            if (currentUsages == CertificateUsage.basicCertificateUsages) {
                throw new Exception("Certificate is unusable");
            }
            return;
        }

        // check the specified usage
        cm.verifyCertificate(nickname, true, cu);
    }

    /**
     * Verify that the cert is currently valid (notBefore &lt;= now &lt;= notAfter).
     */
    public static void verifyCertValidity(String nickname) throws Exception {

        logger.info("CertUtil: Checking cert validity for " + nickname);

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
}
