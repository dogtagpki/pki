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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.pkcs11.PK11Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertUtil {

    public final static Logger logger = LoggerFactory.getLogger(CertUtil.class);

    static final int LINE_COUNT = 76;

    public static byte[] parseCSR(String csr) {

        if (csr == null) {
            return null;
        }

        csr = csr.replaceAll(Cert.REQUEST_HEADER, "");
        csr = csr.replaceAll("-----BEGIN NEW CERTIFICATE REQUEST-----", "");
        csr = csr.replaceAll(Cert.REQUEST_FOOTER, "");
        csr = csr.replaceAll("-----END NEW CERTIFICATE REQUEST-----", "");

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(csr, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();

            nextLine = nextLine.trim();
            if (nextLine.equals(Cert.REQUEST_HEADER))
                continue;
            if (nextLine.equals("-----BEGIN NEW CERTIFICATE REQUEST-----"))
                continue;
            if (nextLine.equals(Cert.REQUEST_FOOTER))
                continue;
            if (nextLine.equals("-----END NEW CERTIFICATE REQUEST-----"))
                continue;
            sb.append(nextLine);
        }

        return Utils.base64decode(sb.toString());
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
                return CertUtil.getSANExtension(extensions);
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

    /**
     * Get DNS names from PKCS #10 request.
     */
    public static Set<String> getDNSNames(PKCS10 pkcs10) throws Exception {

        Set<String> dnsNames = new HashSet<>();

        X500Name subjectDN = pkcs10.getSubjectName();
        logger.info("Getting DNS name from subject DN: " + subjectDN);

        String cn;
        try {
            cn = subjectDN.getCommonName();

        } catch (NullPointerException e) {
            // X500Name.getCommonName() throws NPE if subject DN is blank
            // TODO: fix X500Name.getCommonName() to return null
            cn = null;
        }

        if (cn != null) {
            dnsNames.add(cn.toLowerCase());
        }

        logger.info("Getting SAN extension from CSR");
        SubjectAlternativeNameExtension sanExtension = CertUtil.getSANExtension(pkcs10);

        if (sanExtension != null) {
            logger.info("Getting DNS names from SAN extension");
            dnsNames.addAll(CertUtil.getDNSNames(sanExtension));
        }

        return dnsNames;
    }
}
