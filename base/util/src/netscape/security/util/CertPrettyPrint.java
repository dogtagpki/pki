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
package netscape.security.util;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.TimeZone;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.SignedData;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CertPrettyPrint {

    /*==========================================================
     * constants
     *==========================================================*/
    private final static String CUSTOM_LOCALE = "Custom";

    /*==========================================================
     * variables
     *==========================================================*/
    private X509CertImpl mX509Cert = null;
    private PrettyPrintFormat pp = null;
    private byte[] mCert_b = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    public CertPrettyPrint(Certificate cert) {
        if (cert instanceof X509CertImpl)
            mX509Cert = (X509CertImpl) cert;

        pp = new PrettyPrintFormat(":");
    }

    public CertPrettyPrint(byte[] certb) {
        mCert_b = certb;
        pp = new PrettyPrintFormat(":");
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * This method return string representation of the certificate
     * in predefined format using specified client local. I18N Support.
     *
     * @param clientLocale Locale to be used for localization
     * @return string representation of the certificate
     */
    public String toString(Locale clientLocale) {

        if (mX509Cert != null)
            return X509toString(clientLocale);
        else if (mCert_b != null)
            return pkcs7toString(clientLocale);
        else
            return null;
    }

    public String pkcs7toString(Locale clientLocale) {
        StringBuffer content=new StringBuffer();

        try {
            mX509Cert = new X509CertImpl(mCert_b);
            return toString(clientLocale);
        } catch (Exception e) {
        }

        ContentInfo ci = null;
        try {
            ci = (ContentInfo)
                    ASN1Util.decode(ContentInfo.getTemplate(), mCert_b);
        } catch (Exception e) {
            return "";
        }

        if (ci.getContentType().equals(ContentInfo.SIGNED_DATA)) {
            SignedData sd = null;
            try {
                sd = (SignedData) ci.getInterpretedContent();
            } catch (Exception e) {
                return "";
            }

            if (sd.hasCertificates()) {
                SET certs = sd.getCertificates();

                for (int i = 0; i < certs.size(); i++) {
                    org.mozilla.jss.pkix.cert.Certificate cert =
                            (org.mozilla.jss.pkix.cert.Certificate) certs.elementAt(i);
                    X509CertImpl certImpl = null;
                    try {
                        certImpl = new X509CertImpl(
                                ASN1Util.encode(cert));
                    } catch (Exception e) {
                    }

                    CertPrettyPrint print = new CertPrettyPrint(certImpl);
                    content.append(print.toString(Locale.getDefault()));
                    content.append("\n");
                }

                return content.toString();
            }
        }

        return content.toString();
    }

    public String stripCertBrackets(String s) {
        if (s == null) {
            return s;
        }

        if ((s.startsWith("-----BEGIN CERTIFICATE-----")) &&
                (s.endsWith("-----END CERTIFICATE-----"))) {
            return (s.substring(27, (s.length() - 25)));
        }

        // To support Thawte's header and footer
        if ((s.startsWith("-----BEGIN PKCS #7 SIGNED DATA-----")) &&
                (s.endsWith("-----END PKCS #7 SIGNED DATA-----"))) {
            return (s.substring(35, (s.length() - 33)));
        }

        return s;
    }

    public String normalizeCertStr(String s) {
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

    public String X509toString(Locale clientLocale) {

        //get I18N resources
        ResourceBundle resource = ResourceBundle.getBundle(
                PrettyPrintResources.class.getName());
        DateFormat dateFormater = DateFormat.getDateTimeInstance(
                DateFormat.FULL, DateFormat.FULL, clientLocale);
        //get timezone and timezone ID
        String tz = " ";
        String tzid = " ";

        StringBuffer sb = new StringBuffer();

        try {
            X509CertInfo info = (X509CertInfo) mX509Cert.get(
                    X509CertImpl.NAME + "." + X509CertImpl.INFO);
            String serial2 = mX509Cert.getSerialNumber().toString(16).toUpperCase();

            //get correct instance of key
            PublicKey pKey = mX509Cert.getPublicKey();
            X509Key key = null;

            if (pKey instanceof CertificateX509Key) {
                CertificateX509Key certKey = (CertificateX509Key) pKey;

                key = (X509Key) certKey.get(CertificateX509Key.KEY);
            }
            if (pKey instanceof X509Key) {
                key = (X509Key) pKey;
            }

            //take care of spki
            sb.append(pp.indent(4) + resource.getString(
                    PrettyPrintResources.TOKEN_CERTIFICATE) + "\n");
            sb.append(pp.indent(8) + resource.getString(
                    PrettyPrintResources.TOKEN_DATA) + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_VERSION) + " v");
            sb.append((mX509Cert.getVersion() + 1) + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SERIAL) + "0x" + serial2 + "\n");
            //XXX I18N Algorithm Name ?
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGALG) + mX509Cert.getSigAlgName() +
                    " - " + mX509Cert.getSigAlgOID() + "\n");
            //XXX I18N IssuerDN ?
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_ISSUER) +
                    mX509Cert.getIssuerDN().toString() + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_VALIDITY) + "\n");
            String notBefore = dateFormater.format(mX509Cert.getNotBefore());
            String notAfter = dateFormater.format(mX509Cert.getNotAfter());

            //get timezone and timezone ID
            if (TimeZone.getDefault() != null) {
                tz = TimeZone.getDefault().getDisplayName(
                            TimeZone.getDefault().inDaylightTime(
                                    mX509Cert.getNotBefore()),
                            TimeZone.SHORT,
                            clientLocale);
                tzid = TimeZone.getDefault().getID();
            }
            // Specify notBefore
            if (tz.equals(tzid) || tzid.equals(CUSTOM_LOCALE)) {
                // Do NOT append timezone ID
                sb.append(pp.indent(16)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_NOT_BEFORE)
                        + notBefore
                        + "\n");
            } else {
                // Append timezone ID
                sb.append(pp.indent(16)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_NOT_BEFORE)
                        + notBefore
                        + " " + tzid + "\n");
            }
            // re-get timezone (just in case it is different . . .)
            if (TimeZone.getDefault() != null) {
                tz = TimeZone.getDefault().getDisplayName(
                            TimeZone.getDefault().inDaylightTime(
                                    mX509Cert.getNotAfter()),
                            TimeZone.SHORT,
                            clientLocale);
            }
            // Specify notAfter
            if (tz.equals(tzid) || tzid.equals(CUSTOM_LOCALE)) {
                // Do NOT append timezone ID
                sb.append(pp.indent(16)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_NOT_AFTER)
                        + notAfter
                        + "\n");
            } else {
                // Append timezone ID
                sb.append(pp.indent(16)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_NOT_AFTER)
                        + notAfter
                        + " " + tzid + "\n");
            }
            //XXX I18N SubjectDN ?
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SUBJECT) +
                    mX509Cert.getSubjectDN().toString() + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SPKI) + "\n");

            PubKeyPrettyPrint pkpp = new PubKeyPrettyPrint(key);

            sb.append(pkpp.toString(clientLocale, 16, 16));

            //take care of extensions
            CertificateExtensions extensions = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);

            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_EXTENSIONS) + "\n");
            if (extensions != null)
                for (int i = 0; i < extensions.size(); i++) {
                    Extension ext = extensions.elementAt(i);
                    ExtPrettyPrint extpp = new ExtPrettyPrint(ext, 16);

                    sb.append(extpp.toString());
                }

            //take care of signature
            sb.append(pp.indent(8) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGNATURE) + "\n");
            //XXX I18N Algorithm Name ?
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_ALGORITHM) +
                    mX509Cert.getSigAlgName() + " - " + mX509Cert.getSigAlgOID() + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGNATURE) + "\n");
            sb.append(pp.toHexString(mX509Cert.getSignature(), 16, 16));

            // fingerprints
            String[] hashes = new String[] { "MD2", "MD5", "SHA-1", "SHA-256", "SHA-512" };
            StringBuffer certFingerprints = new StringBuffer();

            sb.append(pp.indent(8) + "FingerPrint\n");
            for (int i = 0; i < hashes.length; i++) {
                MessageDigest md = MessageDigest.getInstance(hashes[i]);

                md.update(mX509Cert.getEncoded());
                certFingerprints.append(pp.indent(12) + hashes[i] + ":\n" +
                        pp.toHexString(md.digest(), 16, 16));
            }

            sb.append(certFingerprints.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return sb.toString();
    }

}
