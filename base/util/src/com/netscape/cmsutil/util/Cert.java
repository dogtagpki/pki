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
package com.netscape.cmsutil.util;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import netscape.security.pkcs.PKCS7;
import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.crypto.SignatureAlgorithm;

public class Cert {

    public static SignatureAlgorithm mapAlgorithmToJss(String algname) {
        if (algname.equals("MD5withRSA"))
            return SignatureAlgorithm.RSASignatureWithMD5Digest;
        else if (algname.equals("MD2withRSA"))
            return SignatureAlgorithm.RSASignatureWithMD2Digest;
        else if (algname.equals("SHA1withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA1Digest;
        else if (algname.equals("SHA1withDSA"))
            return SignatureAlgorithm.DSASignatureWithSHA1Digest;
        else if (algname.equals("SHA256withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA256Digest;
        else if (algname.equals("SHA512withRSA"))
            return SignatureAlgorithm.RSASignatureWithSHA512Digest;
        else if (algname.equals("SHA1withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA1Digest;
        else if (algname.equals("SHA256withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA256Digest;
        else if (algname.equals("SHA384withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA384Digest;
        else if (algname.equals("SHA512withEC"))
            return SignatureAlgorithm.ECSignatureWithSHA512Digest;
        return null;
    }

    public static String stripBrackets(String s) {
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

    public static String stripCertBrackets(String s) {
        return stripBrackets(s);
    }

    // private static BASE64Decoder mDecoder = new BASE64Decoder();
    public static X509CertImpl mapCert(String mime64)
            throws IOException {
        mime64 = stripCertBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
        byte rawPub[] = Utils.base64decode(newval);
        X509CertImpl cert = null;

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
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
        byte rawPub[] = Utils.base64decode(newval);
        PKCS7 p7 = null;

        try {
            p7 = new PKCS7(rawPub);
        } catch (Exception e) {
            throw new IOException("p7 is null");
        }
        return p7.getCertificates();
    }

    public static X509CRL mapCRL(String mime64)
            throws IOException {
        mime64 = stripCRLBrackets(mime64.trim());
        String newval = normalizeCertStr(mime64);
        // byte rawPub[] = mDecoder.decodeBuffer(newval);
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

    public static String normalizeCertStrAndReq(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }
}
