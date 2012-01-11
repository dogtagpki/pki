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
package netscape.security.extensions;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

/**
 * Extends X509CertInfo class so that minimal fields are initialized at
 * creation time so an object of this type is always serializable.
 */
public class CertInfo extends X509CertInfo {
    /**
     *
     */
    private static final long serialVersionUID = -2883888348288591989L;
    public static final CertificateSubjectName SERIALIZE_SUBJECT;
    public static final CertificateIssuerName SERIALIZE_ISSUER;
    public static final CertificateValidity SERIALIZE_VALIDITY;
    public static final CertificateSerialNumber SERIALIZE_SERIALNO;
    public static final CertificateAlgorithmId SERIALIZE_ALGOR;
    public static final CertificateVersion FORCE_VERSION_3;

    static {
        try {
            // force version 3
            FORCE_VERSION_3 =
                    new CertificateVersion(CertificateVersion.V3);
            SERIALIZE_SUBJECT =
                    new CertificateSubjectName(
                            new X500Name("cn=uninitialized"));
            SERIALIZE_ISSUER =
                    new CertificateIssuerName(
                            new X500Name("cn=uninitialized"));
            SERIALIZE_VALIDITY =
                    new CertificateValidity(new Date(0), new Date(0));
            SERIALIZE_SERIALNO =
                    new CertificateSerialNumber(new BigInteger("0"));
            SERIALIZE_ALGOR =
                    new CertificateAlgorithmId(
                            AlgorithmId.getAlgorithmId("MD5withRSA"));
        } catch (IOException e) {
            // should never happen. If does, system is hosed. 
            System.out.println("**** Impossible Error encountered ****");
            throw new RuntimeException(e.toString());
        } catch (NoSuchAlgorithmException e) {
            // should never happen. If does, system is hosed. 
            System.out.println("**** Impossible Error encountered ****");
            throw new RuntimeException(e.toString());
        }
    }

    /**
     * Initializes most fields required by der encoding so object will
     * serialize properly.
     */
    // XXX should write a class to use something else for serialization
    // but this is faster and done now for the time crunch.
    public CertInfo() {
        super();
        makeSerializable(this);
    }

    public static void makeSerializable(X509CertInfo certinfo) {
        try {
            // force version 3.
            certinfo.set(X509CertInfo.VERSION, FORCE_VERSION_3);

            if (certinfo.get(X509CertInfo.SERIAL_NUMBER) == null) {
                certinfo.set(X509CertInfo.SERIAL_NUMBER, SERIALIZE_SERIALNO);
            }
            if (certinfo.get(X509CertInfo.ALGORITHM_ID) == null) {
                certinfo.set(X509CertInfo.ALGORITHM_ID, SERIALIZE_ALGOR);
            }
            if (certinfo.get(X509CertInfo.ISSUER) == null) {
                certinfo.set(X509CertInfo.ISSUER, SERIALIZE_ISSUER);
            }
            if (certinfo.get(X509CertInfo.VALIDITY) == null) {
                certinfo.set(X509CertInfo.VALIDITY, SERIALIZE_VALIDITY);
            }
            // set subject name anyway - it'll get overwritten.
            if (certinfo.get(X509CertInfo.SUBJECT) == null) {
                certinfo.set(X509CertInfo.SUBJECT, SERIALIZE_SUBJECT);
            }
            // key is set later in the request.
        } // these exceptions shouldn't happen here unless the 
          // whole process is hosed.
        catch (CertificateException e) {
        } catch (IOException e) {
        }
    }
}
