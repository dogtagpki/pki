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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs11;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

/**
 * @author Endi S. Dewata
 */
public class PKCS11CertCLI extends CLI {

    public PKCS11CertCLI(PKCS11CLI parent) {
        super("cert", "PKCS #11 certificate management commands", parent);

        addModule(new PKCS11CertFindCLI(this));
        addModule(new PKCS11CertShowCLI(this));
        addModule(new PKCS11CertRemoveCLI(this));
    }

    public static void printCertInfo(String alias, Certificate cert) throws CertificateEncodingException, CertificateException {

        System.out.println("  Cert ID: " + alias);
        System.out.println("  Type: " + cert.getType());

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());

        CertId serialNumber = new CertId(certImpl.getSerialNumber());
        System.out.println("  Serial Number: " + serialNumber.toHexString());
        System.out.println("  Subject DN: " + certImpl.getSubjectDN());
        System.out.println("  Issuer DN: " + certImpl.getIssuerDN());
    }
}
