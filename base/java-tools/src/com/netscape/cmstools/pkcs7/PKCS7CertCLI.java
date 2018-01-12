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

package com.netscape.cmstools.pkcs7;

import java.security.cert.X509Certificate;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;

public class PKCS7CertCLI extends CLI {

    public PKCS7CertCLI(PKCS7CLI parent) {
        super("cert", "PKCS #7 certificate management commands", parent);

        addModule(new PKCS7CertFindCLI(this));
        addModule(new PKCS7CertExportCLI(this));
    }

    public static void printCertInfo(X509Certificate cert) throws Exception {

        System.out.println("  Serial Number: " + new CertId(cert.getSerialNumber()).toHexString());
        System.out.println("  Subject DN: " + cert.getSubjectDN());
        System.out.println("  Issuer DN: " + cert.getIssuerDN());
    }
}
