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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs12;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12CertInfo;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertCLI extends CLI {

    public PKCS12CLI pkcs12CLI;

    public PKCS12CertCLI(PKCS12CLI pkcs12CLI) {
        super("cert", "PKCS #12 certificate management commands", pkcs12CLI);
        this.pkcs12CLI = pkcs12CLI;

        addModule(new PKCS12CertAddCLI(this));
        addModule(new PKCS12CertExportCLI(this));
        addModule(new PKCS12CertImportCLI(this));
        addModule(new PKCS12CertFindCLI(this));
        addModule(new PKCS12CertModCLI(this));
        addModule(new PKCS12CertRemoveCLI(this));
    }

    public static void printCertInfo(PKCS12 pkcs12, PKCS12CertInfo certInfo) throws Exception {

        String hexCertID = "0x" + Utils.HexEncode(certInfo.getID());
        System.out.println("  Certificate ID: " + hexCertID);

        System.out.println("  Serial Number: " + new CertId(certInfo.getCert().getSerialNumber()).toHexString());
        System.out.println("  Friendly Name: " + certInfo.getFriendlyName());
        System.out.println("  Subject DN: " + certInfo.getCert().getSubjectName());
        System.out.println("  Issuer DN: " + certInfo.getCert().getIssuerName());

        if (certInfo.getTrustFlags() != null) {
            System.out.println("  Trust Flags: " + certInfo.getTrustFlags());
        }

        byte[] keyID = certInfo.getKeyID();
        System.out.println("  Has Key: " + (keyID != null));
        if (keyID != null) {
            String hexKeyID = "0x" + Utils.HexEncode(keyID);
            System.out.println("  Key ID: " + hexKeyID);
        }
    }
}
