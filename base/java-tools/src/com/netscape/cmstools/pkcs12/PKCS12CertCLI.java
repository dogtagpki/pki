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

import java.math.BigInteger;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;

import netscape.security.pkcs.PKCS12;
import netscape.security.pkcs.PKCS12CertInfo;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertCLI extends CLI {

    public PKCS12CertCLI(PKCS12CLI parent) {
        super("cert", "PKCS #12 certificate management commands", parent);

        addModule(new PKCS12CertAddCLI(this));
        addModule(new PKCS12CertExportCLI(this));
        addModule(new PKCS12CertFindCLI(this));
        addModule(new PKCS12CertModCLI(this));
        addModule(new PKCS12CertRemoveCLI(this));
    }

    public static void printCertInfo(PKCS12 pkcs12, PKCS12CertInfo certInfo) throws Exception {

        BigInteger id = certInfo.getID();
        System.out.println("  Certificate ID: " + id.toString(16));

        System.out.println("  Serial Number: " + new CertId(certInfo.getCert().getSerialNumber()).toHexString());
        System.out.println("  Nickname: " + certInfo.getNickname());
        System.out.println("  Subject DN: " + certInfo.getCert().getSubjectDN());
        System.out.println("  Issuer DN: " + certInfo.getCert().getIssuerDN());

        if (certInfo.getTrustFlags() != null) {
            System.out.println("  Trust Flags: " + certInfo.getTrustFlags());
        }

        System.out.println("  Has Key: " + (pkcs12.getKeyInfoByID(id) != null));
    }
}
