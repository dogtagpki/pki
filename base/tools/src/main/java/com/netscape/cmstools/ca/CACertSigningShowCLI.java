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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.ca.CASystemCertClient;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertSigningShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertSigningShowCLI.class);

    public CACertCLI certCLI;

    public CACertSigningShowCLI(CACertCLI certCLI) {
        super("signing-show", "Show CA signing certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CASystemCertClient certClient = new CASystemCertClient(client, "ca");
        CertData certData = certClient.getSigningCert();

        System.out.println("  Serial Number: " + certData.getSerialNumber().toHexString());
        System.out.println("  Subject DN: " + certData.getSubjectDN());
        System.out.println("  Issuer DN: " + certData.getIssuerDN());
        System.out.println("  Not Valid Before: " + certData.getNotBefore());
        System.out.println("  Not Valid After: " + certData.getNotAfter());
    }
}
