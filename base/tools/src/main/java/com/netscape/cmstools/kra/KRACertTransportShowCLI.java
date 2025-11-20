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

package com.netscape.cmstools.kra;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.kra.KRASystemCertClient;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class KRACertTransportShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRACertTransportShowCLI.class);

    public KRACertCLI certCLI;

    public KRACertTransportShowCLI(KRACertCLI certCLI) {
        super("transport-show", "Show KRA transport certificate", certCLI);
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
        KRASystemCertClient certClient = new KRASystemCertClient(client, "kra");
        CertData certData = certClient.getTransportCert();

        System.out.println("  Serial Number: " + certData.getSerialNumber().toHexString());
        System.out.println("  Subject DN: " + certData.getSubjectDN());
        System.out.println("  Issuer DN: " + certData.getIssuerDN());
        System.out.println("  Not Valid Before: " + certData.getNotBefore());
        System.out.println("  Not Valid After: " + certData.getNotAfter());
    }
}
