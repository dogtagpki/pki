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
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.SystemCertClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class KRACertTransportShowCLI extends CLI {

    public KRACertCLI certCLI;

    public KRACertTransportShowCLI(KRACertCLI certCLI) {
        super("transport-show", "Show transport certificate", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.Level.INFO);

        } else if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);
        }

        MainCLI mainCLI = certCLI.kraCLI.mainCLI;
        mainCLI.init();

        PKIClient client = getClient();
        SystemCertClient certClient = new SystemCertClient(client, "kra");
        CertData certData = certClient.getTransportCert();

        System.out.println("  Serial Number: " + certData.getSerialNumber().toHexString());
        System.out.println("  Subject DN: " + certData.getSubjectDN());
        System.out.println("  Issuer DN: " + certData.getIssuerDN());
        System.out.println("  Not Valid Before: " + certData.getNotBefore());
        System.out.println("  Not Valid After: " + certData.getNotAfter());
    }
}
