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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.client;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCertFindCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertFindCLI(ClientCLI clientCLI) {
        super("cert-find", "Find certificates in client security database", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "ca", false, "Find CA certificates only");
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        PKIClient client = getClient();

        X509Certificate[] certs;
        if (cmd.hasOption("ca")) {
            certs = client.getCACerts();
        } else {
            certs = client.getCerts();
        }

        if (certs == null || certs.length == 0) {
            MainCLI.printMessage("No certificates found");
            return;
        }

        MainCLI.printMessage(certs.length + " certificate(s) found");

        boolean first = true;

        for (X509Certificate cert : certs) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            ClientCLI.printCertInfo(cert);
        }

        MainCLI.printMessage("Number of entries returned " + certs.length);
   }
}
