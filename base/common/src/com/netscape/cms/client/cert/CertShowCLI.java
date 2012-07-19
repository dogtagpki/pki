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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.client.cert;

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;
import com.netscape.cms.servlet.cert.model.CertificateData;

/**
 * @author Endi S. Dewata
 */
public class CertShowCLI extends CLI {

    public CertCLI parent;

    public CertShowCLI(CertCLI parent) {
        super("show", "Show certificate");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <Serial Number> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "output", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pretty", false, "Pretty print");
        options.addOption(null, "encoded", false, "Base-64 encoded");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        boolean showPrettyPrint = cmd.hasOption("pretty");
        boolean showEncoded = cmd.hasOption("encoded");

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            printHelp();
            System.exit(1);
        }

        CertId certID = new CertId(cmdArgs[0]);
        String file = cmd.getOptionValue("output");

        CertificateData certData = parent.client.getCert(certID);

        String encoded = certData.getEncoded();
        if (encoded != null && file != null) {
            // store cert to file
            PrintWriter out = new PrintWriter(new FileWriter(file));
            out.print(encoded);
            out.close();
        }

        MainCLI.printMessage("Certificate \"" + certID.toHexString() + "\"");

        CertCLI.printCertData(certData, showPrettyPrint, showEncoded);
    }
}
