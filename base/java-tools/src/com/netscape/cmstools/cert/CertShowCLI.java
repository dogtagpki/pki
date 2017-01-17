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

package com.netscape.cmstools.cert;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CertShowCLI extends CLI {

    public CertCLI certCLI;

    public CertShowCLI(CertCLI certCLI) {
        super("show", "Show certificate", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Serial Number> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pretty", false, "Pretty print");
        options.addOption(null, "encoded", false, "Base-64 encoded");
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing Serial Number.");
        }

        boolean showPrettyPrint = cmd.hasOption("pretty");
        boolean showEncoded = cmd.hasOption("encoded");

        CertId certID = new CertId(cmdArgs[0]);
        String file = cmd.getOptionValue("output");

        CertData certData = certCLI.certClient.getCert(certID);

        String encoded = certData.getEncoded();
        if (encoded != null && file != null) {
            // store cert to file
            try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
                out.print(encoded);
            }
        }

        MainCLI.printMessage("Certificate \"" + certID.toHexString() + "\"");

        CertCLI.printCertData(certData, showPrettyPrint, showEncoded);
    }
}
