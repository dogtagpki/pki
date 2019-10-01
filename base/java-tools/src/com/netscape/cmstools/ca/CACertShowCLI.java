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

package com.netscape.cmstools.ca;

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertShowCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertShowCLI.class);

    public CACertCLI certCLI;

    public CACertShowCLI(CACertCLI certCLI) {
        super("show", "Show certificate", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Serial Number> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "DEPRECATED: Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pretty", false, "Pretty print");
        options.addOption(null, "encoded", false, "DEPRECATED: Base-64 encoded");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing Serial Number.");
        }

        CertId certID = new CertId(cmdArgs[0]);

        boolean showPrettyPrint = cmd.hasOption("pretty");
        boolean showEncoded = cmd.hasOption("encoded");

        if (showEncoded) {
            logger.warn("The --encoded option has been deprecated. Use pki ca-cert-export instead.");
        }

        String file = cmd.getOptionValue("output");

        if (file != null) {
            logger.warn("The --output option has been deprecated. Use pki ca-cert-export instead.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CACertClient certClient = certCLI.getCertClient();
        CertData certData = certClient.getCert(certID);

        String encoded = certData.getEncoded();
        if (encoded != null && file != null) {
            // store cert to file
            try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
                out.print(encoded);
            }
        }

        CACertCLI.printCertData(certData, showPrettyPrint, showEncoded);
    }
}
