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

import java.io.FileOutputStream;
import java.io.PrintStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.util.Cert;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertExportCLI.class);

    public CACertCLI certCLI;

    public CACertExportCLI(CACertCLI certCLI) {
        super("export", "Export certificate", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Serial Number> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: pem (default), der");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing serial number");
        }

        CertId certID = new CertId(cmdArgs[0]);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CACertClient certClient = certCLI.getCertClient();
        CertData certData = certClient.getCert(certID);

        String outputFormat = cmd.getOptionValue("output-format", "pem");

        String cert = null;
        byte[] bytes = null;

        if ("pem".equalsIgnoreCase(outputFormat)) {
            cert = certData.getEncoded();

        } else if ("der".equalsIgnoreCase(outputFormat)) {
            bytes = Cert.parseCertificate(certData.getEncoded());

        } else {
            throw new Exception("Unsupported format: " + outputFormat);
        }

        String outputFile = cmd.getOptionValue("output-file");

        if (outputFile != null) {
            try (PrintStream out = new PrintStream(new FileOutputStream(outputFile))) {
                if (cert != null) {
                    out.print(cert);
                } else {
                    out.write(bytes);
                }
            }

        } else {
            if (cert != null) {
                System.out.print(cert);
            } else {
                System.out.write(bytes);
            }
        }
    }
}
