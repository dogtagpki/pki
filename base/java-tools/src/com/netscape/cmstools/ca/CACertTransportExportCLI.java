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
import org.dogtagpki.ca.CASystemCertClient;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertTransportExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertTransportExportCLI.class);

    public CACertCLI certCLI;

    public CACertTransportExportCLI(CACertCLI certCLI) {
        super("transport-export", "Export CA transport certificate", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pkcs7", false, "Export PKCS #7 certificate chain");
    }

    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = getClient();
        CASystemCertClient certClient = new CASystemCertClient(client, "ca");
        CertData certData = certClient.getTransportCert();

        String outputFormat = cmd.getOptionValue("output-format");

        String cert = null;
        byte[] bytes = null;

        if (cmd.hasOption("pkcs7")) {

            String certChain = certData.getPkcs7CertChain();
            logger.info("Cert chain:\n" + certChain);

            PKCS7 pkcs7 = new PKCS7(Utils.base64decode(certChain));

            if (outputFormat == null || "PEM".equalsIgnoreCase(outputFormat)) {
                cert = pkcs7.toPEMString();

            } else if ("DER".equalsIgnoreCase(outputFormat)) {
                bytes = pkcs7.getBytes();

            } else {
                throw new Exception("Unsupported format: " + outputFormat);
            }

        } else {

            if (outputFormat == null || "PEM".equalsIgnoreCase(outputFormat)) {
                cert = certData.getEncoded();

            } else if ("DER".equalsIgnoreCase(outputFormat)) {
                bytes = Cert.parseCertificate(certData.getEncoded());

            } else {
                throw new Exception("Unsupported format: " + outputFormat);
            }
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
