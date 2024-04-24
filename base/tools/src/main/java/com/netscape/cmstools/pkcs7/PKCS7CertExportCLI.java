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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs7;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmstools.cli.MainCLI;

public class PKCS7CertExportCLI extends CommandCLI {

    private static Logger logger = LoggerFactory.getLogger(PKCS7CertExportCLI.class);

    public PKCS7CertCLI certCLI;

    public PKCS7CertExportCLI(PKCS7CertCLI certCLI) {
        super("export", "Export certificates from PKCS #7 file", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nicknames...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "pkcs7", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs7-file", true, "DEPRECATED: PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("string");
        options.addOption(option);

        option = new Option(null, "output-prefix", true, "Prefix for output file");
        option.setArgName("string");
        options.addOption(option);

        option = new Option(null, "output-suffix", true, "Suffix for output file");
        option.setArgName("string");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String filename = cmd.getOptionValue("pkcs7");
        if (filename == null) {
            filename = cmd.getOptionValue("pkcs7-file");
            if (filename != null) {
                logger.warn("The --pkcs7-file has been deprecated. Use --pkcs7 instead.");
            }
        }

        String input;
        if (filename == null) {
            logger.info("Loading PKCS #7 data from standard input");
            input = IOUtils.toString(System.in, "UTF-8").trim();

        } else {
            logger.info("Loading PKCS #7 data from " + filename);
            input = new String(Files.readAllBytes(Paths.get(filename))).trim();
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKCS7 pkcs7 = new PKCS7(input);
        X509Certificate[] certs = pkcs7.getCertificates();
        if (certs == null || certs.length == 0) {
            System.out.println("PKCS #7 data contains no certificates");
            return;
        }

        // sort certs from root to leaf
        certs = Cert.sortCertificateChain(certs);

        String outputFile = cmd.getOptionValue("output-file");
        if (outputFile != null) {

            // export certs into a series of PEM certificates in a single file
            try (PrintWriter out = new PrintWriter(outputFile)) {
                for (X509Certificate cert : certs) {
                    out.println(Cert.HEADER);
                    out.print(Utils.base64encodeMultiLine(cert.getEncoded()));
                    out.println(Cert.FOOTER);
                }
            }

            return;
        }

        // export certs into PEM certificates in separate files
        String prefix = cmd.getOptionValue("output-prefix", filename + "-");
        String suffix = cmd.getOptionValue("output-suffix", "");
        int i = 0;

        for (X509Certificate cert : certs) {

            logger.info("Exporting certificate #" + i + ": " + cert.getSubjectDN());

            String output = prefix + i + suffix;

            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(Cert.HEADER);
                out.print(Utils.base64encode(cert.getEncoded(), true));
                out.println(Cert.FOOTER);
            }

            System.out.println(output + ": " + cert.getSubjectDN());

            i++;
        }
    }
}
