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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

import netscape.security.pkcs.PKCS7;

public class PKCS7CertExportCLI extends CLI {

    private static Logger logger = Logger.getLogger(PKCS7CertExportCLI.class.getName());

    public PKCS7CertExportCLI(PKCS7CertCLI certCLI) {
        super("export", "Export certificates from PKCS #7 file", certCLI);

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nicknames...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "pkcs7-file", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-prefix", true, "Prefix for output file");
        option.setArgName("string");
        options.addOption(option);

        option = new Option(null, "output-suffix", true, "Suffix for output file");
        option.setArgName("string");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args, true);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("verbose")) {
            Logger.getLogger("org.dogtagpki").setLevel(Level.INFO);
            Logger.getLogger("com.netscape").setLevel(Level.INFO);
            Logger.getLogger("netscape").setLevel(Level.INFO);

        } else if (cmd.hasOption("debug")) {
            Logger.getLogger("org.dogtagpki").setLevel(Level.FINE);
            Logger.getLogger("com.netscape").setLevel(Level.FINE);
            Logger.getLogger("netscape").setLevel(Level.FINE);
        }

        String filename = cmd.getOptionValue("pkcs7-file");

        if (filename == null) {
            throw new Exception("Missing PKCS #7 file.");
        }

        logger.info("Loading PKCS #7 data from " + filename);
        String str = new String(Files.readAllBytes(Paths.get(filename))).trim();
        PKCS7 pkcs7 = new PKCS7(str);

        X509Certificate[] certs = pkcs7.getCertificates();
        if (certs == null || certs.length == 0) {
            System.out.println("PKCS #7 data contains no certificates");
            return;
        }

        // sort certs from root to leaf
        certs = CryptoUtil.sortCertificateChain(certs);

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
