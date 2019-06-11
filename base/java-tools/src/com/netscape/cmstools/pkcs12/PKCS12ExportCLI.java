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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools.pkcs12;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;

/**
 * Tool for exporting NSS database into PKCS #12 file
 */
public class PKCS12ExportCLI extends CLI {

    public PKCS12ExportCLI(PKCS12CLI certCLI) {
        super("export", "Export NSS database into PKCS #12 file", certCLI);

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nicknames...]", options);

        System.out.println();

        System.out.println("Supported certificate encryption algorithms:");
        for (PBEAlgorithm algorithm : PKCS12Util.SUPPORTED_CERT_ENCRYPTIONS) {

            if (algorithm == null) {
                System.out.println(" - " + PKCS12Util.NO_ENCRYPTION);

            } else {
                System.out.println(" - " + algorithm);
            }
        }

        System.out.println();

        System.out.println("Supported key encryption algorithms:");
        for (PBEAlgorithm algorithm : PKCS12Util.SUPPORTED_KEY_ENCRYPTIONS) {

            if (algorithm == null) {
                System.out.println(" - " + PKCS12Util.NO_ENCRYPTION);

            } else {
                System.out.println(" - " + algorithm);
            }
        }
    }

    public void createOptions() {
        Option option = new Option(null, "pkcs12-file", true, "PKCS #12 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-password", true, "PKCS #12 password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "pkcs12-password-file", true, "PKCS #12 password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-encryption", true,
                "Certificate encryption algorithm (default: " + PKCS12Util.DEFAULT_CERT_ENCRYPTION_NAME + ").");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option(null, "key-encryption", true,
                "Key encryption algorithm (default: " + PKCS12Util.DEFAULT_KEY_ENCRYPTION_NAME + ").");
        option.setArgName("algorithm");
        options.addOption(option);

        options.addOption(null, "append", false, "Append into an existing PKCS #12 file");
        options.addOption(null, "no-trust-flags", false, "Do not include trust flags");
        options.addOption(null, "no-key", false, "Do not include private key");
        options.addOption(null, "no-chain", false, "Do not include certificate chain");

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
            PKILogger.setLevel(PKILogger.Level.INFO);

        } else if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);
        }

        String[] nicknames = cmd.getArgs();
        String filename = cmd.getOptionValue("pkcs12-file");

        if (filename == null) {
            throw new Exception("Missing PKCS #12 file.");
        }

        String passwordString = cmd.getOptionValue("pkcs12-password");

        if (passwordString == null) {

            String passwordFile = cmd.getOptionValue("pkcs12-password-file");
            if (passwordFile != null) {
                try (BufferedReader in = new BufferedReader(new FileReader(passwordFile))) {
                    passwordString = in.readLine();
                }
            }
        }

        if (passwordString == null) {
            throw new Exception("Missing PKCS #12 password.");
        }

        Password password = new Password(passwordString.toCharArray());

        String certEncryption = cmd.getOptionValue("cert-encryption");
        String keyEncryption = cmd.getOptionValue("key-encryption");

        boolean append = cmd.hasOption("append");
        boolean includeTrustFlags = !cmd.hasOption("no-trust-flags");
        boolean includeKey = !cmd.hasOption("no-key");
        boolean includeChain = !cmd.hasOption("no-chain");

        try {
            PKCS12Util util = new PKCS12Util();
            if (certEncryption != null) {
                util.setCertEncryption(certEncryption);
            }
            if (keyEncryption != null) {
                util.setKeyEncryption(keyEncryption);
            }
            util.setTrustFlagsEnabled(includeTrustFlags);

            PKCS12 pkcs12;

            if (append && new File(filename).exists()) {
                // if append requested and file exists, export into the existing file
                pkcs12 = util.loadFromFile(filename, password);

            } else {
                // otherwise, create a new file
                pkcs12 = new PKCS12();
            }

            if (nicknames.length == 0) {
                // load all certificates
                util.loadFromNSS(pkcs12, includeKey, includeChain);

            } else {
                // load the specified certificates
                for (String nickname : nicknames) {
                    util.loadCertFromNSS(pkcs12, nickname, includeKey, includeChain);
                }
            }

            util.storeIntoFile(pkcs12, filename, password);

        } finally {
            password.clear();
        }

        MainCLI.printMessage("Export complete");
    }
}
