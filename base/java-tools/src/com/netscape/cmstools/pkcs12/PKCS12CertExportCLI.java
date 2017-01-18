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
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmsutil.util.Utils;

import netscape.security.pkcs.PKCS12;
import netscape.security.pkcs.PKCS12CertInfo;
import netscape.security.pkcs.PKCS12Util;
import netscape.security.x509.X509CertImpl;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertExportCLI extends CLI {

    public PKCS12CertExportCLI(PKCS12CertCLI certCLI) {
        super("export", "Export certificate from PKCS #12 file", certCLI);

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
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

        option = new Option(null, "cert-file", true, "Certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-id", true, "Certificate ID to export");
        option.setArgName("ID");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

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

        String[] cmdArgs = cmd.getArgs();
        String id = cmd.getOptionValue("cert-id");

        if (cmdArgs.length < 1 && id == null) {
            throw new Exception("Missing certificate nickname or ID.");
        }

        if (cmdArgs.length >= 1 && id != null) {
            throw new Exception("Certificate nickname and ID are mutually exclusive.");
        }

        String nickname = null;
        BigInteger certID = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        } else {
            certID = new BigInteger(id, 16);
        }

        String pkcs12File = cmd.getOptionValue("pkcs12-file");

        if (pkcs12File == null) {
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

        String certFile = cmd.getOptionValue("cert-file");

        if (certFile == null) {
            throw new Exception("Missing certificate file.");
        }

        try {
            PKCS12Util util = new PKCS12Util();
            PKCS12 pkcs12 = util.loadFromFile(pkcs12File, password);

            Collection<PKCS12CertInfo> certInfos = new ArrayList<PKCS12CertInfo>();

            if (nickname != null) {
                certInfos.addAll(pkcs12.getCertInfosByNickname(nickname));

            } else {
                PKCS12CertInfo certInfo = pkcs12.getCertInfoByID(certID);
                if (certInfo != null) {
                    certInfos.add(certInfo);
                }
            }

            if (certInfos.isEmpty()) {
                throw new Exception("Certificate not found.");
            }

            try (PrintStream os = new PrintStream(new FileOutputStream(certFile))) {
                for (PKCS12CertInfo certInfo : certInfos) {
                    X509CertImpl cert = certInfo.getCert();
                    os.println("-----BEGIN CERTIFICATE-----");
                    os.print(Utils.base64encode(cert.getEncoded()));
                    os.println("-----END CERTIFICATE-----");
                }
            }

        } finally {
            password.clear();
        }
    }
}
