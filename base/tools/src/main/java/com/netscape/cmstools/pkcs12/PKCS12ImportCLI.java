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
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

/**
 * Tool for importing NSS database from PKCS #12 file
 */
public class PKCS12ImportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKCS12ImportCLI.class);

    public PKCS12CLI pkcs12CLI;

    public PKCS12ImportCLI(PKCS12CLI pkcs12CLI) {
        super("import", "Import PKCS #12 file into NSS database", pkcs12CLI);
        this.pkcs12CLI = pkcs12CLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nicknames...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "pkcs12", true, "PKCS #12 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-file", true, "DEPRECATED: PKCS #12 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "password", true, "PKCS #12 password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "pkcs12-password", true, "DEPRECATED: PKCS #12 password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "password-file", true, "PKCS #12 password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-password-file", true, "DEPRECATED: PKCS #12 password file");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "no-trust-flags", false, "Do not include trust flags");
        options.addOption(null, "no-user-certs", false, "Do not import user certificates");
        options.addOption(null, "no-ca-certs", false, "Do not import CA certificates");
        options.addOption(null, "overwrite", false, "Overwrite existing certificates");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] nicknames = cmd.getArgs();

        String filename = cmd.getOptionValue("pkcs12-file");

        if (filename == null) {
            filename = cmd.getOptionValue("pkcs12");
        } else {
            logger.warn("The --pkcs12-file option has been deprecated. Use --pkcs12 instead.");
        }

        if (filename == null) {
            throw new Exception("Missing PKCS #12 file");
        }

        String passwordString = cmd.getOptionValue("pkcs12-password");
        if (passwordString == null) {
            passwordString = cmd.getOptionValue("password");
        } else {
            logger.warn("The --pkcs12-password option has been deprecated. Use --password instead.");
        }

        if (passwordString == null) {

            String passwordFile = cmd.getOptionValue("pkcs12-password-file");
            if (passwordFile == null) {
                passwordFile = cmd.getOptionValue("password-file");
            } else {
                logger.warn("The --pkcs12-password-file option has been deprecated. Use --password-file instead.");
            }

            if (passwordFile != null) {
                try (BufferedReader in = new BufferedReader(new FileReader(passwordFile))) {
                    passwordString = in.readLine();
                }
            }
        }

        if (passwordString == null) {
            throw new Exception("Missing PKCS #12 password");
        }

        boolean trustFlagsEnabled = !cmd.hasOption("no-trust-flags");
        boolean excludeCACerts = cmd.hasOption("no-ca-certs");
        boolean excludeUserCerts = cmd.hasOption("no-user-certs");
        boolean overwrite = cmd.hasOption("overwrite");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        Password password = new Password(passwordString.toCharArray());

        try {
            PKCS12Util util = new PKCS12Util();
            util.setTrustFlagsEnabled(trustFlagsEnabled);

            // load PKCS12 object from file
            PKCS12 pkcs12 = util.loadFromFile(filename, password);

            Collection<PKCS12CertInfo> caCerts = new ArrayList<>();
            Collection<PKCS12CertInfo> userCerts = new ArrayList<>();

            for (PKCS12CertInfo certInfo : pkcs12.getCertInfos()) {
                byte[] keyID = certInfo.getKeyID();
                if (keyID == null) {
                    // no key -> CA cert
                    caCerts.add(certInfo);
                } else {
                    // has key -> user cert
                    userCerts.add(certInfo);
                }
            }

            if (excludeCACerts) {
                // remove CA certs from PKCS12 object
                for (PKCS12CertInfo certInfo : caCerts) {
                    pkcs12.removeCertInfoByFriendlyName(certInfo.getFriendlyName());
                }
            }

            if (excludeUserCerts) {
                // remove user certs from PKCS12 object
                for (PKCS12CertInfo certInfo : userCerts) {
                    pkcs12.removeCertInfoByFriendlyName(certInfo.getFriendlyName());
                }
            }

            if (nicknames.length == 0) {
                // import all certs from PKCS12 object
                util.storeIntoNSS(pkcs12, password, overwrite);

            } else {
                // import specified certs from PKCS12 object
                for (String nickname : nicknames) {
                    util.storeCertIntoNSS(pkcs12, password, nickname, overwrite);
                }
            }


        } finally {
            password.clear();
        }
    }
}
