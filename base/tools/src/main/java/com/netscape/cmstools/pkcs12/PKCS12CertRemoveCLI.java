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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertRemoveCLI extends CommandCLI {

    public PKCS12CertCLI certCLI;

    public PKCS12CertRemoveCLI(PKCS12CertCLI certCLI) {
        super("del", "Remove certificate from PKCS #12 file", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
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
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length == 0) {
            throw new Exception("Missing certificate nickname.");
        }

        String nickname = cmdArgs[0];

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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        Password password = new Password(passwordString.toCharArray());

        try {
            PKCS12Util util = new PKCS12Util();

            PKCS12 pkcs12 = util.loadFromFile(filename, password);
            pkcs12.removeCertInfoByFriendlyName(nickname);
            util.storeIntoFile(pkcs12, filename, password);

        } finally {
            password.clear();
        }

        MainCLI.printMessage("Deleted certificate \"" + nickname + "\"");
    }
}
