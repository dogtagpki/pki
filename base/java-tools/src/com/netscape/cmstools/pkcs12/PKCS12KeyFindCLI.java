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
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.util.logger.PKILogger;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

import netscape.security.pkcs.PKCS12;
import netscape.security.pkcs.PKCS12KeyInfo;
import netscape.security.pkcs.PKCS12Util;

/**
 * @author Endi S. Dewata
 */
public class PKCS12KeyFindCLI extends CLI {

    public PKCS12KeyFindCLI(PKCS12KeyCLI certCLI) {
        super("find", "Find keys in PKCS #12 file", certCLI);

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
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
            PKILogger.setLevel(PKILogger.Level.INFO);

        } else if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

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

        Collection<PKCS12KeyInfo> keyInfos;

        try {
            PKCS12Util util = new PKCS12Util();
            PKCS12 pkcs12 = util.loadFromFile(filename, password);

            keyInfos = pkcs12.getKeyInfos();

        } finally {
            password.clear();
        }

        MainCLI.printMessage(keyInfos.size() + " entries found");
        if (keyInfos.size() == 0) return;

        boolean first = true;

        for (PKCS12KeyInfo keyInfo : keyInfos) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            PKCS12KeyCLI.printKeyInfo(keyInfo);
        }
    }
}
