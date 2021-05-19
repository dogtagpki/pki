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
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertFindCLI extends CommandCLI {

    public PKCS12CertCLI certCLI;

    public PKCS12CertFindCLI(PKCS12CertCLI certCLI) {
        super("find", "Find certificates in PKCS #12 file", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
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
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String filename = cmd.getOptionValue("pkcs12");
        if (filename == null) {
            filename = cmd.getOptionValue("pkcs12-file");
        }

        if (filename == null) {
            throw new Exception("Missing PKCS #12 file.");
        }

        String passwordString = cmd.getOptionValue("password");
        if (passwordString == null) {
            passwordString = cmd.getOptionValue("pkcs12-password");
        }

        if (passwordString == null) {

            String passwordFile = cmd.getOptionValue("password-file");
            if (passwordFile == null) {
                passwordFile = cmd.getOptionValue("pkcs12-password-file");
            }

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

        PKCS12 pkcs12;
        try {
            PKCS12Util util = new PKCS12Util();
            pkcs12 = util.loadFromFile(filename, password);

        } finally {
            password.clear();
        }

        Collection<PKCS12CertInfo> certInfos = pkcs12.getCertInfos();

        MainCLI.printMessage(certInfos.size() + " entries found");
        if (certInfos.size() == 0) return;

        boolean first = true;

        for (PKCS12CertInfo certInfo : certInfos) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            PKCS12CertCLI.printCertInfo(pkcs12, certInfo);
        }
    }
}
