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
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertModCLI extends CommandCLI {

    public PKCS12CertCLI certCLI;

    public PKCS12CertModCLI(PKCS12CertCLI certCLI) {
        super("mod", "Modify certificate in PKCS #12 file", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <cert ID or nickname> [OPTIONS...]", options);
    }

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

        option = new Option(null, "friendly-name", true, "Certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "trust-flags", true, "Certificate trust flags");
        option.setArgName("flags");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length == 0) {
            throw new Exception("Missing certificate ID or nickname");
        }

        String nickname = cmdArgs[0];

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

        String friendlyName = cmd.getOptionValue("friendly-name");
        String trustFlags = cmd.getOptionValue("trust-flags");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        Password password = new Password(passwordString.toCharArray());

        byte[] certID;
        try {
            certID = Hex.decodeHex(nickname.toCharArray());
        } catch (DecoderException e) {
            // nickname is not an ID
            certID = null;
        }

        try {
            PKCS12Util util = new PKCS12Util();
            PKCS12 pkcs12 = util.loadFromFile(filename, password);

            PKCS12CertInfo certInfo = null;

            if (certID != null) { // search cert by ID (if provided)
                certInfo = pkcs12.getCertInfoByID(certID);
            }

            if (certInfo == null) { // if not found, search cert by nickname
                Collection<PKCS12CertInfo> certInfos = pkcs12.getCertInfosByFriendlyName(nickname);
                if (!certInfos.isEmpty()) {
                    certInfo = certInfos.iterator().next();
                }
            }

            if (certInfo == null) {
                throw new Exception("Certificate " + nickname + " not found");
            }

            if (friendlyName != null) {
                certInfo.setFriendlyName(friendlyName);
            }

            if (trustFlags != null) {
                if (trustFlags.equals("")) { // remove trust flags
                    certInfo.setTrustFlags(null);

                } else { // set trust flags
                    certInfo.setTrustFlags(trustFlags);
                }
            }

            util.storeIntoFile(pkcs12, filename, password);

        } finally {
            password.clear();
        }

        MainCLI.printMessage("Updated certificate \"" + nickname + "\"");
    }
}
