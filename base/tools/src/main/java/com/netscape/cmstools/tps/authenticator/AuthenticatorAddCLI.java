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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.tps.authenticator;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.tps.authenticator.AuthenticatorClient;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorAddCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticatorAddCLI.class);

    public AuthenticatorCLI authenticatorCLI;

    public AuthenticatorAddCLI(AuthenticatorCLI authenticatorCLI) {
        super("add", "Add authenticator", authenticatorCLI);
        this.authenticatorCLI = authenticatorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " --input <file> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "input", true, "Input file containing authenticator properties.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String input = cmd.getOptionValue("input");

        if (input == null) {
            throw new Exception("Missing input file");
        }

        AuthenticatorData authenticatorData;

        try (BufferedReader in = new BufferedReader(new FileReader(input));
            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw, true)) {

            String line;
            while ((line = in.readLine()) != null) {
                out.println(line);
            }

            authenticatorData = AuthenticatorData.valueOf(sw.toString());
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthenticatorClient authenticatorClient = authenticatorCLI.getAuthenticatorClient();
        authenticatorData = authenticatorClient.addAuthenticator(authenticatorData);

        MainCLI.printMessage("Added authenticator \"" + authenticatorData.getID() + "\"");

        AuthenticatorCLI.printAuthenticatorData(authenticatorData, true);
    }
}
