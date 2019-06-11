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

package com.netscape.cmstools.tps.token;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.tps.token.TokenClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class TokenRemoveCLI extends CLI {

    public TokenCLI tokenCLI;

    public TokenRemoveCLI(TokenCLI tokenCLI) {
        super("del", "Remove token", tokenCLI);
        this.tokenCLI = tokenCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Token ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Token ID specified.");
        }

        String tokenID = args[0];

        TokenClient tokenClient = tokenCLI.getTokenClient();
        tokenClient.removeToken(tokenID);

        MainCLI.printMessage("Deleted token \"" + tokenID + "\"");
    }
}
