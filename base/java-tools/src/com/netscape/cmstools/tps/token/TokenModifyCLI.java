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
import org.apache.commons.cli.Option;

import com.netscape.certsrv.tps.token.TokenClient;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class TokenModifyCLI extends CLI {

    public TokenCLI tokenCLI;

    public TokenModifyCLI(TokenCLI tokenCLI) {
        super("mod", "Modify token", tokenCLI);
        this.tokenCLI = tokenCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Token ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "user", true, "User ID");
        option.setArgName("User ID");
        options.addOption(option);

        option = new Option(null, "policy", true, "Policy");
        option.setArgName("Policy");
        options.addOption(option);

        option = new Option(null, "status", true, "Status");
        option.setArgName("Status");
        options.addOption(option);
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

        TokenData tokenData = new TokenData();
        boolean modify = false;

        String tokenID = cmdArgs[0];
        tokenData.setID(tokenID);

        String userID = cmd.getOptionValue("user");
        if (userID != null) {
            tokenData.setUserID(userID);
            modify = true;
        }

        String policy = cmd.getOptionValue("policy");
        if (policy != null) {
            tokenData.setPolicy(policy);
            modify = true;
        }

        TokenClient tokenClient = tokenCLI.getTokenClient();

        if (modify) {
            tokenData = tokenClient.modifyToken(tokenID, tokenData);
        }

        String status = cmd.getOptionValue("status");
        if (status != null) {
            tokenData = tokenClient.changeTokenStatus(tokenID, TokenStatus.valueOf(status));
        }

        if (!modify && status == null) {
            throw new Exception("No modifications specified.");
        }

        MainCLI.printMessage("Modified token \"" + tokenID + "\"");

        TokenCLI.printToken(tokenData);
    }
}
