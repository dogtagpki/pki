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

        option = new Option(null, "type", true, "Type");
        option.setArgName("Type");
        options.addOption(option);

        option = new Option(null, "applet", true, "Applet ID");
        option.setArgName("Applet ID");
        options.addOption(option);

        option = new Option(null, "key-info", true, "Key info");
        option.setArgName("Key info");
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
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: No Token ID specified.");
            printHelp();
            System.exit(-1);
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

        String type = cmd.getOptionValue("type");
        if (type != null) {
            tokenData.setType(type);
            modify = true;
        }

        String appletID = cmd.getOptionValue("applet");
        if (appletID != null) {
            tokenData.setAppletID(appletID);
            modify = true;
        }

        String keyInfo = cmd.getOptionValue("key-info");
        if (keyInfo != null) {
            tokenData.setKeyInfo(keyInfo);
            modify = true;
        }

        String policy = cmd.getOptionValue("policy");
        if (policy != null) {
            tokenData.setPolicy(policy);
            modify = true;
        }

        if (modify) {
            tokenData = tokenCLI.tokenClient.modifyToken(tokenID, tokenData);
        }

        String status = cmd.getOptionValue("status");
        if (status != null) {
            tokenData = tokenCLI.tokenClient.changeTokenStatus(tokenID, TokenStatus.valueOf(status));
        }

        if (!modify && status == null) {
            System.err.println("Error: No modifications specified.");
            printHelp();
            System.exit(-1);
        }

        MainCLI.printMessage("Modified token \"" + tokenID + "\"");

        TokenCLI.printToken(tokenData);
    }
}
