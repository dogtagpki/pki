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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.token.TokenClient;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class TokenAddCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TokenAddCLI.class);

    public TokenCLI tokenCLI;

    public TokenAddCLI(TokenCLI tokenCLI) {
        super("add", "Add token", tokenCLI);
        this.tokenCLI = tokenCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Token ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "user", true, "User ID");
        option.setArgName("User ID");
        options.addOption(option);

        option = new Option(null, "policy", true, "Policy");
        option.setArgName("Policy");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Token ID specified.");
        }

        String tokenID = cmdArgs[0];

        TokenData tokenData = new TokenData();
        tokenData.setTokenID(tokenID);

        String userID = cmd.getOptionValue("user");
        tokenData.setUserID(userID);

        String policy = cmd.getOptionValue("policy");
        tokenData.setPolicy(policy);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = tokenCLI.tpsCLI.getSubsystemClient(client);
        TokenClient tokenClient = new TokenClient(subsystemClient);
        tokenData = tokenClient.addToken(tokenData);

        MainCLI.printMessage("Added token \"" + tokenID + "\"");

        TokenCLI.printToken(tokenData);
    }
}
