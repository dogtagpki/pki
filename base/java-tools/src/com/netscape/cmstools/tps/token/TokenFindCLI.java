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
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.tps.token.TokenClient;
import com.netscape.certsrv.tps.token.TokenCollection;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class TokenFindCLI extends CLI {

    public TokenCLI tokenCLI;

    public TokenFindCLI(TokenCLI tokenCLI) {
        super("find", "Find tokens", tokenCLI);
        this.tokenCLI = tokenCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [FILTER] [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "token", true, "Token ID");
        option.setArgName("token ID");
        options.addOption(option);

        option = new Option(null, "user", true, "User ID");
        option.setArgName("user ID");
        options.addOption(option);

        option = new Option(null, "type", true, "Token type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "status", true, "Token status");
        option.setArgName("status");
        options.addOption(option);

        option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
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
        String filter = cmdArgs.length > 0 ? cmdArgs[0] : null;
        String tokenID = cmd.getOptionValue("token");
        String userID = cmd.getOptionValue("user");
        String type = cmd.getOptionValue("type");
        String statusStr = cmd.getOptionValue("status");

        TokenStatus status = null;
        if (statusStr != null) {
            status = TokenStatus.valueOf(statusStr);
        }

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        TokenClient tokenClient = tokenCLI.getTokenClient();
        TokenCollection result = tokenClient.findTokens(
                filter,
                tokenID,
                userID,
                type,
                status,
                start,
                size);

        MainCLI.printMessage(result.getTotal() + " entries matched");
        if (result.getTotal() == 0) return;

        Collection<TokenData> tokens = result.getEntries();
        boolean first = true;

        for (TokenData tokenData : tokens) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            TokenCLI.printToken(tokenData);
        }

        MainCLI.printMessage("Number of entries returned " + tokens.size());
    }
}
