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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.user;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.user.UserData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserAddCLI extends CLI {

    public UserCLI userCLI;

    public UserAddCLI(UserCLI userCLI) {
        super("add", "Add user", userCLI);
        this.userCLI = userCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> --fullName <fullname> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "fullName", true, "Full name");
        option.setArgName("fullName");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "email", true, "Email");
        option.setArgName("email");
        options.addOption(option);

        option = new Option(null, "password", true, "Password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "phone", true, "Phone");
        option.setArgName("phone");
        options.addOption(option);

        option = new Option(null, "type", true, "Type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "state", true, "State");
        option.setArgName("state");
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
            System.err.println("Error: No User ID specified.");
            printHelp();
            System.exit(-1);
        }

        String userID = cmdArgs[0];

        UserData userData = new UserData();
        userData.setUserID(userID);
        userData.setFullName(cmd.getOptionValue("fullName"));
        userData.setEmail(cmd.getOptionValue("email"));
        userData.setPassword(cmd.getOptionValue("password"));
        userData.setPhone(cmd.getOptionValue("phone"));
        userData.setType(cmd.getOptionValue("type"));
        userData.setState(cmd.getOptionValue("state"));

        userData = userCLI.userClient.addUser(userData);

        MainCLI.printMessage("Added user \"" + userID + "\"");

        UserCLI.printUser(userData);
    }
}
