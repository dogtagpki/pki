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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.user.UserClient;
import com.netscape.certsrv.user.UserData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class UserModifyCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserModifyCLI.class);

    public UserCLI userCLI;

    public UserModifyCLI(UserCLI userCLI) {
        super("mod", "Modify user", userCLI);
        this.userCLI = userCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "fullName", true, "Full name");
        option.setArgName("fullName");
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

        // type cannot be modified
        // option = new Option(null, "type", true, "Type");
        // option.setArgName("type");
        // options.addOption(option);

        option = new Option(null, "state", true, "State");
        option.setArgName("state");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No User ID specified.");
        }

        String userId = cmdArgs[0];

        UserData userData = new UserData();
        userData.setID(userId);
        userData.setFullName(cmd.getOptionValue("fullName"));
        userData.setEmail(cmd.getOptionValue("email"));
        userData.setPassword(cmd.getOptionValue("password"));
        userData.setPhone(cmd.getOptionValue("phone"));
        // type cannot be modified
        // userData.setType(cmd.getOptionValue("type"));
        userData.setState(cmd.getOptionValue("state"));

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = userCLI.subsystemCLI.getSubsystemClient(client);
        UserClient userClient = new UserClient(subsystemClient);
        userData = userClient.modifyUser(userId, userData);

        MainCLI.printMessage("Modified user \"" + userId + "\"");

        UserCLI.printUser(userData);
    }
}
