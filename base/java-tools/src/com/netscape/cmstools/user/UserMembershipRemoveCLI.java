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

package com.netscape.cmstools.user;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserMembershipRemoveCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserMembershipRemoveCLI.class);

    public UserMembershipCLI userMembershipCLI;

    public UserMembershipRemoveCLI(UserMembershipCLI userMembershipCLI) {
        super("del", "Remove user membership", userMembershipCLI);
        this.userMembershipCLI = userMembershipCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> <Group ID> [OPTIONS...]", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 2) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        String userID = cmdArgs[0];
        String groupID = cmdArgs[1];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        UserClient userClient = userMembershipCLI.getUserClient();
        userClient.removeUserMembership(userID, groupID);

        MainCLI.printMessage("Deleted membership in group \""+groupID+"\"");
    }
}
