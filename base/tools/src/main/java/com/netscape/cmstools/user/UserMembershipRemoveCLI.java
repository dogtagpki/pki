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

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class UserMembershipRemoveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserMembershipRemoveCLI.class);

    public UserMembershipCLI userMembershipCLI;

    public UserMembershipRemoveCLI(UserMembershipCLI userMembershipCLI) {
        super("del", "Remove user membership", userMembershipCLI);
        this.userMembershipCLI = userMembershipCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> <Group ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 2) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        String userID = cmdArgs[0];
        String groupID = cmdArgs[1];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = userMembershipCLI.parent.subsystemCLI.getSubsystemClient(client);
        UserClient userClient = new UserClient(subsystemClient);
        userClient.removeUserMembership(userID, groupID);

        MainCLI.printMessage("Deleted membership in group \""+groupID+"\"");
    }
}
