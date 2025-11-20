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

package com.netscape.cmstools.group;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberRemoveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GroupMemberRemoveCLI.class);

    public GroupMemberCLI groupMemberCLI;

    public GroupMemberRemoveCLI(GroupMemberCLI groupMemberCLI) {
        super("del", "Remove group member", groupMemberCLI);
        this.groupMemberCLI = groupMemberCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Group ID> <Member ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 2) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        String groupID = cmdArgs[0];
        String memberID = cmdArgs[1];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = groupMemberCLI.parent.subsystemCLI.getSubsystemClient(client);
        GroupClient groupClient = new GroupClient(subsystemClient);
        groupClient.removeGroupMember(groupID, memberID);

        MainCLI.printMessage("Deleted group member \""+memberID+"\"");
    }
}
