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

import com.netscape.certsrv.group.GroupData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupShowCLI extends CLI {

    public GroupCLI groupCLI;

    public GroupShowCLI(GroupCLI groupCLI) {
        super("show", "Show group", groupCLI);
        this.groupCLI = groupCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Group ID>", options);
    }

    public void execute(String[] args) throws Exception {

        if (args.length != 1) {
            printHelp();
            System.exit(1);
        }

        String groupID = args[0];

        GroupData groupData = groupCLI.groupClient.getGroup(groupID);

        MainCLI.printMessage("Group \""+groupID+"\"");

        GroupCLI.printGroup(groupData);
    }
}
