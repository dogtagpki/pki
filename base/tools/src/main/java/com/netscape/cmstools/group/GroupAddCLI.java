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
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupData;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupAddCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GroupAddCLI.class);

    public GroupCLI groupCLI;

    public GroupAddCLI(GroupCLI groupCLI) {
        super("add", "Add group", groupCLI);
        this.groupCLI = groupCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Group ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "description", true, "Description");
        option.setArgName("description");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Group ID specified.");
        }

        String groupID = cmdArgs[0];

        GroupData groupData = new GroupData();
        groupData.setGroupID(groupID);
        groupData.setDescription(cmd.getOptionValue("description"));

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        GroupClient groupClient = groupCLI.getGroupClient();
        groupData = groupClient.addGroup(groupData);

        MainCLI.printMessage("Added group \""+groupID+"\"");

        GroupCLI.printGroup(groupData);
    }
}
