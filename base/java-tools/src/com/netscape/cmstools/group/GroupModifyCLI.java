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

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupModifyCLI extends CLI {

    public GroupCLI groupCLI;

    public GroupModifyCLI(GroupCLI groupCLI) {
        super("mod", "Modify group", groupCLI);
        this.groupCLI = groupCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Group ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "description", true, "Description");
        option.setArgName("description");
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

        if (cmdArgs.length != 1) {
            throw new Exception("No Group ID specified.");
        }

        String groupID = cmdArgs[0];

        GroupData groupData = new GroupData();
        groupData.setID(groupID);
        groupData.setDescription(cmd.getOptionValue("description"));

        GroupClient groupClient = groupCLI.getGroupClient();
        groupData = groupClient.modifyGroup(groupID, groupData);

        MainCLI.printMessage("Modified group \""+groupID+"\"");

        GroupCLI.printGroup(groupData);
    }
}
