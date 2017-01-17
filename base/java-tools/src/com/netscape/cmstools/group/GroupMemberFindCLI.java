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
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberFindCLI extends CLI {

    public GroupMemberCLI groupMemberCLI;

    public GroupMemberFindCLI(GroupMemberCLI groupMemberCLI) {
        super("find", "Find group members", groupMemberCLI);
        this.groupMemberCLI = groupMemberCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Group ID> [FILTER] [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
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

        if (cmdArgs.length < 1 || cmdArgs.length > 2) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        String groupID = cmdArgs[0];
        String filter = cmdArgs.length < 2 ? null : cmdArgs[1];

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        GroupMemberCollection response = groupMemberCLI.groupClient.findGroupMembers(groupID, filter, start, size);

        MainCLI.printMessage(response.getTotal() + " entries matched");
        if (response.getTotal() == 0) return;

        Collection<GroupMemberData> entries = response.getEntries();
        boolean first = true;

        for (GroupMemberData groupMemberData : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            GroupMemberCLI.printGroupMember(groupMemberData);
        }

        MainCLI.printMessage("Number of entries returned "+entries.size());
    }
}
