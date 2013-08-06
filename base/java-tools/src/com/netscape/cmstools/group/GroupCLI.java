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

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupCLI extends CLI {

    public GroupClient groupClient;

    public GroupCLI(CLI parent) {
        super("group", "Group management commands", parent);

        addModule(new GroupFindCLI(this));
        addModule(new GroupShowCLI(this));
        addModule(new GroupAddCLI(this));
        addModule(new GroupModifyCLI(this));
        addModule(new GroupRemoveCLI(this));

        addModule(new GroupFindMemberCLI(this));
        addModule(new GroupShowMemberCLI(this));
        addModule(new GroupAddMemberCLI(this));
        addModule(new GroupRemoveMemberCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        groupClient = new GroupClient(client);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \""+command+"\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printGroup(GroupData groupData) {
        System.out.println("  Group ID: "+groupData.getID());

        String description = groupData.getDescription();
        if (!StringUtils.isEmpty(description)) System.out.println("  Description: "+description);

        Link link = groupData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

    public static void printGroupMember(GroupMemberData groupMemberData) {
        System.out.println("  User: "+groupMemberData.getID());

        Link link = groupMemberData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
