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

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupData;
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

        addModule(new GroupMemberCLI(this));
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
        groupClient = (GroupClient)parent.getClient("group");

        // if this is a top-level command
        if (groupClient == null) {
            // determine the subsystem
            String subsystem = client.getSubsystem();
            if (subsystem == null) subsystem = "ca";

            // create new group client
            groupClient = new GroupClient(client, subsystem);
        }

        super.execute(args);
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
}
