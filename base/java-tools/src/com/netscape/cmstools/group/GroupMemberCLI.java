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

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberCLI extends CLI {

    public GroupClient groupClient;

    public GroupMemberCLI(GroupCLI parent) {
        super("member", "Group member management commands", parent);

        addModule(new GroupMemberFindCLI(this));
        addModule(new GroupMemberShowCLI(this));
        addModule(new GroupMemberAddCLI(this));
        addModule(new GroupMemberRemoveCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        groupClient = ((GroupCLI)parent).groupClient;

        super.execute(args);
    }

    public static void printGroupMember(GroupMemberData groupMemberData) {
        System.out.println("  User: "+groupMemberData.getID());

        Link link = groupMemberData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
