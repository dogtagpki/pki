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

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupMemberData;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GroupMemberCLI.class);

    GroupCLI parent;

    public GroupMemberCLI(GroupCLI parent) {
        super("member", "Group member management commands", parent);

        this.parent = parent;

        addModule(new GroupMemberFindCLI(this));
        addModule(new GroupMemberShowCLI(this));
        addModule(new GroupMemberAddCLI(this));
        addModule(new GroupMemberRemoveCLI(this));
    }

    @Override
    public String getManPage() {
        return "pki-group-member";
    }

    public GroupClient getGroupClient() throws Exception {
        return parent.getGroupClient();
    }

    public static void printGroupMember(GroupMemberData groupMemberData) {
        System.out.println("  User: "+groupMemberData.getID());

        Link link = groupMemberData.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
