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

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.group.GroupData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class GroupCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GroupCLI.class);

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

    @Override
    public String getManPage() {
        return "pki-group";
    }

    public GroupClient getGroupClient() throws Exception {

        if (groupClient != null) return groupClient;

        PKIClient client = getClient();

        // determine the subsystem
        String subsystem;
        if (parent instanceof SubsystemCLI) {
            SubsystemCLI subsystemCLI = (SubsystemCLI)parent;
            subsystem = subsystemCLI.getName();
        } else {
            subsystem = client.getSubsystem();
            if (subsystem == null) subsystem = "ca";
        }

        // create new group client
        groupClient = new GroupClient(client, subsystem);

        return groupClient;
    }

    public static void printGroup(GroupData groupData) {
        System.out.println("  Group ID: "+groupData.getID());

        String description = groupData.getDescription();
        if (!StringUtils.isEmpty(description)) System.out.println("  Description: "+description);

        Link link = groupData.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
