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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.logging;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.logging.ActivityClient;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ActivityCLI extends CLI {

    public ActivityClient activityClient;

    public ActivityCLI(CLI parent) {
        super("activity", "Activity management commands", parent);

        addModule(new ActivityFindCLI(this));
        addModule(new ActivityShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        activityClient = (ActivityClient)parent.getClient("activity");

        super.execute(args);
    }

    public static void printActivity(ActivityData activity) {
        System.out.println("  Activity ID: " + activity.getID());
        if (activity.getTokenID() != null) System.out.println("  Token ID: " + activity.getTokenID());
        if (activity.getUserID() != null) System.out.println("  User ID: " + activity.getUserID());
        if (activity.getDate() != null) System.out.println("  Date: " + activity.getDate());

        Link link = activity.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
