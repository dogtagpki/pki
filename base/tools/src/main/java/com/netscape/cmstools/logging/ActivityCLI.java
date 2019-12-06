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

import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.logging.ActivityClient;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.cmstools.tps.TPSCLI;

/**
 * @author Endi S. Dewata
 */
public class ActivityCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ActivityCLI.class);

    public TPSCLI tpsCLI;
    public ActivityClient activityClient;

    public ActivityCLI(TPSCLI tpsCLI) {
        super("activity", "Activity management commands", tpsCLI);
        this.tpsCLI = tpsCLI;

        addModule(new ActivityFindCLI(this));
        addModule(new ActivityShowCLI(this));
    }

    public ActivityClient getActivityClient() throws Exception {

        if (activityClient != null) return activityClient;

        PKIClient client = getClient();
        activityClient = (ActivityClient)parent.getClient("activity");

        return activityClient;
    }

    public static void printActivity(ActivityData activity, boolean showAll) {
        System.out.println("  Activity ID: " + activity.getID());
        if (activity.getTokenID() != null) System.out.println("  Token ID: " + activity.getTokenID());
        if (activity.getUserID() != null) System.out.println("  User ID: " + activity.getUserID());
        if (activity.getIP() != null) System.out.println("  IP: " + activity.getIP());
        if (activity.getOperation() != null) System.out.println("  Operation: " + activity.getOperation());
        if (activity.getResult() != null) System.out.println("  Result: " + activity.getResult());
        if (activity.getDate() != null) System.out.println("  Date: " + activity.getDate());

        if (showAll) {
            if (activity.getMessage() != null)  System.out.println("  Message: " + activity.getMessage());
        }

        Link link = activity.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
