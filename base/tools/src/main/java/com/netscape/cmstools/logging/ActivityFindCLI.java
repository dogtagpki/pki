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

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.logging.ActivityClient;
import com.netscape.certsrv.logging.ActivityCollection;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ActivityFindCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ActivityFindCLI.class);

    public ActivityCLI activityCLI;

    public ActivityFindCLI(ActivityCLI activityCLI) {
        super("find", "Find activities", activityCLI);
        this.activityCLI = activityCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [FILTER] [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String filter = cmdArgs.length > 0 ? cmdArgs[0] : null;

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ActivityClient activityClient = activityCLI.getActivityClient();
        ActivityCollection result = activityClient.findActivities(filter, start, size);

        MainCLI.printMessage(result.getTotal() + " entries matched");
        if (result.getTotal() == 0) return;

        Collection<ActivityData> activities = result.getEntries();
        boolean first = true;

        for (ActivityData activityData : activities) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            ActivityCLI.printActivity(activityData, false);
        }

        MainCLI.printMessage("Number of entries returned " + activities.size());
    }
}
