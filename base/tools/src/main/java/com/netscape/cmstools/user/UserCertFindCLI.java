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

package com.netscape.cmstools.user;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserCertFindCLI.class);

    public UserCertCLI userCertCLI;

    public UserCertFindCLI(UserCertCLI userCertCLI) {
        super("find", "Find user certificates", userCertCLI);
        this.userCertCLI = userCertCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No User ID specified.");
        }

        String userID = cmdArgs[0];

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = userCertCLI.parent.subsystemCLI.getSubsystemClient(client);
        UserClient userClient = new UserClient(subsystemClient);
        UserCertCollection response = userClient.findUserCerts(userID, start, size);

        Integer total = response.getTotal();
        if (total != null) {
            MainCLI.printMessage(total + " entries matched");
            if (total == 0) return;
        }

        Collection<UserCertData> entries = response.getEntries();
        boolean first = true;

        for (UserCertData userCertData : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            UserCertCLI.printCert(userCertData, false, false);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }
}
