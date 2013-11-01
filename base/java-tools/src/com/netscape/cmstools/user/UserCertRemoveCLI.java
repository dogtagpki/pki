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

import java.net.URLEncoder;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;


/**
 * @author Endi S. Dewata
 */
public class UserCertRemoveCLI extends CLI {

    public UserCertCLI userCertCLI;

    public UserCertRemoveCLI(UserCertCLI userCertCLI) {
        super("del", "Remove user certificate", userCertCLI);
        this.userCertCLI = userCertCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> <Cert ID>", options);
    }

    public void execute(String[] args) throws Exception {

        if (args.length != 2) {
            printHelp();
            System.exit(1);
        }

        String userID = args[0];
        String certID = args[1];

        if (verbose) {
            System.out.println("Removing cert "+certID+" from user "+userID+".");
        }

        userCertCLI.userClient.removeUserCert(userID, URLEncoder.encode(certID, "UTF-8"));

        MainCLI.printMessage("Deleted certificate \"" + certID + "\"");
    }
}
