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

package com.netscape.cms.client.user;

import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserRemoveCLI extends CLI {

    public UserCLI parent;

    public UserRemoveCLI(UserCLI parent) {
        super("del", "Remove user");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <User ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        if (args.length != 1) {
            printHelp();
            System.exit(1);
        }

        String userID = args[0];

        parent.client.removeUser(userID);

        MainCLI.printMessage("Deleted user \"" + userID + "\"");
    }
}
