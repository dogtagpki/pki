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

package com.netscape.cmstools.tps.profile;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingRemoveCLI extends CLI {

    public ProfileMappingCLI profileMappingCLI;

    public ProfileMappingRemoveCLI(ProfileMappingCLI profileMappingCLI) {
        super("del", "Remove profile mapping", profileMappingCLI);
        this.profileMappingCLI = profileMappingCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile Mapping ID>", options);
    }

    public void execute(String[] args) throws Exception {

        if (args.length != 1) {
            printHelp();
            System.exit(1);
        }

        String profileMappingID = args[0];

        profileMappingCLI.profileMappingClient.removeProfileMapping(profileMappingID);

        MainCLI.printMessage("Deleted profile mapping \"" + profileMappingID + "\"");
    }
}
