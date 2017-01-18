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

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

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
        formatter.printHelp(getFullName() + " <Profile Mapping ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile Mapping ID specified.");
        }

        String profileMappingID = args[0];

        profileMappingCLI.profileMappingClient.removeProfileMapping(profileMappingID);

        MainCLI.printMessage("Deleted profile mapping \"" + profileMappingID + "\"");
    }
}
