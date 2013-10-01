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

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingShowCLI extends CLI {

    public ProfileMappingCLI profileMappingCLI;

    public ProfileMappingShowCLI(ProfileMappingCLI profileMappingCLI) {
        super("show", "Show profileMapping", profileMappingCLI);
        this.profileMappingCLI = profileMappingCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile Mapping ID>", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "output", true, "Output file to store profile mapping properties.");
        option.setArgName("file");
        options.addOption(option);

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            printHelp();
            System.exit(1);
        }

        String profileMappingID = args[0];
        String output = cmd.getOptionValue("output");

        ProfileMappingData profileMappingData = profileMappingCLI.profileMappingClient.getProfileMapping(profileMappingID);

        if (output == null) {
            MainCLI.printMessage("ProfileMapping \"" + profileMappingID + "\"");
            ProfileMappingCLI.printProfileMappingData(profileMappingData, true);

        } else {
            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(profileMappingData);
            }
            MainCLI.printMessage("Stored profile mapping \"" + profileMappingID + "\" into " + output);
        }
    }
}
