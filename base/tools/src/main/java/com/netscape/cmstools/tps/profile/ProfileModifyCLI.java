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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.tps.profile.ProfileClient;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileModifyCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileModifyCLI.class);

    public ProfileCLI profileCLI;

    public ProfileModifyCLI(ProfileCLI profileCLI) {
        super("mod", "Modify profile", profileCLI);
        this.profileCLI = profileCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "action", true, "Action: update (default), submit, cancel, approve, reject, enable, disable.");
        option.setArgName("action");
        options.addOption(option);

        option = new Option(null, "input", true, "Input file containing profile properties.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileID = cmdArgs[0];
        String action = cmd.getOptionValue("action", "update");
        String input = cmd.getOptionValue("input");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ProfileClient profileClient = profileCLI.getProfileClient();
        ProfileData profileData;

        if (action.equals("update")) {

            if (input == null) {
                throw new Exception("Missing input file");
            }

            try (BufferedReader in = new BufferedReader(new FileReader(input));
                StringWriter sw = new StringWriter();
                PrintWriter out = new PrintWriter(sw, true)) {

                String line;
                while ((line = in.readLine()) != null) {
                    out.println(line);
                }

                profileData = ProfileData.valueOf(sw.toString());
            }

            profileData = profileClient.updateProfile(profileID, profileData);

        } else { // other actions
            profileData = profileClient.changeProfileStatus(profileID, action);
        }

        MainCLI.printMessage("Modified profile \"" + profileID + "\"");

        ProfileCLI.printProfileData(profileData, true);
    }
}
