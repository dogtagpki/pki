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

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.profile.ProfileMappingClient;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingAddCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileMappingAddCLI.class);

    public ProfileMappingCLI profileMappingCLI;

    public ProfileMappingAddCLI(ProfileMappingCLI profileMappingCLI) {
        super("add", "Add profile mapping", profileMappingCLI);
        this.profileMappingCLI = profileMappingCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " --input <file> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "input", true, "Input file containing profile mapping properties.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String input = cmd.getOptionValue("input");

        if (input == null) {
            throw new Exception("Missing input file");
        }

        ProfileMappingData profileMappingData;

        try (BufferedReader in = new BufferedReader(new FileReader(input));
            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw, true)) {

            String line;
            while ((line = in.readLine()) != null) {
                out.println(line);
            }

            profileMappingData = JSONSerializer.fromJSON(sw.toString(), ProfileMappingData.class);
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileMappingCLI.profileCLI.tpsCLI.getSubsystemClient(client);
        ProfileMappingClient profileMappingClient = new ProfileMappingClient(subsystemClient);
        profileMappingData = profileMappingClient.addProfileMapping(profileMappingData);

        MainCLI.printMessage("Added profile mapping \"" + profileMappingData.getID() + "\"");

        ProfileMappingCLI.printProfileMappingData(profileMappingData, true);
    }
}
