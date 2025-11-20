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

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.profile.ProfileMappingClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingRemoveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileMappingRemoveCLI.class);

    public ProfileMappingCLI profileMappingCLI;

    public ProfileMappingRemoveCLI(ProfileMappingCLI profileMappingCLI) {
        super("del", "Remove profile mapping", profileMappingCLI);
        this.profileMappingCLI = profileMappingCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile Mapping ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Profile Mapping ID specified.");
        }

        String profileMappingID = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileMappingCLI.profileCLI.tpsCLI.getSubsystemClient(client);
        ProfileMappingClient profileMappingClient = new ProfileMappingClient(subsystemClient);
        profileMappingClient.removeProfileMapping(profileMappingID);

        MainCLI.printMessage("Deleted profile mapping \"" + profileMappingID + "\"");
    }
}
