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

import java.io.IOException;
import java.util.Map;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.tps.profile.ProfileClient;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileCLI extends CLI {

    public ProfileClient profileClient;

    public ProfileCLI(CLI parent) {
        super("profile", "Profile management commands", parent);

        addModule(new ProfileAddCLI(this));
        addModule(new ProfileFindCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileRemoveCLI(this));
        addModule(new ProfileShowCLI(this));

        addModule(new ProfileMappingCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        profileClient = (ProfileClient)parent.getClient("profile");

        super.execute(args);
    }

    public static void printProfileData(ProfileData profileData, boolean showProperties) throws IOException {
        System.out.println("  Profile ID: " + profileData.getID());
        if (profileData.getStatus() != null) System.out.println("  Status: " + profileData.getStatus());

        if (showProperties) {
            System.out.println("  Properties:");
            Map<String, String> properties = profileData.getProperties();
            for (String name : properties.keySet()) {
                String value = properties.get(name);
                System.out.println("    " + name + ": " + value);
            }
        }

        Link link = profileData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
