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

import com.netscape.certsrv.tps.profile.ProfileMappingClient;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingCLI extends CLI {

    public ProfileMappingClient profileMappingClient;

    public ProfileMappingCLI(ProfileCLI profileCLI) {
        super("mapping", "Profile mapping management commands", profileCLI);

        addModule(new ProfileMappingAddCLI(this));
        addModule(new ProfileMappingFindCLI(this));
        addModule(new ProfileMappingModifyCLI(this));
        addModule(new ProfileMappingRemoveCLI(this));
        addModule(new ProfileMappingShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        profileMappingClient = (ProfileMappingClient)parent.getClient("profile-mapping");

        super.execute(args);
    }

    public static void printProfileMappingData(ProfileMappingData profileMappingData, boolean showProperties) throws IOException {
        System.out.println("  Profile Mapping ID: " + profileMappingData.getID());
        if (profileMappingData.getStatus() != null) System.out.println("  Status: " + profileMappingData.getStatus());

        if (showProperties) {
            System.out.println("  Properties:");
            Map<String, String> properties = profileMappingData.getProperties();
            for (String name : properties.keySet()) {
                String value = properties.get(name);
                System.out.println("    " + name + ": " + value);
            }
        }

        Link link = profileMappingData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
