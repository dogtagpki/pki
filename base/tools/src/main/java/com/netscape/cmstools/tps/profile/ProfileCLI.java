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

import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.tps.profile.ProfileClient;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.cmstools.tps.TPSCLI;

/**
 * @author Endi S. Dewata
 */
public class ProfileCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileCLI.class);

    public TPSCLI tpsCLI;
    public ProfileClient profileClient;

    public ProfileCLI(TPSCLI tpsCLI) {
        super("profile", "Profile management commands", tpsCLI);
        this.tpsCLI = tpsCLI;

        addModule(new ProfileAddCLI(this));
        addModule(new ProfileFindCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileRemoveCLI(this));
        addModule(new ProfileShowCLI(this));

        addModule(new ProfileMappingCLI(this));
    }

    @Override
    public String getManPage() {
        return "pki-tps-profile";
    }

    public ProfileClient getProfileClient() throws Exception {

        if (profileClient != null) return profileClient;

        PKIClient client = getClient();
        profileClient = (ProfileClient)parent.getClient("profile");

        return profileClient;
    }

    public static void printProfileData(ProfileData profileData, boolean showProperties) throws IOException {
        System.out.println("  Profile ID: " + profileData.getID());
        if (profileData.getStatus() != null) System.out.println("  Status: " + profileData.getStatus());

        if (showProperties) {
            System.out.println("  Properties:");
            Map<String, String> properties = profileData.getProperties();
            if (properties != null) {
                for (String name : properties.keySet()) {
                    String value = properties.get(name);
                    System.out.println("    " + name + ": " + value);
                }
            }
        }

        Link link = profileData.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
