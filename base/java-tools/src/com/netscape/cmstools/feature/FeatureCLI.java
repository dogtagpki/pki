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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools.feature;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class FeatureCLI extends CLI {

    public FeatureClient featureClient;

    public FeatureCLI(CLI parent) {
        super("feature", "Feature management commands", parent);

        addModule(new FeatureFindCLI(this));
        addModule(new FeatureShowCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public FeatureClient getFeatureClient() throws Exception {

        if (featureClient != null) return featureClient;

        PKIClient client = getClient();
        featureClient = new FeatureClient(client, "ca");

        return featureClient;
    }

    protected static void printFeature(Feature data) {
        System.out.println("  ID:             " + data.getId());
        String desc = data.getDescription();
        if (desc != null)
            System.out.println("  Description:    " + desc);
        String version = data.getVersion();
        if (version != null)
            System.out.println("  Version:        " + version);
        System.out.println("  Enabled:        " + data.isEnabled());
    }

}

