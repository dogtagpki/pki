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

import java.util.Collection;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class FeatureFindCLI extends SubsystemCommandCLI {

    public FeatureCLI featureCLI;

    public FeatureFindCLI(FeatureCLI featureCLI) {
        super("find", "Find features", featureCLI);
        this.featureCLI = featureCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = featureCLI.subsystemCLI.getSubsystemClient(client);
        FeatureClient featureClient = new FeatureClient(subsystemClient);
        Collection<Feature> features = featureClient.listFeatures();

        MainCLI.printMessage(features.size() + " entries matched");
        if (features.size() == 0) return;

        boolean first = true;
        for (Feature feature : features) {
            if (first)
                first = false;
            else
                System.out.println();
            FeatureCLI.printFeature(feature);
        }

        MainCLI.printMessage("Number of entries returned " + features.size());
    }
}
