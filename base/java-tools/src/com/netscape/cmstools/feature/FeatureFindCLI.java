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

import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class FeatureFindCLI extends CLI {

    public FeatureCLI featureCLI;

    public FeatureFindCLI(FeatureCLI featureCLI) {
        super("find", "Find features", featureCLI);
        this.featureCLI = featureCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        @SuppressWarnings("unused")
        CommandLine cmd = parser.parse(options, args);

        FeatureClient featureClient = featureCLI.getFeatureClient();
        List<Feature> features = featureClient.listFeatures();

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
