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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.system.Feature;
import com.netscape.cmstools.cli.CLI;

public class FeatureShowCLI extends CLI {

    public FeatureCLI featureCLI;

    public FeatureShowCLI(FeatureCLI featureCLI) {
        super("show", "Show features", featureCLI);
        this.featureCLI = featureCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <ID>", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            System.err.println("Error: too many arguments.");
            printHelp();
            System.exit(-1);
        }

        if (cmdArgs.length == 0) {
            System.err.println("Error: No ID specified.");
            printHelp();
            System.exit(-1);
        }

        String featureID = cmdArgs[0];

        Feature data = featureCLI.featureClient.getFeature(featureID);
        FeatureCLI.printFeature(data);
    }

}
