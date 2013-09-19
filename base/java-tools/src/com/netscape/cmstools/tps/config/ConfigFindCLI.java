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

package com.netscape.cmstools.tps.config;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.tps.config.ConfigCollection;
import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ConfigFindCLI extends CLI {

    public ConfigCLI configCLI;

    public ConfigFindCLI(ConfigCLI configCLI) {
        super("find", "Find configurations", configCLI);
        this.configCLI = configCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            printHelp();
            System.exit(1);
        }

        ConfigCollection result = configCLI.configClient.findConfigs();

        Collection<ConfigData> entries = result.getConfigs();

        MainCLI.printMessage(entries.size() + " entries matched");
        boolean first = true;

        for (ConfigData configData : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            ConfigCLI.printConfigData(configData, false);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }
}
