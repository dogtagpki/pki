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

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.common.ConfigClient;
import org.dogtagpki.common.ConfigData;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmstools.config.ConfigCLI;

/**
 * @author Endi S. Dewata
 */
public class ConfigShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConfigShowCLI.class);

    public ConfigCLI configCLI;

    public ConfigShowCLI(ConfigCLI configCLI) {
        super("show", "Show general properties", configCLI);
        this.configCLI = configCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + "[OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "Output file to store general properties.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String output = cmd.getOptionValue("output");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        ConfigClient configClient = configCLI.getConfigClient(client);
        ConfigData configData = configClient.getConfig();

        if (output == null) {
            MainCLI.printMessage("Configuration");
            ConfigCLI.printConfigData(configData);

        } else {
            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(configData.toJSON());
            }
            MainCLI.printMessage("Stored configuration into " + output);
        }
    }
}
