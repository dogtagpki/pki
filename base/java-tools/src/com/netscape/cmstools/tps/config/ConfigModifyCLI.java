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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ConfigModifyCLI extends CLI {

    public ConfigCLI configCLI;

    public ConfigModifyCLI(ConfigCLI configCLI) {
        super("mod", "Modify configuration", configCLI);
        this.configCLI = configCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Config ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "input", true, "Input configuration file.");
        option.setArgName("file");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "output", true, "Output configuration file.");
        option.setArgName("file");
        options.addOption(option);

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            printHelp();
            System.exit(1);
        }

        String configID = args[0];
        String input = cmd.getOptionValue("input");
        String output = cmd.getOptionValue("output");

        if (input == null) {
            System.err.println("Error: Input file is required.");
            printHelp();
            System.exit(1);
        }

        ConfigData configData;

        try (BufferedReader in = new BufferedReader(new FileReader(input));
            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw, true)) {

            String line;
            while ((line = in.readLine()) != null) {
                out.println(line);
            }

            configData = ConfigData.valueOf(sw.toString());
        }

        configData = configCLI.configClient.updateConfig(configID, configData);

        MainCLI.printMessage("Updated configuration");

        if (output == null) {
            ConfigCLI.printConfigData(configData, true);

        } else {
            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(configData);
            }
        }
    }
}
