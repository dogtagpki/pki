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

import java.io.IOException;
import java.util.Arrays;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.tps.config.ConfigClient;
import com.netscape.certsrv.tps.config.ConfigData;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ConfigCLI extends CLI {

    public ConfigClient configClient;

    public ConfigCLI(CLI parent) {
        super("config", "Configuration management commands", parent);

        addModule(new ConfigFindCLI(this));
        addModule(new ConfigModifyCLI(this));
        addModule(new ConfigShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        configClient = (ConfigClient)parent.getClient("config");

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printConfigData(ConfigData configData, boolean showProperties) throws IOException {

        System.out.println("  Config ID: " + configData.getID());
        System.out.println("  Display Name: " + configData.getDisplayName());

        if (showProperties) {
            System.out.println("  Properties:");
            for (String name : configData.getPropertyNames()) {
                String value = configData.getProperty(name);
                System.out.println("    " + name + ": " + value);
            }
        }

        Link link = configData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
