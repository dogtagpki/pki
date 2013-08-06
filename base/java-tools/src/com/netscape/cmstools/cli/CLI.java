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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cli;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.client.PKIClient;


/**
 * @author Endi S. Dewata
 */
public class CLI {

    public static boolean verbose;

    public static CommandLineParser parser = new PosixParser();
    public static HelpFormatter formatter = new HelpFormatter();

    public String name;
    public String description;
    public CLI parent;

    public Options options = new Options();
    public Map<String, CLI> modules = new LinkedHashMap<String, CLI>();

    public PKIClient client;

    public CLI(String name, String description) {
        this(name, description, null);
    }

    public CLI(String name, String description, CLI parent) {
        this.name = name;
        this.description = description;
        this.parent = parent;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFullName() {
        if (parent == null) {
            return name;
        } else {
            return parent.getName() + "-" + name;
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void addModule(CLI module) {
        modules.put(module.getName(), module);
    }

    public CLI getModule(String name) {
        return modules.get(name);
    }

    public PKIClient getClient() {
        return client;
    }

    public Object getClient(String name) {
        return null;
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = getFullName() + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String moduleName;
        String moduleCommand;

        // If a command contains a '-' sign it will be
        // split into module name and module command.
        // Otherwise it's a single command.
        int i = command.indexOf('-');
        if (i >= 0) { // <module name>-<module command>
            moduleName = command.substring(0, i);
            moduleCommand = command.substring(i+1);

        } else { // <command>
            moduleName = command;
            moduleCommand = null;
        }

        // get command module
        if (verbose) System.out.println("Module: " + moduleName);
        CLI module = getModule(moduleName);
        if (module == null) {
            throw new Error("Invalid module \"" + moduleName + "\".");
        }

        // prepare module arguments
        String[] moduleArgs;
        if (moduleCommand != null) {
            moduleArgs = new String[args.length];
            moduleArgs[0] = moduleCommand;
            System.arraycopy(args, 1, moduleArgs, 1, args.length-1);

        } else {
            moduleArgs = new String[args.length-1];
            System.arraycopy(args, 1, moduleArgs, 0, args.length-1);
        }

        module.execute(moduleArgs);
    }

    public static boolean isVerbose() {
        return verbose;
    }

    public static void setVerbose(boolean verbose) {
        CLI.verbose = verbose;
    }
}
