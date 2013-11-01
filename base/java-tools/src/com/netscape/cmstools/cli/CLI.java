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

import java.util.ArrayList;
import java.util.Collection;
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
            return parent.getFullName() + "-" + name;
        }
    }

    public String getFullModuleName(String moduleName) {
        return getFullName() + "-" + moduleName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public CLI getParent() {
        return parent;
    }

    public boolean isDeprecated() {
        return getClass().getAnnotation(Deprecated.class) != null;
    }

    public CLI getModule(String name) {
        return modules.get(name);
    }

    public void addModule(CLI module) {
        modules.put(module.getName(), module);
    }

    public CLI removeModule(String name) {
        return modules.remove(name);
    }

    public PKIClient getClient() {
        return client;
    }

    public Object getClient(String name) {
        if (parent != null) return parent.getClient(name);
        return null;
    }

    public Collection<CLI> getDeprecatedModules() {
        Collection<CLI> list = new ArrayList<CLI>();
        for (CLI module : modules.values()) {
            if (!module.isDeprecated()) continue;
            list.add(module);
        }
        return list;
    }

    public void printHelp() {

        int leftPadding = 1;
        int rightPadding = 25;

        System.out.println("Commands:");

        for (CLI module : modules.values()) {
            if (module.isDeprecated()) continue;

            String label = module.getFullName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }

        Collection<CLI> deprecatedModules = getDeprecatedModules();

        if (!deprecatedModules.isEmpty()) {
            System.out.println();
            System.out.println("Deprecated:");

            for (CLI module : deprecatedModules) {
                String label = module.getFullName();

                int padding = rightPadding - leftPadding - label.length();
                if (padding < 1)
                    padding = 1;

                System.out.print(StringUtils.repeat(" ", leftPadding));
                System.out.print(label);
                System.out.print(StringUtils.repeat(" ", padding));
                System.out.println(module.getDescription());
            }
        }
    }

    public void execute(String[] args) throws Exception {

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        // A command consists of parts joined by dashes: <part 1>-<part 2>-...-<part N>.
        // For example: cert-request-find
        String command = args[0];

        // The command will be split into module name and module command, for example:
        //  - module name: cert
        //  - module command: request-find
        String moduleName = null;
        String moduleCommand = null;

        // Search the module by incrementally adding parts into module name.
        // Repeat until it finds the module or until there is no more parts to add.
        CLI module = null;
        int position = 0;

        while (true) {

            // Find the next dash.
            int i = command.indexOf('-', position);
            if (i >= 0) {
                // If dash found, split command.
                moduleName = command.substring(0, i);
                moduleCommand = command.substring(i+1);

            } else {
                // If dash not found, use the whole command.
                moduleName = command;
                moduleCommand = null;
            }

            // Find module with that name.
            module = getModule(moduleName);

            // If module found, stop.
            if (module != null) break;

            // If there's no more dashes, stop.
            if (i < 0) break;

            position = i + 1;
        }

        if (module == null) {
            throw new Error("Invalid module \"" + getFullModuleName(moduleName) + "\".");
        }

        if (verbose) System.out.println("Module: " + moduleName);

        // Prepare module arguments.
        String[] moduleArgs;
        if (moduleCommand != null) {
            // If module command exists, include it as arguments: <module command> <args>...
            moduleArgs = new String[args.length];
            moduleArgs[0] = moduleCommand;
            System.arraycopy(args, 1, moduleArgs, 1, args.length-1);

        } else {
            // Otherwise, pass the original arguments: <args>...
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
