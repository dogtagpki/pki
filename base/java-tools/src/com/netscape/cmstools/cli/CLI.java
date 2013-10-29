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


/**
 * @author Endi S. Dewata
 */
public class CLI {

    public static boolean verbose;

    public static CommandLineParser parser = new PosixParser();
    public static HelpFormatter formatter = new HelpFormatter();

    public String name;
    public String description;

    public Options options = new Options();
    public Map<String, CLI> modules = new LinkedHashMap<String, CLI>();

    public CLI(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isDeprecated() {
        return getClass().getAnnotation(Deprecated.class) != null;
    }

    public void addModule(CLI module) {
        modules.put(module.getName(), module);
    }

    public CLI getModule(String name) {
        return modules.get(name);
    }

    public void execute(String[] args) throws Exception {
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

            String label = name + "-" + module.getName();

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
                String label = name+"-"+module.getName();

                int padding = rightPadding - leftPadding - label.length();
                if (padding < 1) padding = 1;

                System.out.print(StringUtils.repeat(" ", leftPadding));
                System.out.print(label);
                System.out.print(StringUtils.repeat(" ", padding));
                System.out.println(module.getDescription());
            }
        }
    }

    public static boolean isVerbose() {
        return verbose;
    }

    public static void setVerbose(boolean verbose) {
        CLI.verbose = verbose;
    }
}
