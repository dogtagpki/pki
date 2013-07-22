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

package com.netscape.cmstools.cli;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.tps.TPSClient;
import com.netscape.cmstools.token.TokenCLI;

/**
 * @author Endi S. Dewata
 */
public class TPSCLI extends CLI {

    public MainCLI mainCLI;
    public TPSClient tpsClient;

    public TPSCLI(MainCLI mainCLI) {
        super("tps", "TPS management commands", mainCLI);
        this.mainCLI = mainCLI;

        addModule(new TokenCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

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

        tpsClient = new TPSClient(mainCLI.client);

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
}
