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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.cli;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;

/**
 * @author Endi S. Dewata
 */
public class CommandCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CommandCLI.class);

    public CommandCLI(String name, String description, CLI parent) {
        super(name, description, parent);

        // add default options
        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");

        createOptions();
    }

    public void createOptions() {
    }

    @Override
    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        execute(cmd);
    }

    public void execute(CommandLine cmd) throws Exception {
    }
}
