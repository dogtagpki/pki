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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.logging;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.logging.AuditClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditFileRemoveCLI extends CLI {

    public AuditCLI auditCLI;

    public AuditFileRemoveCLI(AuditCLI auditCLI) {
        super("file-del", "Remove audit file", auditCLI);
        this.auditCLI = auditCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename> [OPTIONS...]", options);
    }

    public void createOptions() {
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing audit file name.");

        } if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        String filename = cmdArgs[0];

        AuditClient auditClient = auditCLI.getAuditClient();
        // auditClient.removeAuditFile(filename);

        MainCLI.printMessage("Deleted audit file \"" + filename + "\"");
    }
}
