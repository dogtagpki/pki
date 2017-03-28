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

import java.util.Collection;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.logging.AuditFile;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditFileFindCLI extends CLI {

    public AuditCLI auditCLI;

    public AuditFileFindCLI(AuditCLI auditCLI) {
        super("file-find", "Find audit files", auditCLI);
        this.auditCLI = auditCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
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

        if (cmdArgs.length > 0) {
            throw new Exception("Too many arguments specified.");
        }

        AuditClient auditClient = auditCLI.getAuditClient();
        AuditFileCollection response = auditClient.findAuditFiles();

        MainCLI.printMessage(response.getTotal() + " entries matched");
        if (response.getTotal() == 0) return;

        Collection<AuditFile> entries = response.getEntries();
        boolean first = true;

        for (AuditFile auditFile : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            AuditCLI.printAuditFile(auditFile);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }
}
