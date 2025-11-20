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

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.logging.AuditFile;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditFileFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuditFileFindCLI.class);

    public AuditCLI auditCLI;

    public AuditFileFindCLI(AuditCLI auditCLI) {
        super("file-find", "Find audit files", auditCLI);
        this.auditCLI = auditCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 0) {
            throw new Exception("Too many arguments specified.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        AuditClient auditClient = auditCLI.getAuditClient(client);
        AuditFileCollection response = auditClient.findAuditFiles();

        Integer total = response.getTotal();
        if (total != null) {
            MainCLI.printMessage(total + " entries matched");
            if (total == 0) return;
        }

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
