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

import java.io.FileOutputStream;
import java.io.OutputStream;

import javax.ws.rs.core.StreamingOutput;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.logging.AuditLogFindRequest;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class AuditLogFindCLI extends CLI {

    public AuditCLI auditCLI;

    public AuditLogFindCLI(AuditCLI auditCLI) {
        super("log-find", "Find audit logs", auditCLI);
        this.auditCLI = auditCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "filename", true, "Audit log file name.");
        option.setArgName("name");
        options.addOption(option);

        option = new Option(null, "output", true, "Output file to store audit logs.");
        option.setArgName("path");
        options.addOption(option);

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

        String filename = cmd.getOptionValue("filename");
        String output = cmd.getOptionValue("output");

        AuditLogFindRequest request = new AuditLogFindRequest();
        request.setFileName(filename);

        AuditClient auditClient = auditCLI.getAuditClient();
        StreamingOutput so = auditClient.findAuditLogs(request);

        if (output == null) {
            so.write(System.out);

        } else {
            try (OutputStream out = new FileOutputStream(output)) {
                so.write(out);
            }
        }
    }
}
