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
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class AuditFileRetrieveCLI extends CLI {

    public AuditCLI auditCLI;

    public AuditFileRetrieveCLI(AuditCLI auditCLI) {
        super("file-retrieve", "Retrieve audit file", auditCLI);
        this.auditCLI = auditCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "Output file.");
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

        if (cmdArgs.length < 1) {
            throw new Exception("Missing audit file name.");

        } if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        String filename = cmdArgs[0];
        String output = cmd.getOptionValue("output");
        if (output == null) output = filename;

        AuditClient auditClient = auditCLI.getAuditClient();
        StreamingOutput so = auditClient.getAuditFile(filename);

        try (OutputStream out = new FileOutputStream(output)) {
            so.write(out);
        }
    }
}
