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

package com.netscape.cmstools.logging;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditModifyCLI extends CLI {

    public AuditCLI auditCLI;

    public AuditModifyCLI(AuditCLI auditCLI) {
        super("mod", "Modify audit configuration", auditCLI);
        this.auditCLI = auditCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "input", true, "Input file containing audit configuration.");
        option.setArgName("file");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(null, "output", true, "Output file to store audit configuration.");
        option.setArgName("file");
        options.addOption(option);

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            printHelp();
            System.exit(1);
        }

        String input = cmd.getOptionValue("input");
        String output = cmd.getOptionValue("output");

        if (input == null) {
            System.err.println("Error: Input file is required.");
            printHelp();
            System.exit(1);
        }

        AuditConfig auditConfig;

        try (BufferedReader in = new BufferedReader(new FileReader(input));
            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw, true)) {

            String line;
            while ((line = in.readLine()) != null) {
                out.println(line);
            }

            auditConfig = AuditConfig.valueOf(sw.toString());
        }

        auditConfig = auditCLI.auditClient.updateAuditConfig(auditConfig);

        MainCLI.printMessage("Updated audit configuration");

        if (output == null) {
            AuditCLI.printAuditConfig(auditConfig);

        } else {
            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(auditConfig);
            }
        }
    }
}
