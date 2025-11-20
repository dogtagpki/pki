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

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditModifyCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuditModifyCLI.class);

    public AuditCLI auditCLI;

    public AuditModifyCLI(AuditCLI auditCLI) {
        super("mod", "Modify audit configuration", auditCLI);
        this.auditCLI = auditCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "action", true, "Action: enable, disable.");
        option.setArgName("action");
        options.addOption(option);

        option = new Option(null, "input", true, "Input file containing audit configuration.");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "output", true, "Output file to store audit configuration.");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String action = cmd.getOptionValue("action");
        String input = cmd.getOptionValue("input");
        String output = cmd.getOptionValue("output");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        AuditClient auditClient = auditCLI.getAuditClient(client);
        AuditConfig auditConfig;

        if (action == null) { // modify audit configuration

            if (input == null) {
                throw new Exception("Missing action or input file.");
            }

            try (BufferedReader in = new BufferedReader(new FileReader(input));
                StringWriter sw = new StringWriter();
                PrintWriter out = new PrintWriter(sw, true)) {

                String line;
                while ((line = in.readLine()) != null) {
                    out.println(line);
                }

                auditConfig = JSONSerializer.fromJSON(sw.toString(), AuditConfig.class);
            }

            auditConfig = auditClient.updateAuditConfig(auditConfig);

        } else { // change audit status

            if (input != null) {
                throw new Exception("Action and input file are mutually exclusive.");
            }

            auditConfig = auditClient.changeAuditStatus(action);
        }

        MainCLI.printMessage("Modified audit configuration");

        if (output == null) {
            AuditCLI.printAuditConfig(auditConfig);

        } else {
            try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
                out.println(auditConfig.toJSON());
            }
        }
    }
}
