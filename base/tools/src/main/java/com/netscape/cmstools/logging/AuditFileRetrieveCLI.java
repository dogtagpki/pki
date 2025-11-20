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

import java.io.File;
import java.io.InputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.FileUtils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.logging.AuditClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class AuditFileRetrieveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuditFileRetrieveCLI.class);

    public AuditCLI auditCLI;

    public AuditFileRetrieveCLI(AuditCLI auditCLI) {
        super("file-retrieve", "Retrieve audit file", auditCLI);
        this.auditCLI = auditCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "Output file.");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing audit file name.");

        } if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        String filename = cmdArgs[0];
        String output = cmd.getOptionValue("output");
        if (output == null) output = filename;

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        AuditClient auditClient = auditCLI.getAuditClient(client);
        InputStream is = auditClient.getAuditFile(filename);
        File outputFile = new File(output);
        FileUtils.copyInputStreamToFile(is, outputFile);
    }
}
