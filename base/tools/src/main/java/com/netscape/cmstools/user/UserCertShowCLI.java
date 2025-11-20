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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.user;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URLEncoder;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserCertShowCLI.class);

    public UserCertCLI userCertCLI;

    public UserCertShowCLI(UserCertCLI userCertCLI) {
        super("show", "Show user certificate", userCertCLI);
        this.userCertCLI = userCertCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> <Cert ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pretty", false, "Pretty print");
        options.addOption(null, "encoded", false, "Base-64 encoded");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 2) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        boolean showPrettyPrint = cmd.hasOption("pretty");
        boolean showEncoded = cmd.hasOption("encoded");

        String userID = cmdArgs[0];
        String certID = cmdArgs[1];
        String file = cmd.getOptionValue("output");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = userCertCLI.parent.subsystemCLI.getSubsystemClient(client);
        UserClient userClient = new UserClient(subsystemClient);
        UserCertData userCertData = userClient.getUserCert(userID, URLEncoder.encode(certID, "UTF-8"));

        String encoded = userCertData.getEncoded();
        if (encoded != null && file != null) {
            // store cert to file
            PrintWriter out = new PrintWriter(new FileWriter(file));
            out.print(encoded);
            out.close();
        }

        MainCLI.printMessage("Certificate \"" + userCertData.getID() + "\"");

        UserCertCLI.printCert(userCertData, showPrettyPrint, showEncoded);
    }
}
