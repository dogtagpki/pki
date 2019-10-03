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

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCertAddCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserCertAddCLI.class);

    public UserCertCLI userCertCLI;

    public UserCertAddCLI(UserCertCLI userCertCLI) {
        super("add", "Add user certificate", userCertCLI);
        this.userCertCLI = userCertCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "input", true, "Input file");
        option.setArgName("file");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number of certificate in CA");
        option.setArgName("serial number");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No User ID specified.");
        }

        String userID = cmdArgs[0];
        String inputFile = cmd.getOptionValue("input");
        String serialNumber = cmd.getOptionValue("serial");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String encoded;

        if (inputFile != null && serialNumber != null) {
            throw new Exception("Conflicting options: --input and --serial.");

        } else if (inputFile != null) {
            logger.info("Reading certificate from " + inputFile);

            encoded = new String(Files.readAllBytes(Paths.get(inputFile)));
            logger.info("Certificate:\n" + encoded);

        } else if (serialNumber != null) {
            logger.info("Downloading certificate " + serialNumber);

            CAClient caClient = MainCLI.createCAClient(parent.getClient());
            CACertClient certClient = new CACertClient(caClient);

            CertData certData = certClient.getCert(new CertId(serialNumber));
            encoded = certData.getEncoded();
            logger.info("Certificate:\n" + encoded);

        } else {
            throw new Exception("Missing input file or serial number.");
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setEncoded(encoded);

        logger.info("Request:\n" + userCertData);

        UserClient userClient = userCertCLI.getUserClient();
        userCertData = userClient.addUserCert(userID, userCertData);

        MainCLI.printMessage("Added certificate \"" + userCertData.getID() + "\"");

        UserCertCLI.printCert(userCertData, false, false);
    }
}
