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

import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.certsrv.user.UserData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class UserAddCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserAddCLI.class);

    public UserCLI userCLI;

    public UserAddCLI(UserCLI userCLI) {
        super("add", "Add user", userCLI);
        this.userCLI = userCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <User ID> --fullName <fullname> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "fullName", true, "DEPRECATED: Full name");
        option.setArgName("full name");
        options.addOption(option);

        option = new Option(null, "full-name", true, "Full name");
        option.setArgName("full name");
        options.addOption(option);

        option = new Option(null, "email", true, "Email");
        option.setArgName("email");
        options.addOption(option);

        option = new Option(null, "password", true, "Password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "phone", true, "Phone");
        option.setArgName("phone");
        options.addOption(option);

        option = new Option(null, "type", true, "Type: userType, agentType, adminType, subsystemType");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "state", true, "State");
        option.setArgName("state");
        options.addOption(option);

        option = new Option(null, "cert-file", true, "Path to user certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "User certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "security-domain", true, "Security domain URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No User ID specified.");
        }

        String userID = cmdArgs[0];
        String fullName = cmd.getOptionValue("full-name");

        if (fullName == null) {
            fullName = cmd.getOptionValue("fullName");
            if (fullName != null) {
                logger.warn("The --fullName option has been deprecated. Use --full-name instead.");
            }
        }

        if (fullName == null) {
            throw new Exception("Missing full name");
        }

        String installToken = cmd.getOptionValue("install-token");
        String sessionID;

        if (installToken != null) {
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        } else {
            sessionID = cmd.getOptionValue("session");
        }

        UserData userData = new UserData();
        userData.setUserID(userID);
        userData.setFullName(fullName);
        userData.setEmail(cmd.getOptionValue("email"));
        userData.setPassword(cmd.getOptionValue("password"));
        userData.setPhone(cmd.getOptionValue("phone"));
        userData.setType(cmd.getOptionValue("type"));
        userData.setState(cmd.getOptionValue("state"));

        byte[] binCert = null;

        String filename = cmd.getOptionValue("cert-file");
        if (filename != null) {
            binCert = Files.readAllBytes(Paths.get(filename));

            String format = cmd.getOptionValue("format");
            if (format == null || "PEM".equalsIgnoreCase(format)) {
                binCert = Cert.parseCertificate(new String(binCert));

            } else if ("DER".equalsIgnoreCase(format)) {
                // nothing to do

            } else {
                throw new Exception("Unsupported format: " + format);
            }
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = userCLI.subsystemCLI.getSubsystemClient(client);
        UserClient userClient = new UserClient(subsystemClient);

        String securityDomain = cmd.getOptionValue("security-domain");
        if (securityDomain == null) {

            userData = userClient.addUser(userData);

            if (binCert != null) { // cert is optional

                String pemCert =
                        Cert.HEADER + "\n" +
                        Utils.base64encodeMultiLine(binCert) +
                        Cert.FOOTER + "\n";

                UserCertData userCertData = new UserCertData();
                userCertData.setEncoded(pemCert);

                userCertData = userClient.addUserCert(userID, userCertData);
            }

        } else {
            URI uri = new URL(securityDomain).toURI();

            if (binCert == null) { // cert is required
                throw new Exception("Missing user certificate");
            }

            String b64Cert = Utils.base64encodeSingleLine(binCert);

            subsystemClient.addUser(uri, userID, fullName, b64Cert, sessionID);
        }

        MainCLI.printMessage("Added user \"" + userID + "\"");

        UserCLI.printUser(userData);
    }
}
