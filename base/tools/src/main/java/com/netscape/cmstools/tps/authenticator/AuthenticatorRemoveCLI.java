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

package com.netscape.cmstools.tps.authenticator;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.authenticator.AuthenticatorClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorRemoveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticatorRemoveCLI.class);

    public AuthenticatorCLI authenticatorCLI;

    public AuthenticatorRemoveCLI(AuthenticatorCLI authenticatorCLI) {
        super("del", "Remove authenticator", authenticatorCLI);
        this.authenticatorCLI = authenticatorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Authenticator ID> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Authenticator ID specified.");
        }

        String authenticatorID = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = authenticatorCLI.tpsCLI.getSubsystemClient(client);
        AuthenticatorClient authenticatorClient = new AuthenticatorClient(subsystemClient);
        authenticatorClient.removeAuthenticator(authenticatorID);

        MainCLI.printMessage("Deleted authenticator \"" + authenticatorID + "\"");
    }
}
