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

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tps.authenticator.AuthenticatorClient;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticatorFindCLI.class);

    public AuthenticatorCLI authenticatorCLI;

    public AuthenticatorFindCLI(AuthenticatorCLI authenticatorCLI) {
        super("find", "Find authenticators", authenticatorCLI);
        this.authenticatorCLI = authenticatorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [FILTER] [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String filter = cmdArgs.length > 0 ? cmdArgs[0] : null;

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = authenticatorCLI.tpsCLI.getSubsystemClient(client);
        AuthenticatorClient authenticatorClient = new AuthenticatorClient(subsystemClient);
        AuthenticatorCollection result = authenticatorClient.findAuthenticators(filter, start, size);

        Integer total = result.getTotal();
        if (total != null) {
            MainCLI.printMessage(total + " entries matched");
            if (total == 0) return;
        }

        Collection<AuthenticatorData> authenticators = result.getEntries();
        boolean first = true;

        for (AuthenticatorData authenticatorData : authenticators) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            AuthenticatorCLI.printAuthenticatorData(authenticatorData, false);
        }

        MainCLI.printMessage("Number of entries returned " + authenticators.size());
    }
}
