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

package com.netscape.cmstools.client;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 * @deprecated Replaced by NSSCertRemoveCLI.
 */
@Deprecated
public class ClientCertRemoveCLI extends CommandCLI {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertRemoveCLI.class);

    public ClientCLI clientCLI;

    public ClientCertRemoveCLI(ClientCLI clientCLI) {
        super("cert-del", "Remove certificate from NSS database", clientCLI);
        this.clientCLI = clientCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <nickname> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        logger.warn("The pki " + getFullName() + " has been deprecated. Use pki nss-cert-del instead.");

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No nickname specified.");
        }

        String nickname = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoUtil.deleteCertificates(nickname);

        MainCLI.printMessage("Removed certificate \"" + nickname + "\"");
   }
}
