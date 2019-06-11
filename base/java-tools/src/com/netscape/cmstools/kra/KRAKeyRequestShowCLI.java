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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.kra;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.request.RequestId;

public class KRAKeyRequestShowCLI extends CLI {

    public KRAKeyCLI keyCLI;

    public KRAKeyRequestShowCLI(KRAKeyCLI keyCLI) {
        super("request-show", "Get key request", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        // Check for "--help"
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Request ID specified.");
        }

        RequestId requestId = new RequestId(args[0].trim());

        KeyClient keyClient = keyCLI.getKeyClient();
        KeyRequestInfo keyRequestInfo = keyClient.getRequestInfo(requestId);

        KRAKeyCLI.printKeyRequestInfo(keyRequestInfo);
    }
}
