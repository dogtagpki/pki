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

package com.netscape.cmstools.key;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.CLI;

public class KeyModifyCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyModifyCLI(KeyCLI keyCLI) {
        super("mod", "Modify the status of a key", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Key ID> [OPTIONS]", options);
    }

    public void execute(String[] args) {

        // Check for "--help" prior to parsing due to required option
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        Option option = new Option(null, "status", true, "Status of the key.\nValid values: active, inactive");
        option.setRequired(true);
        option.setArgName("status");
        options.addOption(option);

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String status = cmd.getOptionValue("status");
        if (status == null) {
            System.out.println("No status:: " + status);
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();
        if (cmdArgs.length != 1) {
            printHelp();
            System.exit(-1);
        }
        KeyId keyId = new KeyId(cmdArgs[0]);

        keyCLI.keyClient.modifyKeyStatus(keyId, status);

        KeyInfo keyInfo = keyCLI.keyClient.getKeyInfo(keyId);
        KeyCLI.printKeyInfo(keyInfo);
    }
}
