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

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.CLI;

public class KeyModifyCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyModifyCLI(KeyCLI keyCLI) {
        super("mod", "Modify the status of a key", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Key ID> --status <status> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "status", true, "Status of the key.\nValid values: active, inactive");
        option.setRequired(true);
        option.setArgName("status");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("No Key ID specified.");
        }

        String status = cmd.getOptionValue("status");

        KeyId keyId = new KeyId(cmdArgs[0]);

        keyCLI.keyClient.modifyKeyStatus(keyId, status);

        KeyInfo keyInfo = keyCLI.keyClient.getKeyInfo(keyId);
        KeyCLI.printKeyInfo(keyInfo);
    }
}
