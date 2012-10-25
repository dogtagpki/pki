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

package com.netscape.cmstools.key;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyDataInfo;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class KeyCLI extends CLI {

    public MainCLI parent;
    public KeyClient keyClient;

    public KeyCLI(MainCLI parent) {
        super("key", "Key management commands");
        this.parent = parent;

        addModule(new KeyFindCLI(this));
        addModule(new KeyRequestFindCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        keyClient = new KeyClient(parent.connection);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printKeyInfo(KeyDataInfo info) {
        System.out.println("  Key ID: "+info.getKeyId().toHexString());
        if (info.getClientID() != null) System.out.println("  Client ID: "+info.getClientID());
        if (info.getStatus() != null) System.out.println("  Status: "+info.getStatus());
        if (info.getAlgorithm() != null) System.out.println("  Algorithm: "+info.getAlgorithm());
        if (info.getSize() != null) System.out.println("  Size: "+info.getSize());
        if (info.getOwnerName() != null) System.out.println("  Owner: "+info.getOwnerName());
    }

    public static void printKeyRequestInfo(KeyRequestInfo info) {
        System.out.println("  Request ID: "+info.getRequestId().toHexString());
        if (info.getKeyId() != null) System.out.println("  Key ID: "+info.getKeyId().toHexString());
        if (info.getRequestType() != null) System.out.println("  Type: "+info.getRequestType());
        if (info.getRequestStatus() != null) System.out.println("  Status: "+info.getRequestStatus());
    }
}
