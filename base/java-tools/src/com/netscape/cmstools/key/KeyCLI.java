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

import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyDataInfo;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class KeyCLI extends CLI {

    public KeyClient keyClient;

    public KeyCLI(CLI parent) {
        super("key", "Key management commands", parent);

        addModule(new KeyFindCLI(this));
        addModule(new KeyRequestFindCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();

        // determine the subsystem
        String subsystem = client.getSubsystem();
        if (subsystem == null) subsystem = "kra";

        // create new key client
        keyClient = new KeyClient(client, subsystem);

        super.execute(args);
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
