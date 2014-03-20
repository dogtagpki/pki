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

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.CLI;

public class KeyShowCLI extends CLI{

    public KeyCLI keyCLI;

    public KeyShowCLI(KeyCLI keyCLI){
        super("show", "Get key", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Key Id>", options);
    }

    public void execute(String[] args){

        if (args.length != 1){
            printHelp();
            System.exit(-1);
        }

        KeyId keyId = new KeyId(args[0].trim());

        KeyInfo keyInfo = keyCLI.keyClient.getKeyInfo(keyId);

        KeyCLI.printKeyInfo(keyInfo);
    }

}
