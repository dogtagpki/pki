//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;

public class NSSKeyCLI extends CLI {

    public NSSKeyCLI(NSSCLI nssCLI) {
        super("key", "NSS key management commands", nssCLI);

        addModule(new NSSKeyExportCLI(this));
        addModule(new NSSKeyFindCLI(this));
        addModule(new NSSKeyImportCLI(this));
    }

    public static void printKeyInfo(KeyInfo keyInfo) throws Exception {

        KeyId keyID = keyInfo.getKeyId();
        System.out.println("  Key ID: " + keyID.toHexString());
        System.out.println("  Algorithm: " + keyInfo.getAlgorithm());
    }
}
