//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.request.RequestId;

public class TKSKeyCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSKeyCLI.class);

    public TKSCLI tksCLI;

    public TKSKeyCLI(TKSCLI tksCLI) {
        super("key", "Key management commands", tksCLI);
        this.tksCLI = tksCLI;

        addModule(new TKSKeyCreateCLI(this));
        addModule(new TKSKeyExportCLI(this));
        addModule(new TKSKeyRemoveCLI(this));
        addModule(new TKSKeyReplaceCLI(this));
        addModule(new TKSKeyShowCLI(this));
    }

    @Override
    public String getFullName() {
        return parent.getFullName() + "-" + name;
    }

    public static void printKeyInfo(String id, KeyData data) {
        System.out.println("  Key ID: " + id);

        String type = data.getType();
        if (type != null) System.out.println("  Type: " + type);

        String encryptAlgorithmOID = data.getEncryptAlgorithmOID();
        if (encryptAlgorithmOID != null) System.out.println("  Encrypt Algorithm: " + encryptAlgorithmOID);

        String wrapAlgorithm = data.getWrapAlgorithm();
        if (wrapAlgorithm != null) System.out.println("  Wrap Algorithm: " + wrapAlgorithm);

        RequestId requestID = data.getRequestID();
        if (requestID != null) System.out.println("  Request ID: " + requestID.toHexString());
    }
}
