//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.pkcs11.PK11InternalCert;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;

public class NSSCertShowCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertShowCLI.class);

    public NSSCertShowCLI(NSSCertCLI nssCertCLI) {
        super("show", "Show certificate", nssCertCLI);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <nickname>", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length < 1) {
            throw new Exception("Missing required positional argument: nickname");
        }

        nickname = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoManager cm = CryptoManager.getInstance();
        PK11InternalCert cert = (PK11InternalCert) cm.findCertByNickname(nickname);

        System.out.println("  Serial Number: " + new CertId(cert.getSerialNumber()));
        System.out.println("  Subject DN: " + cert.getSubjectDN());
        System.out.println("  Issuer DN: " + cert.getIssuerDN());
        System.out.println("  Not Valid Before: " + cert.getNotBefore());
        System.out.println("  Not Valid After: " + cert.getNotAfter());

        StringBuilder sb = new StringBuilder();
        sb.append(PKCS12.encodeFlags(cert.getSSLTrust()));
        sb.append(",");
        sb.append(PKCS12.encodeFlags(cert.getEmailTrust()));
        sb.append(",");
        sb.append(PKCS12.encodeFlags(cert.getObjectSigningTrust()));

        System.out.println("  Trust Attributes: " + sb);
    }
}
