//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.user.UserCertData;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserCertCLI extends CLI {

    public SubsystemUserCertCLI(CLI parent) {
        super("cert", parent.name.toUpperCase() + " user cert management commands", parent);

        addModule(new SubsystemUserCertFindCLI(this));
        addModule(new SubsystemUserCertAddCLI(this));
        addModule(new SubsystemUserCertRemoveCLI(this));
    }

    public static void printCert(
            UserCertData userCertData,
            boolean showPrettyPrint,
            boolean showEncoded) {

        System.out.println("  Cert ID: " + userCertData.getID());
        System.out.println("  Version: " + userCertData.getVersion());
        System.out.println("  Serial Number: " + userCertData.getSerialNumber().toHexString());
        System.out.println("  Issuer: " + userCertData.getIssuerDN());
        System.out.println("  Subject: " + userCertData.getSubjectDN());

        String prettyPrint = userCertData.getPrettyPrint();
        if (showPrettyPrint && prettyPrint != null) {
            System.out.println();
            System.out.println(prettyPrint);
        }

        String encoded = userCertData.getEncoded();
        if (showEncoded && encoded != null) {
            System.out.println();
            System.out.println(encoded);
        }
    }
}
