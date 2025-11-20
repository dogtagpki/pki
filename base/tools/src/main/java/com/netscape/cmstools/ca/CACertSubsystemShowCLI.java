//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.ca.CASystemCertClient;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertSubsystemShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertSubsystemShowCLI.class);

    public CACertCLI certCLI;

    public CACertSubsystemShowCLI(CACertCLI certCLI) {
        super("subsystem-show", "Show CA subsystem certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CASystemCertClient certClient = new CASystemCertClient(client, "ca");
        CertData certData = certClient.getSubsystemCert();

        System.out.println("  Serial Number: " + certData.getSerialNumber().toHexString());
        System.out.println("  Subject DN: " + certData.getSubjectDN());
        System.out.println("  Issuer DN: " + certData.getIssuerDN());
        System.out.println("  Not Valid Before: " + certData.getNotBefore());
        System.out.println("  Not Valid After: " + certData.getNotAfter());
    }
}
