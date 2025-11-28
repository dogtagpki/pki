//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.acme;

import javax.ws.rs.core.Response;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.acme.ACMEClient;
import org.dogtagpki.acme.ACMEDirectory;
import org.dogtagpki.acme.ACMEMetadata;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ACMEInfoCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEInfoCLI.class);

    public ACMEInfoCLI(ACMECLI acmeCLI) {
        super("info", "Display ACME metadata", acmeCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getPKIClient();
        ACMEClient acmeClient = new ACMEClient(client);

        try {
            ACMEDirectory directory = acmeClient.getDirectory();
            System.out.println("  Status: Available");

            ACMEMetadata metadata = directory.getMetadata();
            System.out.println("  Terms of Service: " + metadata.getTermsOfService());
            System.out.println("  Website: " + metadata.getWebsite());
            System.out.println("  CAA Identities: " + String.join(", ", metadata.getCaaIdentities()));
            System.out.println("  External Account Required: " + metadata.getExternalAccountRequired());

        } catch (PKIException e) {
            if (e.getCode() != Response.Status.SERVICE_UNAVAILABLE.getStatusCode()) {
                throw e;
            }
            System.out.println("  Status: Unavailable");
        }
    }
}
