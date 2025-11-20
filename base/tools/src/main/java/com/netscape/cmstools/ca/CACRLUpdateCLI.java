//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.ca.CACRLClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class CACRLUpdateCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACRLUpdateCLI.class);

    public CACRLCLI crlCLI;

    public CACRLUpdateCLI(CACRLCLI crlCLI) {
        super("update", "Update CRL", crlCLI);
        this.crlCLI = crlCLI;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CAClient caClient = new CAClient(client);
        CACRLClient crlClient = new CACRLClient(caClient);

        crlClient.updateCRL();
    }
}
