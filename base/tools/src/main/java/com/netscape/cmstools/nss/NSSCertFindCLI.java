//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSCertFindCLI extends CommandCLI {

    public NSSCertFindCLI(NSSCertCLI certCLI) {
        super("find", "Find certificates", certCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public Collection<X509Certificate> findAllCerts() throws Exception {

        logger.info("Searching for all certs");
        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore store = token.getCryptoStore();

        return Arrays.asList(store.getCertificates());
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        boolean first = true;

        for (X509Certificate cert : findAllCerts()) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            NSSCertInfo certInfo = NSSCertCLI.createCertInfo(cert);
            NSSCertCLI.printCertInfo(certInfo);
        }
    }
}
