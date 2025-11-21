//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
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

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "subject", true, "Subject DN");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "issuer", true, "Issuer DN");
        option.setArgName("DN");
        options.addOption(option);
    }

    public Collection<X509Certificate> findCerts(
            String subject,
            String issuer
            ) throws Exception {

        logger.info("Searching for certs");
        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore store = token.getCryptoStore();

        List<X509Certificate> results = new ArrayList<>();
        for (X509Certificate cert : store.getCertificates()) {

            if (subject != null && !subject.equals(cert.getSubjectDN().toString())) {
                continue;
            }

            if (issuer != null && !issuer.equals(cert.getIssuerDN().toString())) {
                continue;
            }

            results.add(cert);
        }
        return results;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String subject = cmd.getOptionValue("subject");
        String issuer = cmd.getOptionValue("issuer");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        boolean first = true;

        for (X509Certificate cert : findCerts(subject, issuer)) {

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
