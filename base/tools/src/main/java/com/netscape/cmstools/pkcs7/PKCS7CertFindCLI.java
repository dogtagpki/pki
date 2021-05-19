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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs7;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmstools.cli.MainCLI;

public class PKCS7CertFindCLI extends CommandCLI {

    private static Logger logger = LoggerFactory.getLogger(PKCS7CertFindCLI.class);

    public PKCS7CertCLI certCLI;

    public PKCS7CertFindCLI(PKCS7CertCLI certCLI) {
        super("find", "Find certificates in PKCS #7 file", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nicknames...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "pkcs7", true, "PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs7-file", true, "DEPRECATED: PKCS #7 file");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String filename = cmd.getOptionValue("pkcs7");

        if (filename == null) {
            filename = cmd.getOptionValue("pkcs7-file");
            if (filename != null) {
                logger.warn("The --pkcs7-file has been deprecated. Use --pkcs7 instead.");
            }
        }

        if (filename == null) {
            throw new Exception("Missing PKCS #7 file.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        logger.info("Loading PKCS #7 data from " + filename);
        String str = new String(Files.readAllBytes(Paths.get(filename))).trim();
        PKCS7 pkcs7 = new PKCS7(str);

        X509Certificate[] certs = pkcs7.getCertificates();
        if (certs == null || certs.length == 0) {
            System.out.println("PKCS #7 data contains no certificates");
            return;
        }

        // sort certs from root to leaf
        certs = Cert.sortCertificateChain(certs);

        boolean first = true;

        for (X509Certificate cert : certs) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            PKCS7CertCLI.printCertInfo(cert);
        }
    }
}
