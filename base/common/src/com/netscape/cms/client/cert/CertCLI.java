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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.client.cert;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;
import com.netscape.cms.servlet.cert.model.CertDataInfo;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.request.model.CertRequestInfo;

/**
 * @author Endi S. Dewata
 */
public class CertCLI extends CLI {

    public MainCLI parent;
    public CertClient client;

    public CertCLI(MainCLI parent) {
        super("cert", "Certificate management commands");
        this.parent = parent;

        addModule(new CertFindCLI(this));
        addModule(new CertShowCLI(this));

        addModule(new CertRevokeCLI(this));
        addModule(new CertHoldCLI(this));
        addModule(new CertReleaseHoldCLI(this));
        addModule(new CertRequestSubmitCLI(this));
        addModule(new CertRequestReviewCLI(this));
        addModule(new CertRequestApproveCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        client = new CertClient(parent.config);
        client.setVerbose(verbose);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printCertInfo(CertDataInfo info) {
        System.out.println("  Serial Number: "+info.getID().toHexString());
        System.out.println("  Subject DN: "+info.getSubjectDN());
        System.out.println("  Status: "+info.getStatus());

        Link link = info.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

    public static void printCertData(
            CertificateData certData,
            boolean showPrettyPrint,
            boolean showEncoded) {

        System.out.println("  Serial Number: " + certData.getSerialNumber().toHexString());
        System.out.println("  Issuer: " + certData.getIssuerDN());
        System.out.println("  Subject: " + certData.getSubjectDN());
        System.out.println("  Status: " + certData.getStatus());
        System.out.println("  Not Before: " + certData.getNotBefore());
        System.out.println("  Not After: " + certData.getNotAfter());

        Link link = certData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }

        String prettyPrint = certData.getPrettyPrint();
        if (showPrettyPrint && prettyPrint != null) {
            System.out.println();
            System.out.println(prettyPrint);
        }

        String encoded = certData.getEncoded();
        if (showEncoded && encoded != null) {
            System.out.println();
            System.out.println(encoded);
        }
    }

    public static void printCertRequestInfo(CertRequestInfo info) {
        System.out.println("  Request ID: " + info.getRequestId());
        System.out.println("  Status: " + info.getRequestStatus());
        System.out.println("  Type: " + info.getRequestType());
    }
}
