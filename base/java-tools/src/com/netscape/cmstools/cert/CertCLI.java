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

package com.netscape.cmstools.cert;

import java.text.SimpleDateFormat;
import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CertCLI extends CLI {

    public static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

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

        addModule(new CertRequestFindCLI(this));
        addModule(new CertRequestShowCLI(this));
        addModule(new CertRequestSubmitCLI(this));
        addModule(new CertRequestReviewCLI(this));
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

        client = new CertClient(parent.client);

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

    public static String getAlgorithmNameFromOID(String oid) {
        if (oid == null)
            return "";
        else if (oid.equals("1.2.840.113549.1.1.1"))
            return "PKCS #1 RSA";
        else if (oid.equals("1.2.840.113549.1.1.4"))
            return "PKCS #1 MD5 With RSA";
        else if (oid.equals("1.2.840.10040.4.1"))
            return "DSA";
        else
            return "OID."+oid;
    }

    public static void printCertInfo(CertDataInfo info) {
        System.out.println("  Serial Number: "+info.getID().toHexString());
        System.out.println("  Subject DN: "+info.getSubjectDN());
        System.out.println("  Status: "+info.getStatus());

        String type = info.getType();
        Integer version = info.getVersion();
        if (version != null) {
            type += " version " + (version + 1);
        }
        System.out.println("  Type: "+type);

        String keyAlgorithm = getAlgorithmNameFromOID(info.getKeyAlgorithmOID());
        Integer keyLength = info.getKeyLength();
        if (keyLength != null) {
            keyAlgorithm += " with " + keyLength + "-bit key";
        }
        System.out.println("  Key Algorithm: "+keyAlgorithm);

        System.out.println("  Not Valid Before: "+info.getNotValidBefore());
        System.out.println("  Not Valid After: "+info.getNotValidAfter());

        System.out.println("  Issued On: "+info.getIssuedOn());
        System.out.println("  Issued By: "+info.getIssuedBy());

        Link link = info.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

    public static void printCertData(
            CertData certData,
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
        System.out.println("  Type: " + info.getRequestType());
        System.out.println("  Request Status: " + info.getRequestStatus());
        System.out.println("  Operation Result: " + info.getOperationResult());

        String error = info.getErrorMessage();
        if (error != null) {
            System.out.println("  Reason: " + error);
        }

        if (info.getCertId() != null) {
            System.out.println("  Certificate ID: " + info.getCertId().toHexString());
        }
    }

    public static void printCertReviewResponse(CertReviewResponse response) {
        System.out.println("  Request ID: " + response.getRequestId());
        System.out.println("  Profile: " + response.getProfileName());
        System.out.println("  Type: " + response.getRequestType());
        System.out.println("  Status: " + response.getRequestStatus());
    }
}
