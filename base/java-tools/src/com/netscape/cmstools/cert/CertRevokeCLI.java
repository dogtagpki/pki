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

import java.io.BufferedReader;
import java.io.InputStreamReader;

import netscape.security.x509.RevocationReason;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CertRevokeCLI extends CLI {

    public CertCLI certCLI;

    public CertRevokeCLI(CertCLI certCLI) {
        super("revoke", "Revoke certificate", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Serial Number> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        StringBuilder sb = new StringBuilder();

        for (RevocationReason reason : RevocationReason.INSTANCES) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(reason);
            if (reason == RevocationReason.UNSPECIFIED) {
                sb.append(" (default)");
            }
        }

        Option option = new Option(null, "reason", true, "Revocation reason: " + sb);
        option.setArgName("reason");
        options.addOption(option);

        option = new Option(null, "comments", true, "Comments");
        option.setArgName("comments");
        options.addOption(option);

        options.addOption(null, "ca", false, "CA signing certificate");
        options.addOption(null, "force", false, "Force");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            printHelp();
            System.exit(1);
        }

        CertId certID = new CertId(cmdArgs[0]);

        String string = cmd.getOptionValue("reason", RevocationReason.UNSPECIFIED.toString());
        RevocationReason reason = RevocationReason.valueOf(string);

        if (reason == null) {
            System.err.println("Error: Invalid revocation reason: "+string);
            printHelp();
            System.exit(1);
            return;
        }

        CertData certData = certCLI.certClient.reviewCert(certID);

        if (!cmd.hasOption("force")) {

            if (reason == RevocationReason.CERTIFICATE_HOLD) {
                System.out.println("Placing certificate on-hold:");
            } else if (reason == RevocationReason.REMOVE_FROM_CRL) {
                System.out.println("Placing certificate off-hold:");
            } else {
                System.out.println("Revoking certificate:");
            }

            CertCLI.printCertData(certData, false, false);
            if (verbose) System.out.println("  Nonce: " + certData.getNonce());

            System.out.print("Are you sure (Y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            if (!line.equalsIgnoreCase("Y")) {
                System.exit(1);
            }
        }

        CertRevokeRequest request = new CertRevokeRequest();
        request.setReason(reason);
        request.setComments(cmd.getOptionValue("comments"));
        request.setNonce(certData.getNonce());

        CertRequestInfo certRequestInfo;

        if (cmd.hasOption("ca")) {
            certRequestInfo = certCLI.certClient.revokeCACert(certID, request);
        } else {
            certRequestInfo = certCLI.certClient.revokeCert(certID, request);
        }

        if (verbose) {
            CertCLI.printCertRequestInfo(certRequestInfo);
        }

        if (certRequestInfo.getRequestStatus() == RequestStatus.COMPLETE) {
            if (certRequestInfo.getOperationResult().equals(CertRequestInfo.RES_ERROR)) {
                String error = certRequestInfo.getErrorMessage();
                if (error != null) {
                    System.out.println(error);
                }
                MainCLI.printMessage("Could not revoke certificate \"" + certID.toHexString());
            } else {
                if (reason == RevocationReason.CERTIFICATE_HOLD) {
                    MainCLI.printMessage("Placed certificate \"" + certID.toHexString() + "\" on-hold");
                } else if (reason == RevocationReason.REMOVE_FROM_CRL) {
                    MainCLI.printMessage("Placed certificate \"" + certID.toHexString() + "\" off-hold");
                } else {
                    MainCLI.printMessage("Revoked certificate \"" + certID.toHexString() + "\"");
                }

                certData = certCLI.certClient.getCert(certID);
                CertCLI.printCertData(certData, false, false);
            }
        } else {
            MainCLI.printMessage("Request \"" + certRequestInfo.getRequestId() + "\": "
                    + certRequestInfo.getRequestStatus());
        }
    }
}
