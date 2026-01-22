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

package com.netscape.cmstools.ca;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.netscape.security.x509.RevocationReason;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 *
 * TODO: Add support for invalidity date
 */
public class CACertRevokeCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRevokeCLI.class);

    public CACertCLI certCLI;

    public CACertRevokeCLI(CACertCLI certCLI) {
        super("revoke", "Revoke certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS] <serial numbers>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

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
    }

    public void revokeCert(
            CACertClient certClient,
            CertId certID,
            RevocationReason reason,
            String comments,
            boolean isCA,
            boolean force) throws Exception {

        CertData certData = certClient.reviewCert(certID);

        if (!force) {

            if (reason == RevocationReason.CERTIFICATE_HOLD) {
                System.out.println("Placing certificate on-hold:");
            } else if (reason == RevocationReason.REMOVE_FROM_CRL) {
                System.out.println("Placing certificate off-hold:");
            } else {
                System.out.println("Revoking certificate:");
            }

            CACertCLI.printCertData(certData, false, false);
            logger.info("Nonce: " + certData.getNonce());

            System.out.print("Are you sure (Y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            if (!line.equalsIgnoreCase("Y")) {
                return;
            }
        }

        CertRevokeRequest request = new CertRevokeRequest();
        request.setReason(reason.getLabel());
        request.setComments(comments);
        request.setNonce(certData.getNonce());

        CertRequestInfo certRequestInfo;

        if (isCA) {
            certRequestInfo = certClient.revokeCACert(certID, request);
        } else {
            certRequestInfo = certClient.revokeCert(certID, request);
        }

        if (logger.isInfoEnabled()) {
            CACertRequestCLI.printCertRequestInfo(certRequestInfo);
        }

        if (certRequestInfo.getRequestStatus() == RequestStatus.COMPLETE) {
            if (certRequestInfo.getOperationResult().equals(CertRequestInfo.RES_ERROR)) {
                String error = certRequestInfo.getErrorMessage();
                if (error != null) {
                    System.out.println(error);
                }
                MainCLI.printMessage("Could not revoke certificate \"" + certID.toHexString() + "\"");
            } else {
                if (reason == RevocationReason.CERTIFICATE_HOLD) {
                    MainCLI.printMessage("Placed certificate \"" + certID.toHexString() + "\" on-hold");
                } else if (reason == RevocationReason.REMOVE_FROM_CRL) {
                    MainCLI.printMessage("Placed certificate \"" + certID.toHexString() + "\" off-hold");
                } else {
                    MainCLI.printMessage("Revoked certificate \"" + certID.toHexString() + "\"");
                }

                certData = certClient.getCert(certID);
                CACertCLI.printCertData(certData, false, false);
            }
        } else {
            MainCLI.printMessage("Request \"" + certRequestInfo.getRequestID().toHexString() + "\": "
                    + certRequestInfo.getRequestStatus());
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length == 0) {
            throw new CLIException("Missing serial numbers");
        }

        String string = cmd.getOptionValue("reason", RevocationReason.UNSPECIFIED.toString());
        RevocationReason reason = RevocationReason.valueOf(string);

        if (reason == null) {
            throw new CLIException("Invalid revocation reason: " + string);
        }

        String comments = cmd.getOptionValue("comments");
        boolean isCA = cmd.hasOption("ca");
        boolean force = cmd.hasOption("force");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = getPKIClient();
        SubsystemClient subsystemClient = getSubsystemClient(client);
        CACertClient certClient = new CACertClient(subsystemClient);

        for (String cmdArg : cmdArgs) {
            CertId certID = null;
            try {
                certID = new CertId(cmdArg);
                revokeCert(certClient, certID, reason, comments, isCA, force);
            } catch (Exception e) {
                mainCLI.handleException(new CLIException("Unable to revoke certificate " + cmdArg + ": " + e.getMessage(), e));
                // continue to the next cert
            }
        }
    }
}
