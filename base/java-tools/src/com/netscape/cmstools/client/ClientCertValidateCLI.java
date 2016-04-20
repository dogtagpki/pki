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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.CertificateUsage;

import com.netscape.cmstools.cli.CLI;

/**
 * @author Ade Lee
 */
public class ClientCertValidateCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertValidateCLI(ClientCLI clientCLI) {
        super("cert-validate", "Validate certificate", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void createOptions() {
        Option option = new Option(null, "certusage", true, "Certificate usage.");
        option.setArgName("certusage");
        options.addOption(option);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " nickname", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: Invalid number of arguments.");
            printHelp();
            System.exit(-1);
        }

        // Get nickname from command argument.
        String nickname = cmdArgs[0];

        // get usages from options
        String certusage = cmd.getOptionValue("certusage");
        boolean isValid = false;

        try {
            isValid = verifySystemCertByNickname(nickname, certusage);
        } catch (Exception e) {
            System.err.println("Certificate verification failed: " + e);
            isValid = false;
        }

        if (isValid) {
            System.exit(0);
        } else {
            System.exit(1);
        }
    }

    public boolean verifySystemCertByNickname(String nickname, String certusage) throws Exception {
        CertificateUsage cu = getCertificateUsage(certusage);
        int ccu = 0;

        if (cu == null) {
            throw new Exception("Unsupported certificate usage " + certusage +
                    " in certificate " + nickname);
        }

        CryptoManager cm = CryptoManager.getInstance();
        if (cu.getUsage() != CryptoManager.CertificateUsage.CheckAllUsages.getUsage()) {
            if (cm.isCertValid(nickname, true, cu)) {
                System.out.println("Valid certificate: " + nickname);
                return true;
            } else {
                System.out.println("Invalid certificate: " + nickname);
                return false;
            }

        } else {
            // check all possible usages
            ccu = cm.isCertValid(nickname, true);
            if (ccu == CertificateUsage.basicCertificateUsages) {
                /* cert is good for nothing */
                System.out.println("Cert is good for nothing: " + nickname);
                return false;
            } else {
                List<String> usages = new ArrayList<String>();
                if ((ccu & CryptoManager.CertificateUsage.SSLServer.getUsage()) != 0)
                    usages.add("SSLServer");
                if ((ccu & CryptoManager.CertificateUsage.SSLClient.getUsage()) != 0)
                    usages.add("SSLClient");
                if ((ccu & CryptoManager.CertificateUsage.SSLServerWithStepUp.getUsage()) != 0)
                    usages.add("SSLServerWithStepUp");
                if ((ccu & CryptoManager.CertificateUsage.SSLCA.getUsage()) != 0)
                    usages.add("SSLCA");
                if ((ccu & CryptoManager.CertificateUsage.EmailSigner.getUsage()) != 0)
                    usages.add("EmailSigner");
                if ((ccu & CryptoManager.CertificateUsage.EmailRecipient.getUsage()) != 0)
                    usages.add("EmailRecipient");
                if ((ccu & CryptoManager.CertificateUsage.ObjectSigner.getUsage()) != 0)
                    usages.add("ObjectSigner");
                if ((ccu & CryptoManager.CertificateUsage.UserCertImport.getUsage()) != 0)
                    usages.add("UserCertImport");
                if ((ccu & CryptoManager.CertificateUsage.VerifyCA.getUsage()) != 0)
                    usages.add("VerifyCA");
                if ((ccu & CryptoManager.CertificateUsage.ProtectedObjectSigner.getUsage()) != 0)
                    usages.add("ProtectedObjectSigner");
                if ((ccu & CryptoManager.CertificateUsage.StatusResponder.getUsage()) != 0)
                    usages.add("StatusResponder");
                if ((ccu & CryptoManager.CertificateUsage.AnyCA.getUsage()) != 0)
                    usages.add("AnyCA");
                System.out.println("Cert has the following usages: " + StringUtils.join(usages, ','));
                return true;
            }
        }
    }

    public CertificateUsage getCertificateUsage(String certusage) {
        CertificateUsage cu = null;
        if ((certusage == null) || certusage.equals(""))
            cu = CryptoManager.CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("CheckAllUsages"))
            cu = CryptoManager.CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("SSLServer"))
            cu = CryptoManager.CertificateUsage.SSLServer;
        else if (certusage.equalsIgnoreCase("SSLServerWithStepUp"))
            cu = CryptoManager.CertificateUsage.SSLServerWithStepUp;
        else if (certusage.equalsIgnoreCase("SSLClient"))
            cu = CryptoManager.CertificateUsage.SSLClient;
        else if (certusage.equalsIgnoreCase("SSLCA"))
            cu = CryptoManager.CertificateUsage.SSLCA;
        else if (certusage.equalsIgnoreCase("AnyCA"))
            cu = CryptoManager.CertificateUsage.AnyCA;
        else if (certusage.equalsIgnoreCase("StatusResponder"))
            cu = CryptoManager.CertificateUsage.StatusResponder;
        else if (certusage.equalsIgnoreCase("ObjectSigner"))
            cu = CryptoManager.CertificateUsage.ObjectSigner;
        else if (certusage.equalsIgnoreCase("UserCertImport"))
            cu = CryptoManager.CertificateUsage.UserCertImport;
        else if (certusage.equalsIgnoreCase("ProtectedObjectSigner"))
            cu = CryptoManager.CertificateUsage.ProtectedObjectSigner;
        else if (certusage.equalsIgnoreCase("VerifyCA"))
            cu = CryptoManager.CertificateUsage.VerifyCA;
        else if (certusage.equalsIgnoreCase("EmailSigner"))
            cu = CryptoManager.CertificateUsage.EmailSigner;

        return cu;
    }
}
