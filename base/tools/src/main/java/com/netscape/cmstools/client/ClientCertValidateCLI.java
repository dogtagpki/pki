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

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CertificateUsage;
import org.mozilla.jss.CryptoManager;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class ClientCertValidateCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertValidateCLI.class);

    public ClientCLI clientCLI;

    public ClientCertValidateCLI(ClientCLI clientCLI) {
        super("cert-validate", "Validate certificate", clientCLI);
        this.clientCLI = clientCLI;
    }

    public void createOptions() {
        Option option = new Option(null, "certusage", true, "Certificate usage: " +
                "CheckAllUsages, SSLServer, SSLServerWithStepUp, SSLClient, SSLCA, AnyCA, " +
                "StatusResponder, ObjectSigner, UserCertImport, ProtectedObjectSigner, " +
                "VerifyCA, EmailSigner, EmailRecipient.");
        option.setArgName("certusage");
        options.addOption(option);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " nickname", options);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Invalid number of arguments.");
        }

        // Get nickname from command argument.
        String nickname = cmdArgs[0];

        // get usages from options
        String certusage = cmd.getOptionValue("certusage");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        boolean isValid = verifySystemCertByNickname(nickname, certusage);

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
        if (cu.getUsage() != CertificateUsage.CheckAllUsages.getUsage()) {
            try {
                cm.verifyCertificate(nickname, true, cu);
                System.out.println("Valid certificate: " + nickname);
                return true;
            } catch (CertificateException e) {
                // Invalid certificate: (<code>) <message>
                System.out.println(e.getMessage());
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
                if ((ccu & CertificateUsage.SSLServer.getUsage()) != 0)
                    usages.add("SSLServer");
                if ((ccu & CertificateUsage.SSLClient.getUsage()) != 0)
                    usages.add("SSLClient");
                if ((ccu & CertificateUsage.SSLServerWithStepUp.getUsage()) != 0)
                    usages.add("SSLServerWithStepUp");
                if ((ccu & CertificateUsage.SSLCA.getUsage()) != 0)
                    usages.add("SSLCA");
                if ((ccu & CertificateUsage.EmailSigner.getUsage()) != 0)
                    usages.add("EmailSigner");
                if ((ccu & CertificateUsage.EmailRecipient.getUsage()) != 0)
                    usages.add("EmailRecipient");
                if ((ccu & CertificateUsage.ObjectSigner.getUsage()) != 0)
                    usages.add("ObjectSigner");
                if ((ccu & CertificateUsage.UserCertImport.getUsage()) != 0)
                    usages.add("UserCertImport");
                if ((ccu & CertificateUsage.VerifyCA.getUsage()) != 0)
                    usages.add("VerifyCA");
                if ((ccu & CertificateUsage.ProtectedObjectSigner.getUsage()) != 0)
                    usages.add("ProtectedObjectSigner");
                if ((ccu & CertificateUsage.StatusResponder.getUsage()) != 0)
                    usages.add("StatusResponder");
                if ((ccu & CertificateUsage.AnyCA.getUsage()) != 0)
                    usages.add("AnyCA");
                System.out.println("Cert has the following usages: " + StringUtils.join(usages, ','));
                return true;
            }
        }
    }

    public CertificateUsage getCertificateUsage(String certusage) {
        CertificateUsage cu = null;
        if ((certusage == null) || certusage.equals(""))
            cu = CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("CheckAllUsages"))
            cu = CertificateUsage.CheckAllUsages;
        else if (certusage.equalsIgnoreCase("SSLServer"))
            cu = CertificateUsage.SSLServer;
        else if (certusage.equalsIgnoreCase("SSLServerWithStepUp"))
            cu = CertificateUsage.SSLServerWithStepUp;
        else if (certusage.equalsIgnoreCase("SSLClient"))
            cu = CertificateUsage.SSLClient;
        else if (certusage.equalsIgnoreCase("SSLCA"))
            cu = CertificateUsage.SSLCA;
        else if (certusage.equalsIgnoreCase("AnyCA"))
            cu = CertificateUsage.AnyCA;
        else if (certusage.equalsIgnoreCase("StatusResponder"))
            cu = CertificateUsage.StatusResponder;
        else if (certusage.equalsIgnoreCase("ObjectSigner"))
            cu = CertificateUsage.ObjectSigner;
        else if (certusage.equalsIgnoreCase("UserCertImport"))
            cu = CertificateUsage.UserCertImport;
        else if (certusage.equalsIgnoreCase("ProtectedObjectSigner"))
            cu = CertificateUsage.ProtectedObjectSigner;
        else if (certusage.equalsIgnoreCase("VerifyCA"))
            cu = CertificateUsage.VerifyCA;
        else if (certusage.equalsIgnoreCase("EmailSigner"))
            cu = CertificateUsage.EmailSigner;
        else if (certusage.equalsIgnoreCase("EmailRecipient"))
            cu = CertificateUsage.EmailRecipient;

        return cu;
    }
}
