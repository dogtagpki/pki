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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.client;

import java.io.File;
import java.util.Vector;

import netscape.ldap.util.DN;
import netscape.ldap.util.RDN;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.FileUtils;

import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cmstools.cert.CertCLI;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class ClientCertRequestCLI extends CLI {

    public ClientCLI clientCLI;

    public ClientCertRequestCLI(ClientCLI clientCLI) {
        super("cert-request", "Request a certificate", clientCLI);
        this.clientCLI = clientCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Subject DN> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "algorithm", true, "Algorithm (default: rsa)");
        option.setArgName("algorithm");
        options.addOption(option);

        option = new Option(null, "length", true, "RSA key length (default: 1024)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option(null, "profile", true, "Certificate profile (default: caUserCert)");
        option.setArgName("profile");
        options.addOption(option);

        options.addOption(null, "help", false, "Help");
    }

    public void execute(String[] args) throws Exception {
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(0);
        }

        if (cmdArgs.length > 1) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        if (cmdArgs.length < 1) {
            System.err.println("Error: Missing subject DN.");
            printHelp();
            System.exit(-1);
        }

        String subjectDN = cmdArgs[0];

        String algorithm = cmd.getOptionValue("algorithm", "rsa");
        String length = cmd.getOptionValue("length", "1024");
        String profileID = cmd.getOptionValue("profile", "caUserCert");
        String requestType = "pkcs10";

        MainCLI mainCLI = (MainCLI)parent.getParent();
        File certDatabase = mainCLI.certDatabase;

        String password = mainCLI.config.getCertPassword();
        if (password == null) {
            System.err.println("Error: Missing security database password.");
            System.exit(-1);
        }

        File csrFile = File.createTempFile("pki-client-cert-request-", ".csr", certDatabase);
        csrFile.deleteOnExit();

        String[] commands = {
                "/usr/bin/PKCS10Client",
                "-d", certDatabase.getAbsolutePath(),
                "-p", password,
                "-a", algorithm,
                "-l", length,
                "-o", csrFile.getAbsolutePath(),
                "-n", subjectDN
        };

        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec(commands);

        int rc = p.waitFor();
        if (rc != 0) {
            MainCLI.printMessage("CSR generation failed");
            return;
        }

        if (verbose) {
            System.out.println("CSR generated: " + csrFile);
        }

        String csr = FileUtils.readFileToString(csrFile);

        // late initialization
        mainCLI.init();
        client = mainCLI.getClient();

        CertClient certClient = new CertClient(client, "ca");

        if (verbose) {
            System.out.println("Retrieving " + profileID + " profile.");
        }

        CertEnrollmentRequest request = certClient.getEnrollmentTemplate(profileID);

        ProfileInput kg = request.getInput("Key Generation");

        ProfileAttribute typeAttr = kg.getAttribute("cert_request_type");
        typeAttr.setValue(requestType);

        ProfileAttribute csrAttr = kg.getAttribute("cert_request");
        csrAttr.setValue(csr);

        ProfileInput sn = request.getInput("Subject Name");

        DN dn = new DN(subjectDN);
        Vector<?> rdns = dn.getRDNs();

        for (int i=0; i< rdns.size(); i++) {
            RDN rdn = (RDN)rdns.elementAt(i);
            String type = rdn.getTypes()[0].toLowerCase();
            String value = rdn.getValues()[0];
            ProfileAttribute uidAttr = sn.getAttribute("sn_" + type);
            uidAttr.setValue(value);
        }

        if (verbose) {
            System.out.println("Sending certificate request.");
        }

        CertRequestInfos infos = certClient.enrollRequest(request);

        MainCLI.printMessage("Submitted certificate request");
        CertCLI.printCertRequestInfos(infos);
    }
}
