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

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.system.SystemCertClient;
import com.netscape.cmstools.CRMFPopClient;
import com.netscape.cmstools.ca.CACertCLI;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;

import netscape.ldap.util.DN;
import netscape.ldap.util.RDN;
import netscape.security.x509.X500Name;

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
        formatter.printHelp(getFullName() + " [Subject DN] [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "type", true, "Request type (default: pkcs10)");
        option.setArgName("request type");
        options.addOption(option);

        option = new Option(null, "username", true, "Username for request authentication");
        option.setArgName("username");
        options.addOption(option);

        option = new Option(null, "password", false, "Prompt password for request authentication");
        options.addOption(option);

        option = new Option(null, "attribute-encoding", false, "Enable Attribute encoding");
        options.addOption(option);

        option = new Option(null, "algorithm", true, "Algorithm (default: rsa)");
        option.setArgName("algorithm name");
        options.addOption(option);

        option = new Option(null, "length", true, "RSA key length (default: 1024)");
        option.setArgName("key length");
        options.addOption(option);

        option = new Option(null, "curve", true, "ECC key curve name (default: nistp256)");
        option.setArgName("curve name");
        options.addOption(option);

        option = new Option(null, "ssl-ecdh", false, "SSL certificate with ECDH ECDSA");
        options.addOption(option);

        option = new Option(null, "permanent", false, "Permanent");
        options.addOption(option);

        option = new Option(null, "sensitive", true, "Sensitive");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "extractable", true, "Extractable");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "transport", true, "PEM transport certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "profile", true,
                "Certificate profile (RSA default: caUserCert, ECC default: caECUserCert)");
        option.setArgName("profile");
        options.addOption(option);

        option = new Option(null, "without-pop", false, "Do not include Proof-of-Possession in CRMF request");
        options.addOption(option);

        option = new Option(null, "issuer-id", true, "Authority ID (host authority if omitted)");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "issuer-dn", true, "Authority DN (host authority if omitted)");
        option.setArgName("DN");
        options.addOption(option);

        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {
        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        String certRequestUsername = cmd.getOptionValue("username");

        String subjectDN;

        if (cmdArgs.length == 0) {
            if (certRequestUsername == null) {
                throw new Exception("Missing subject DN or request username.");
            }

            subjectDN = "UID=" + certRequestUsername;

        } else {
            subjectDN = cmdArgs[0];
        }

        // pkcs10, crmf
        String requestType = cmd.getOptionValue("type", "pkcs10");

        boolean attributeEncoding = cmd.hasOption("attribute-encoding");

        // rsa, ec
        String algorithm = cmd.getOptionValue("algorithm", "rsa");
        int length = Integer.parseInt(cmd.getOptionValue("length", "1024"));

        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");
        boolean temporary = !cmd.hasOption("permanent");

        String s = cmd.getOptionValue("sensitive");
        int sensitive;
        if (s == null) {
            sensitive = -1;
        } else {
            if (!s.equalsIgnoreCase("true") && !s.equalsIgnoreCase("false")) {
                throw new IllegalArgumentException("Invalid sensitive parameter: " + s);
            }
            sensitive = Boolean.parseBoolean(s) ? 1 : 0;
        }

        s = cmd.getOptionValue("extractable");
        int extractable;
        if (s == null) {
            extractable = -1;
        } else {
            if (!s.equalsIgnoreCase("true") && !s.equalsIgnoreCase("false")) {
                throw new IllegalArgumentException("Invalid extractable parameter: " + s);
            }
            extractable = Boolean.parseBoolean(s) ? 1 : 0;
        }

        String transportCertFilename = cmd.getOptionValue("transport");

        String profileID = cmd.getOptionValue("profile");
        if (profileID == null) {
            if (algorithm.equals("rsa")) {
                profileID = "caUserCert";
            } else if (algorithm.equals("ec")) {
                profileID = "caECUserCert";
            }
        }

        boolean withPop = !cmd.hasOption("without-pop");

        AuthorityID aid = null;
        if (cmd.hasOption("issuer-id")) {
            String aidString = cmd.getOptionValue("issuer-id");
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new Exception("Invalid issuer ID: " + aidString, e);
            }
        }

        X500Name adn = null;
        if (cmd.hasOption("issuer-dn")) {
            String adnString = cmd.getOptionValue("issuer-dn");
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                throw new Exception("Invalid issuer DN: " + adnString, e);
            }
        }

        if (aid != null && adn != null) {
            throw new Exception("--issuer-id and --issuer-dn options are mutually exclusive");
        }

        MainCLI mainCLI = (MainCLI) parent.getParent();
        File certDatabase = mainCLI.certDatabase;

        String password = mainCLI.config.getCertPassword();
        if (password == null) {
            throw new Exception("Missing security database password.");
        }

        String csr;
        PKIClient client;
        if ("pkcs10".equals(requestType)) {
            if ("rsa".equals(algorithm)) {
                csr = generatePkcs10Request(certDatabase, password, algorithm,
                        Integer.toString(length), subjectDN);
            }

            else if ("ec".equals(algorithm)) {
                csr = generatePkcs10Request(certDatabase, password, algorithm, curve, subjectDN);
            } else {
                throw new Exception("Error: Unknown algorithm: " + algorithm);
            }

            // initialize database after PKCS10Client to avoid conflict
            mainCLI.init();
            client = getClient();

        } else if ("crmf".equals(requestType)) {

            // initialize database before CRMFPopClient to load transport certificate
            mainCLI.init();
            client = getClient();

            String encoded;
            if (transportCertFilename == null) {
                SystemCertClient certClient = new SystemCertClient(client, "ca");
                encoded = certClient.getTransportCert().getEncoded();

            } else {
                encoded = new String(Files.readAllBytes(Paths.get(transportCertFilename)));
            }

            byte[] transportCertData = Cert.parseCertificate(encoded);

            CryptoManager manager = CryptoManager.getInstance();
            X509Certificate transportCert = manager.importCACertPackage(transportCertData);

            // get archival and key wrap mechanisms from CA
            String kwAlg = CRMFPopClient.getKeyWrapAlgotihm(client);
            KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.fromString(kwAlg);

            csr = generateCrmfRequest(transportCert, subjectDN, attributeEncoding,
                    algorithm, length, curve, sslECDH, temporary, sensitive, extractable, withPop,
                    keyWrapAlgorithm);

        } else {
            throw new Exception("Unknown request type: " + requestType);
        }

        if (verbose) {
            System.out.println("CSR:");
            System.out.println(csr);
        }

        CAClient caClient = new CAClient(client);
        CACertClient certClient = new CACertClient(caClient);

        if (verbose) {
            System.out.println("Retrieving " + profileID + " profile.");
        }

        CertEnrollmentRequest request = certClient.getEnrollmentTemplate(profileID);

        // Key Generation / Dual Key Generation
        for (ProfileInput input : request.getInputs()) {

            ProfileAttribute typeAttr = input.getAttribute("cert_request_type");
            if (typeAttr != null) {
                typeAttr.setValue(requestType);
            }

            ProfileAttribute csrAttr = input.getAttribute("cert_request");
            if (csrAttr != null) {
                csrAttr.setValue(csr);
            }
        }

        // parse subject DN and put the values in a map
        DN dn = new DN(subjectDN);
        Vector<?> rdns = dn.getRDNs();

        Map<String, String> subjectAttributes = new HashMap<String, String>();
        for (int i = 0; i < rdns.size(); i++) {
            RDN rdn = (RDN) rdns.elementAt(i);
            String type = rdn.getTypes()[0].toLowerCase();
            String value = rdn.getValues()[0];
            subjectAttributes.put(type, value);
        }

        ProfileInput sn = request.getInput("Subject Name");
        if (sn != null) {
            if (verbose)
                System.out.println("Subject Name:");

            for (ProfileAttribute attribute : sn.getAttributes()) {
                String name = attribute.getName();
                String value = null;

                if (name.equals("subject")) {
                    // get the whole subject DN
                    value = subjectDN;

                } else if (name.startsWith("sn_")) {
                    // get value from subject DN
                    value = subjectAttributes.get(name.substring(3));

                } else {
                    // unknown attribute, ignore
                    if (verbose)
                        System.out.println(" - " + name);
                    continue;
                }

                if (value == null)
                    continue;

                if (verbose)
                    System.out.println(" - " + name + ": " + value);
                attribute.setValue(value);
            }
        }

        if (certRequestUsername != null) {
            request.setAttribute("uid", certRequestUsername);
        }

        if (cmd.hasOption("password")) {
            Console console = System.console();
            String certRequestPassword = new String(console.readPassword("Password: "));
            request.setAttribute("pwd", certRequestPassword);
        }

        if (verbose) {
            System.out.println("Sending certificate request.");
        }

        CertRequestInfos infos = certClient.enrollRequest(request, aid, adn);

        MainCLI.printMessage("Submitted certificate request");
        CACertCLI.printCertRequestInfos(infos);
    }

    public String generatePkcs10Request(
            File certDatabase,
            String password,
            String algorithm,
            String length,
            String subjectDN) throws Exception {

        File csrFile = File.createTempFile("pki-client-cert-request-", ".csr", certDatabase);
        csrFile.deleteOnExit();

        String lenOrCurve = "ec".equals(algorithm) ? "-c" : "-l";

        String[] commands = {
                "/usr/bin/PKCS10Client",
                "-d", certDatabase.getAbsolutePath(),
                "-p", password,
                "-a", algorithm,
                lenOrCurve, "" + length,
                "-o", csrFile.getAbsolutePath(),
                "-n", subjectDN
        };

        try {
            runExternal(commands);
        } catch (Exception e) {
            throw new Exception("CSR generation failed", e);
        }

        if (verbose) {
            System.out.println("CSR generated: " + csrFile);
        }

        return new String(Files.readAllBytes(csrFile.toPath()));
    }

    public String generateCrmfRequest(
            X509Certificate transportCert,
            String subjectDN,
            boolean attributeEncoding,
            String algorithm,
            int length,
            String curve,
            boolean sslECDH,
            boolean temporary,
            int sensitive,
            int extractable,
            boolean withPop,
            KeyWrapAlgorithm keyWrapAlgorithm) throws Exception {

        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = manager.getThreadToken();

        CRMFPopClient client = new CRMFPopClient();

        Name subject = client.createName(subjectDN, attributeEncoding);

        KeyPair keyPair;
        if (algorithm.equals("rsa")) {
            keyPair = CryptoUtil.generateRSAKeyPair(token, length);

        } else if (algorithm.equals("ec")) {
            keyPair = client.generateECCKeyPair(token, curve, sslECDH, temporary, sensitive, extractable);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        CertRequest certRequest = client.createCertRequest(
                token, transportCert, algorithm, keyPair, subject, keyWrapAlgorithm);

        ProofOfPossession pop = null;
        if (withPop) {
            Signature signer = client.createSigner(token, algorithm, keyPair);

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            certRequest.encode(bo);
            signer.update(bo.toByteArray());
            byte[] signature = signer.sign();

            pop = client.createPop(algorithm, signature);
        }

        return client.createCRMFRequest(certRequest, pop);
    }
}
