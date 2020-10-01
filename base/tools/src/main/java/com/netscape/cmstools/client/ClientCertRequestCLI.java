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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.ca.CASystemCertClient;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X500Name;
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
import com.netscape.cmstools.CRMFPopClient;
import com.netscape.cmstools.ca.CACertRequestCLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.ldap.util.DN;
import netscape.ldap.util.RDN;

/**
 * @author Endi S. Dewata
 */
public class ClientCertRequestCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertRequestCLI.class);

    public ClientCLI clientCLI;

    public ClientCertRequestCLI(ClientCLI clientCLI) {
        super("cert-request", "Request a certificate", clientCLI);
        this.clientCLI = clientCLI;
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

        option = new Option(null, "length", true, "RSA key length (default: 2048)");
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
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

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
        int length = Integer.parseInt(cmd.getOptionValue("length", "2048"));

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

        MainCLI mainCLI = (MainCLI) getRoot();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        String password = mainCLI.config.getNSSPassword();

        String csr;
        PKIClient client;
        if ("pkcs10".equals(requestType)) {
            if ("rsa".equals(algorithm)) {
                csr = generatePkcs10Request(
                        nssdb.getDirectory(),
                        password,
                        algorithm,
                        Integer.toString(length),
                        subjectDN);
            }

            else if ("ec".equals(algorithm)) {
                csr = generatePkcs10Request(
                        nssdb.getDirectory(),
                        password,
                        algorithm,
                        curve,
                        subjectDN);
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
                CASystemCertClient certClient = new CASystemCertClient(client, "ca");
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

        logger.info("CSR:\n" + csr);

        CAClient caClient = new CAClient(client);
        CACertClient certClient = new CACertClient(caClient);

        logger.info("Retrieving " + profileID + " profile");

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
            logger.info("Subject Name:");

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
                    logger.info("- " + name);
                    continue;
                }

                if (value == null)
                    continue;

                logger.info("- " + name + ": " + value);
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

        logger.info("Sending certificate request");

        CertRequestInfos infos = certClient.enrollRequest(request, aid, adn);

        CACertRequestCLI.printCertRequestInfos(infos);
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

        List<String> command = new ArrayList<>();
        command.add("PKCS10Client");
        command.add("-d");
        command.add(certDatabase.getAbsolutePath());

        if (password != null) {
            command.add("-p");
            command.add(password);
        }

        command.add("-a");
        command.add(algorithm);
        command.add(lenOrCurve);
        command.add("" + length);
        command.add("-o");
        command.add(csrFile.getAbsolutePath());
        command.add("-n");
        command.add(subjectDN);

        try {
            runExternal(command);
        } catch (Exception e) {
            throw new Exception("Unable to generate CSR: " + e.getMessage(), e);
        }

        logger.info("CSR generated: " + csrFile);

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
